import base64
import functools
import http.server
import os
import selectors
import socket
import socketserver
import ssl
import threading
import urllib.parse
from pathlib import Path

import pytest

from . import helpers

__this_dir__ = Path(__file__).parent.resolve()
_TEST_REPO = __this_dir__ / "test-server" / "repo"
# Public test fixture only: this self-signed key protects no real service or data.
_TEST_CERT = __this_dir__ / "data" / "proxy-cert.pem"
_TEST_KEY = __this_dir__ / "data" / "proxy-key.pem"
_PROXY_ONLY_HOST = "mamba-proxy-test.invalid"


class _StaticRepoHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


class LocalRepoServer:
    def __init__(self, use_ssl=False):
        handler = functools.partial(_StaticRepoHandler, directory=str(_TEST_REPO))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.scheme = "https" if use_ssl else "http"
        # RFC 2606 reserves .invalid, so the origin cannot be reached without the proxy.
        self.hostname = _PROXY_ONLY_HOST
        if use_ssl:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(_TEST_CERT, _TEST_KEY)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self):
        return f"{self.scheme}://{self.hostname}:{self.server.server_address[1]}"

    @property
    def proxy_upstream(self):
        return urllib.parse.urlsplit(self.url).netloc.lower(), self.server.server_address


class _ThreadingProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, expected_auth, upstream_overrides):
        super().__init__(server_address, _ProxyRequestHandler)
        self.expected_auth = expected_auth
        self.upstream_overrides = upstream_overrides
        self.tls_server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls_server_context.load_cert_chain(_TEST_CERT, _TEST_KEY)
        self.tls_client_context = ssl.create_default_context(cafile=_TEST_CERT)
        self._request_log = []
        self._request_log_lock = threading.Lock()

    def record_request(self, method, target):
        with self._request_log_lock:
            self._request_log.append((method, target))

    def request_log(self):
        with self._request_log_lock:
            return list(self._request_log)


class _ProxyRequestHandler(socketserver.BaseRequestHandler):
    _MAX_HEADER_SIZE = 64 * 1024

    def _read_headers(self, connection, read_size=4096):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = connection.recv(read_size)
            if not chunk:
                return None, None
            data += chunk
            if len(data) > self._MAX_HEADER_SIZE:
                raise ValueError("Proxy request headers are too large")
        return data.split(b"\r\n\r\n", 1)

    def _send_response(self, status, headers=()):
        response = [f"HTTP/1.1 {status}", *headers, "", ""]
        self.request.sendall("\r\n".join(response).encode("ascii"))

    def _is_authorized(self, headers):
        expected_auth = self.server.expected_auth
        if expected_auth is None:
            return True
        token = base64.b64encode(expected_auth.encode()).decode()
        return headers.get("proxy-authorization") == f"Basic {token}"

    def _open_upstream(self, target, default_port):
        parsed = urllib.parse.urlsplit(f"//{target}")
        if parsed.hostname is None:
            raise ValueError(f"Invalid proxy target: {target}")
        authority = f"{parsed.hostname}:{parsed.port or default_port}".lower()
        address = self.server.upstream_overrides.get(
            authority, (parsed.hostname, parsed.port or default_port)
        )
        return socket.create_connection(address, timeout=30)

    @staticmethod
    def _relay(client, upstream):
        with selectors.DefaultSelector() as selector:
            selector.register(client, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, client)
            while True:
                for key, _ in selector.select():
                    data = key.fileobj.recv(64 * 1024)
                    if not data:
                        return
                    key.data.sendall(data)

    @staticmethod
    def _https_url(authority, target):
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme:
            if parsed.scheme != "https" or parsed.hostname is None:
                raise ValueError(f"Invalid absolute HTTPS proxy target: {target}")
            return target
        if not target.startswith("/"):
            raise ValueError(f"Invalid HTTPS proxy target: {target}")
        return f"https://{authority}{target}"

    def _handle_connect(self, target):
        parsed = urllib.parse.urlsplit(f"//{target}")
        if parsed.hostname is None:
            raise ValueError(f"Invalid CONNECT target: {target}")
        try:
            raw_upstream = self._open_upstream(target, 443)
            upstream = self.server.tls_client_context.wrap_socket(
                raw_upstream, server_hostname=parsed.hostname
            )
        except OSError:
            self._send_response("502 Bad Gateway", ("Content-Length: 0",))
            return
        with upstream:
            self.server.record_request("CONNECT", target.lower())
            self._send_response("200 Connection Established")
            try:
                with self.server.tls_server_context.wrap_socket(
                    self.request, server_side=True
                ) as client:
                    raw_headers, remainder = self._read_headers(client)
                    if raw_headers is None:
                        return
                    request_line = raw_headers.decode("iso-8859-1").split("\r\n", 1)[0]
                    method, request_target, _ = request_line.split(" ", 2)
                    self.server.record_request(
                        method.upper(), self._https_url(target, request_target)
                    )
                    upstream.sendall(raw_headers + b"\r\n\r\n" + remainder)
                    self._relay(client, upstream)
            except OSError:
                pass

    def _handle_http(self, method, target, version, header_lines, remainder):
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme != "http" or parsed.hostname is None:
            raise ValueError(f"Invalid absolute HTTP proxy target: {target}")

        authority = parsed.netloc
        try:
            upstream = self._open_upstream(authority, 80)
        except OSError:
            self._send_response("502 Bad Gateway", ("Content-Length: 0",))
            return
        with upstream:
            self.server.record_request(method, target)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            forwarded_headers = [
                line
                for line in header_lines
                if not line.lower().startswith(("proxy-authorization:", "proxy-connection:"))
            ]
            request = "\r\n".join(
                [f"{method} {path} {version}", *forwarded_headers, "", ""]
            ).encode("iso-8859-1")
            upstream.sendall(request + remainder)
            try:
                self._relay(self.request, upstream)
            except OSError:
                pass

    def handle(self):
        try:
            # Do not consume a TLS ClientHello that follows the CONNECT headers: bytes read
            # from the raw socket cannot be pushed back into an SSLSocket.
            raw_headers, remainder = self._read_headers(self.request, read_size=1)
            if raw_headers is None:
                return
            lines = raw_headers.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            headers = {
                key.strip().lower(): value.strip()
                for line in lines[1:]
                if ":" in line
                for key, value in [line.split(":", 1)]
            }
            if not self._is_authorized(headers):
                self._send_response(
                    "407 Proxy Authentication Required",
                    ('Proxy-Authenticate: Basic realm="mamba tests"', "Content-Length: 0"),
                )
                return
            if method.upper() == "CONNECT":
                self._handle_connect(target)
            else:
                self._handle_http(method, target, version, lines[1:], remainder)
        except ValueError:
            try:
                self._send_response("400 Bad Request", ("Content-Length: 0",))
            except OSError:
                pass


class HttpConnectProxy:
    def __init__(self, host, port, expected_auth, upstream_overrides=()):
        self.server = _ThreadingProxyServer((host, port), expected_auth, dict(upstream_overrides))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def requests(self):
        return self.server.request_log()


@pytest.mark.parametrize("auth", [None, "foo:bar", "user%40example.com:pass"])
def test_proxy_install_exact_urls(tmp_home, tmp_prefix, monkeypatch, auth):
    """
    Make sure micromamba follows authenticated proxy settings for every fetched URL.

    The local HTTP origin keeps request paths visible to the proxy so the FETCH URLs can be
    compared exactly instead of inferring proxy use from a CONNECT tunnel to the same host.
    """
    clear_proxy_environment(monkeypatch)
    expected_auth = urllib.parse.unquote(auth) if auth is not None else None
    with LocalRepoServer() as origin, HttpConnectProxy(
        "127.0.0.1", 0, expected_auth, (origin.proxy_upstream,)
    ) as proxy:
        rc_file = write_proxy_config(tmp_prefix, proxy, auth, ssl_verify="true")
        res = helpers.install(
            "test-package",
            "-c",
            origin.url,
            "--override-channels",
            "--rc-file",
            rc_file,
            "--json",
            default_channel=False,
            no_rc=False,
        )

    assert proxy.requests
    assert res["actions"]["FETCH"]
    for fetch in res["actions"]["FETCH"]:
        assert ("GET", fetch["url"]) in proxy.requests


@pytest.mark.parametrize("auth", [None, "foo:bar", "user%40example.com:pass"])
@pytest.mark.parametrize("ssl_verify", (True, False))
def test_proxy_https_exact_urls(tmp_home, tmp_prefix, monkeypatch, auth, ssl_verify):
    """
    Test authenticated HTTPS proxying with exact URLs and TLS verification options.

    The proxy terminates TLS with the trusted test certificate, records each decrypted
    request URL, and forwards it over TLS. The reserved origin hostname is only resolvable
    through the proxy override, so a successful install also proves that HTTPS did not bypass it.
    """
    clear_proxy_environment(monkeypatch)
    expected_auth = urllib.parse.unquote(auth) if auth is not None else None
    with LocalRepoServer(use_ssl=True) as origin, HttpConnectProxy(
        "127.0.0.1", 0, expected_auth, (origin.proxy_upstream,)
    ) as proxy:
        verify = str(_TEST_CERT) if ssl_verify else "false"
        rc_file = write_proxy_config(tmp_prefix, proxy, auth, ssl_verify=verify)
        cmd = [
            "test-package",
            "-c",
            origin.url,
            "--override-channels",
            "--rc-file",
            rc_file,
        ]
        if os.name == "nt":
            # The static test certificate intentionally has no revocation endpoint.
            cmd.append("--ssl-no-revoke")
        res = helpers.install(*cmd, "--json", default_channel=False, no_rc=False)

    assert proxy.requests
    assert res["actions"]["FETCH"]
    for fetch in res["actions"]["FETCH"]:
        assert fetch["url"].startswith(origin.url)
        assert ("GET", fetch["url"]) in proxy.requests


def clear_proxy_environment(monkeypatch):
    for name in (
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "all_proxy",
        "https_proxy",
        "http_proxy",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)


def write_proxy_config(prefix, proxy, auth, ssl_verify):
    port = proxy.server.server_address[1]
    credentials = f"{auth}@" if auth is not None else ""
    proxy_url = f"http://{credentials}127.0.0.1:{port}"
    rc_file = prefix / "rc.yaml"
    rc_file.write_text(
        "\n".join(
            [
                "proxy_servers:",
                f"    http: {proxy_url}",
                f"    https: {proxy_url}",
                f"ssl_verify: {ssl_verify}",
            ]
        )
    )
    return rc_file

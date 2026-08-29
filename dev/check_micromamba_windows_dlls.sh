#!/usr/bin/env bash
# Verify that Windows micromamba.exe imports exactly the allowed PE DLLs (no extra
# third-party dependencies such as zlib.dll). Allowlist matches conda-build output
# for the micromamba feedstock; see dev/micromamba_windows_allowed_dlls.tsv.
# Prefer the native MSVC dumpbin already activated by Windows CI; keep objdump
# as a fallback for cross-build and local inspection environments.
# Regression: https://github.com/mamba-org/mamba/issues/4276
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOWLIST="${SCRIPT_DIR}/micromamba_windows_allowed_dlls.tsv"

usage() {
    echo "Usage: $0 <micromamba.exe> [64|arm64]" >&2
    exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
exe="$1"
architecture="${2:-all}"
[[ "$architecture" == "all" || "$architecture" == "64" || "$architecture" == "arm64" ]] || usage
[[ -f "$exe" ]] || {
    echo "error: not a file: $exe" >&2
    exit 1
}
[[ -f "$ALLOWLIST" ]] || {
    echo "error: allowlist not found: $ALLOWLIST" >&2
    exit 1
}

find_objdump() {
    if [[ -n "${OBJDUMP:-}" ]] && command -v "$OBJDUMP" >/dev/null 2>&1; then
        echo "$OBJDUMP"
        return 0
    fi
    local candidate
    for candidate in \
        x86_64-w64-mingw32-objdump \
        "${CONDA_PREFIX:-}/Library/mingw-w64/bin/x86_64-w64-mingw32-objdump" \
        "${CONDA_PREFIX:-}/Library/mingw-w64/bin/x86_64-w64-mingw32-objdump.exe" \
        "${CONDA_PREFIX:-}/Library/bin/x86_64-w64-mingw32-objdump.exe" \
        llvm-objdump; do
        if command -v "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    if [[ -n "${CONDA_PREFIX:-}" ]]; then
        while IFS= read -r -d '' candidate; do
            echo "$candidate"
            return 0
        done < <(find "$CONDA_PREFIX" -name 'x86_64-w64-mingw32-objdump*' -type f -print0 2>/dev/null)
    fi
    return 1
}

list_dlls_with_objdump() {
    local tool="$1"
    "$tool" -x "$exe" | grep -i 'DLL Name:' | sed -E 's/.*DLL Name:[[:space:]]*//i' | tr '[:upper:]' '[:lower:]' | sort -u
}

list_dlls_with_dumpbin() {
    # Git Bash otherwise rewrites /dependents as an MSYS path before invoking dumpbin.
    MSYS2_ARG_CONV_EXCL='/dependents' dumpbin /dependents "$exe" | grep -iE '^[[:space:]]+.+\.dll[[:space:]]*$' | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' | tr '[:upper:]' '[:lower:]' | sort -u
}

tool_label=""
if command -v dumpbin >/dev/null 2>&1; then
    mapfile -t actual < <(list_dlls_with_dumpbin)
    tool_label="dumpbin"
elif objdump="$(find_objdump)"; then
    mapfile -t actual < <(list_dlls_with_objdump "$objdump")
    tool_label="$objdump"
else
    echo "error: need MSVC dumpbin or a PE-capable objdump" >&2
    exit 1
fi

declare -A allow_name allow_category allow_description
while IFS=$'\t' read -r name category description architectures; do
    [[ "$name" =~ ^#.*$ || -z "$name" ]] && continue
    architectures="${architectures:-all}"
    if [[ "$architecture" != "all" && "$architectures" != "all" ]]; then
        [[ ",${architectures}," == *",${architecture},"* ]] || continue
    fi
    key="$(echo "$name" | tr '[:upper:]' '[:lower:]')"
    allow_name[$key]=1
    allow_category[$key]="$category"
    allow_description[$key]="$description"
done <"$ALLOWLIST"

mapfile -t expected < <(printf '%s\n' "${!allow_name[@]}" | sort)

echo "PE import DLLs for $(basename "$exe") (via $tool_label):"
for dll in "${actual[@]}"; do
    if [[ -n "${allow_category[$dll]:-}" ]]; then
        printf '  %-40s  [%s] %s\n' "$dll" "${allow_category[$dll]}" "${allow_description[$dll]}"
    else
        printf '  %-40s  (not in allowlist)\n' "$dll"
    fi
done
echo

unexpected=()
for dll in "${actual[@]}"; do
    [[ -z "${allow_name[$dll]:-}" ]] && unexpected+=("$dll")
done

missing=()
for dll in "${expected[@]}"; do
    found=0
    for a in "${actual[@]}"; do
        [[ "$a" == "$dll" ]] && found=1 && break
    done
    (("$found" == 0)) && missing+=("$dll")
done

if ((${#unexpected[@]} > 0)) || ((${#missing[@]} > 0)); then
    echo "error: PE DLL imports do not match the allowlist in ${ALLOWLIST##*/}" >&2
    if ((${#unexpected[@]} > 0)); then
        echo >&2
        echo "Unexpected imports (link statically or update the allowlist):" >&2
        for dll in "${unexpected[@]}"; do
            echo "  $dll" >&2
        done
    fi
    if ((${#missing[@]} > 0)); then
        echo >&2
        echo "Missing expected imports:" >&2
        for dll in "${missing[@]}"; do
            printf '  %-40s  [%s] %s\n' "$dll" "${allow_category[$dll]}" "${allow_description[$dll]}" >&2
        done
    fi
    echo >&2
    echo "Documented allowlist: $ALLOWLIST" >&2
    exit 1
fi

echo "OK: PE imports match the ${#expected[@]} allowed DLLs documented in ${ALLOWLIST##*/}."

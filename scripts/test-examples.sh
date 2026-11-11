#!/usr/bin/env bash
# Run the example contracts' tests, and ironwood_aztec's, against a local TXE. The tests run the examples' logic in TXE
# test contexts; no contract is compiled or deployed. TXE makes no proofs and sends no network transactions.
#
#   ./scripts/test-examples.sh [--jobs N] [--slow] [example...]
#
# Examples are directory names under examples/ (default: all of them, and ironwood_aztec). --jobs N (default: the
# number of cores) is passed to `nargo test` as --test-threads. --slow also runs the examples' slow_tests crates,
# which the nightly workflow runs. Environment: TXE_PORT (default 8081), NARGO (default aztec-nargo).
set -euo pipefail

NARGO=${NARGO:-aztec-nargo}
PORT=${TXE_PORT:-8081}
jobs=$(nproc)
slow=false
examples=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jobs) jobs="$2"; shift 2 ;;
        --jobs=*) jobs="${1#--jobs=}"; shift ;;
        --slow) slow=true; shift ;;
        -*) echo "Unknown option: $1" >&2; exit 2 ;;
        *) examples+=("$1"); shift ;;
    esac
done

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# The packages with tests.
packages=()
if [[ ${#examples[@]} -eq 0 ]]; then
    for dir in examples/*/; do [[ -f "$dir/contract/Nargo.toml" ]] && examples+=("$(basename "$dir")"); done
    packages+=(ironwood_aztec)
fi
for example in "${examples[@]}"; do
    [[ -d "examples/$example" ]] || { echo "No example named $example" >&2; exit 2; }
    for manifest in "examples/$example"/*/Nargo.toml; do
        [[ "$manifest" == */slow_tests/* ]] && ! $slow && continue
        if grep -rq '#\[test' "$(dirname "$manifest")/src"; then
            packages+=("$(sed -n 's/^name = "\(.*\)"$/\1/p' "$manifest")")
        fi
    done
done

mkdir -p target
# `aztec start --txe` with a long HTTP keep-alive timeout (see txe-server.mjs).
LOG_LEVEL="${LOG_LEVEL:-error}" node scripts/txe-server.mjs "$PORT" > "target/txe-$PORT.log" 2>&1 &
txe_pid=$!
trap 'kill $txe_pid 2>/dev/null || true' EXIT
until nc -z 127.0.0.1 "$PORT" 2>/dev/null; do
    kill -0 $txe_pid 2>/dev/null || { echo "TXE failed to start; see target/txe-$PORT.log" >&2; exit 1; }
    sleep 0.5
done

export NARGO_FOREIGN_CALL_TIMEOUT=300000
status=0
for package in "${packages[@]}"; do
    "$NARGO" test --package "$package" --silence-warnings --test-threads "$jobs" \
        --oracle-resolver "http://127.0.0.1:$PORT" || status=1
done
exit $status

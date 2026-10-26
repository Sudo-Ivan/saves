#!/bin/sh
# SPDX-License-Identifier: 0BSD
# Builds savesd, starts a scratch server, runs SDK integration tests.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "$HOME/.cache/saves-sdk.XXXXXX")
trap 'kill $SRVPID 2>/dev/null; rm -rf "$WORK"' EXIT
cd "$ROOT"
go build -o "$WORK/savesd" ./cmd/savesd
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
"$WORK/savesd" init -dir "$WORK/d" -addr "127.0.0.1:$PORT" -token-file "$WORK/admin.tok" >/dev/null
python3 - "$WORK/d/config.json" "$PORT" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg.setdefault("listen", {})["addr"] = "127.0.0.1:" + sys.argv[2]
cfg.setdefault("sandbox", {})["mode"] = "off"
json.dump(cfg, open(sys.argv[1], "w"), indent=2)
PY
"$WORK/savesd" serve -config "$WORK/d/config.json" >"$WORK/log" 2>&1 &
SRVPID=$!
for i in $(seq 50); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/v1/me" || true)
  [ "$code" = "401" ] && break
  sleep 0.2
done
export SAVES_URL="http://127.0.0.1:$PORT"
export SAVES_TOKEN=$(cat "$WORK/admin.tok")
SDKS="${*:-rust csharp cpp typescript python java}"
fail=0
for sdk in $SDKS; do
  case "$sdk" in
    rust)
      if command -v cargo >/dev/null; then
        (cd sdk/rust && cargo test --test integration 2>&1 | tail -2) && echo "rust: pass" || { echo "rust: fail"; fail=1; }
      else echo "rust: skip (no cargo)"; fi ;;
    csharp)
      if command -v dotnet >/dev/null; then
        (cd sdk/csharp && dotnet test Saves.Sdk.sln --filter 'FullyQualifiedName~IntegrationTests' 2>&1 | tail -2) && echo "csharp: pass" || { echo "csharp: fail"; fail=1; }
      else echo "csharp: skip (no dotnet)"; fi ;;
    cpp)
      if command -v g++ >/dev/null && command -v cmake >/dev/null; then
        (mkdir -p "$WORK/cpp-build" && cd "$WORK/cpp-build" && \
          cmake "$ROOT/sdk/cpp" -DCMAKE_BUILD_TYPE=Release >/dev/null && make -j4 >/dev/null && \
          ./test_offline && ./test_integration) && echo "cpp: pass" || { echo "cpp: fail"; fail=1; }
      else echo "cpp: skip (no g++/cmake)"; fi ;;
    typescript)
      if command -v node >/dev/null && command -v pnpm >/dev/null; then
        (cd sdk/typescript && pnpm install --ignore-scripts >/dev/null 2>&1 && \
          pnpm exec tsc -p tsconfig.json >/dev/null && \
          node --test dist/test/) && echo "typescript: pass" || { echo "typescript: fail"; fail=1; }
      else echo "typescript: skip (no node/pnpm)"; fi ;;
    python)
      if command -v python3 >/dev/null; then
        (cd sdk/python && python3 -m unittest discover -s tests 2>&1 | tail -2) && echo "python: pass" || { echo "python: fail"; fail=1; }
      else echo "python: skip (no python3)"; fi ;;
    java)
      if command -v javac >/dev/null && command -v java >/dev/null; then
        (cd sdk/java && sh build.sh 2>&1 | tail -3) && echo "java: pass" || { echo "java: fail"; fail=1; }
      else echo "java: skip (no jdk)"; fi ;;
    *) echo "$sdk: skip (unknown)" ;;
  esac
done
exit $fail

#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
docker=(docker)
restore_flags=()
if [[ ${1:-} == --sudo-docker ]]; then
  docker=(sudo -n docker)
  restore_flags=(--sudo-docker)
elif [[ $# -ne 0 ]]; then
  echo 'Usage: bash tests/smoke.sh [--sudo-docker]' >&2
  exit 2
fi
tmp=$(mktemp -d)
seed=vault-kit-smoke-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')
cleanup() {
  if "${docker[@]}" container inspect "$seed" >/dev/null 2>&1; then
    "${docker[@]}" container rm --force "$seed" >/dev/null
  fi
  python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$tmp"
}
trap cleanup EXIT
mkdir "$tmp/data"
image=$(python3 -c 'import vault_setup; print(vault_setup.IMAGE)')
"${docker[@]}" run --pull never -d --network none --name "$seed" \
  --user "$(id -u):$(id -g)" -v "$tmp/data:/data" "$image" >/dev/null
for attempt in $(seq 1 25); do
  if "${docker[@]}" exec "$seed" /healthcheck.sh >/dev/null 2>&1; then break; fi
  sleep 1
done
"${docker[@]}" exec "$seed" /healthcheck.sh >/dev/null
"${docker[@]}" stop "$seed" >/dev/null
mkdir -p "$tmp/data/attachments/demo"
printf 'disposable synthetic fixture\n' > "$tmp/data/attachments/demo/item"
age-keygen -o "$tmp/right" 2>/dev/null
age-keygen -o "$tmp/wrong" 2>/dev/null
recipient=$(age-keygen -y "$tmp/right")
python3 vault_setup.py backup --data "$tmp/data" --recipient "$recipient" --output "$tmp/test.age"
sha=$(sha256sum "$tmp/test.age" | cut -d' ' -f1)
if python3 vault_setup.py backup --data "$tmp/data" --recipient "$recipient" --output "$tmp/test.age"; then
  exit 1
fi
if python3 vault_setup.py restore-check "$tmp/test.age" --sha256 "$sha" \
    --identity "$tmp/wrong" --receipt "$tmp/bad.json" "${restore_flags[@]}"; then
  exit 1
fi
test ! -e "$tmp/bad.json"
python3 vault_setup.py restore-check "$tmp/test.age" --sha256 "$sha" \
  --identity "$tmp/right" --receipt "$tmp/good.json" "${restore_flags[@]}"
python3 vault_setup.py status --receipt "$tmp/good.json" --max-age-days 1
python3 - "$tmp/good.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f:
    receipt = json.load(f)
assert receipt["isolated_startup"] == "passed"
assert receipt["asset_files_copied"] == 1
assert receipt["accounts"] == 0
print("Encrypted backup and isolated restore passed; wrong key and overwrite were refused.")
PY

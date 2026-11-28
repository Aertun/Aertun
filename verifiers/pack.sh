#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Rashik Adhikari
# SPDX-License-Identifier: Apache-2.0
#
#   verifiers/pack.sh OUT [VERSION]
#
# Builds the Python and the TypeScript verifier into OUT/pypi and OUT/npm,
# each from a copy of its directory beside the repository's LICENSE and
# NOTICE, so the tree is left as it was. Then it installs each package the
# way a user would and refuses unless the installed command decides every
# one of the protocol's vectors as the protocol requires, the module imports
# as a program would import it, and the package holds what it should and
# nothing else.
#
# Given VERSION (a release's tag without its v), both packages must carry
# it: a release never publishes a package that names another version.
#
# PYTHONS lists the interpreters the installed package is tried under
# (default python3). The build itself runs under python3, and the
# TypeScript under the node on PATH.
set -euo pipefail
# Byte order for every sort and comparison below, whatever the locale.
export LC_ALL=C

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 OUT [VERSION]" >&2
  exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
mkdir -p "$1/pypi" "$1/npm"
out=$(cd "$1" && pwd)
# Whatever is in OUT is what gets published, so it starts empty.
if [ -n "$(find "$out/pypi" "$out/npm" -mindepth 1 -print -quit)" ]; then
  echo "$1 already holds packages; give a directory with none" >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$here/python/pyproject.toml")
npm_version=$(node -p 'require(process.argv[1]).version' "$here/typescript/package.json")
lock_version=$(node -p 'require(process.argv[1]).version' "$here/typescript/package-lock.json")
if [ -z "$version" ] || [ "$version" != "$npm_version" ] || [ "$version" != "$lock_version" ]; then
  echo "the Python package is \"$version\", the TypeScript one \"$npm_version\"" \
    "and its lockfile \"$lock_version\"" >&2
  exit 1
fi
if [ $# -eq 2 ] && [ "$2" != "$version" ]; then
  echo "this release is $2 and the packages say $version" >&2
  exit 1
fi

echo "--- building the Python package, $version"
mkdir "$work/py"
cp "$here/python/pyproject.toml" "$here/python/aertun_verify.py" "$here/python/README.md" \
  "$root/LICENSE" "$root/NOTICE" "$work/py/"
# The build tools in an environment of their own, each checked against its
# pinned hash, so nothing installed on the machine decides what is built.
python3 -m venv "$work/build"
"$work/build/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
  --no-deps --only-binary :all: -r "$here/python/build-requirements.txt"
"$work/build/bin/python" -m build --no-isolation --outdir "$out/pypi" "$work/py" >/dev/null

echo "--- building the TypeScript package, $version"
mkdir "$work/ts"
cp "$here/typescript/package.json" "$here/typescript/package-lock.json" \
  "$here/typescript/tsconfig.json" "$here/typescript/aertun_verify.ts" \
  "$here/typescript/README.md" "$root/LICENSE" "$root/NOTICE" "$work/ts/"
# The compiler from the lockfile, its integrity checked, and no install
# script run. It type-checks the file, writes the JavaScript Node runs from
# a package, and the declarations a TypeScript program reads.
(cd "$work/ts" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error &&
  npm run --silent build &&
  npm pack --ignore-scripts --pack-destination "$out/npm" --loglevel=error >/dev/null)

whl="$out/pypi/aertun_verify-$version-py3-none-any.whl"
sdist="$out/pypi/aertun_verify-$version.tar.gz"
tgz="$out/npm/aertun-verify-$version.tgz"
for f in "$whl" "$sdist" "$tgz"; do
  [ -f "$f" ] || { echo "the build made no $f" >&2; exit 1; }
done

# What each package holds, exactly: a test file or a build leftover in a
# published package is something nobody reviewed for it.
want_whl="aertun_verify-$version.dist-info/METADATA
aertun_verify-$version.dist-info/RECORD
aertun_verify-$version.dist-info/WHEEL
aertun_verify-$version.dist-info/entry_points.txt
aertun_verify-$version.dist-info/licenses/LICENSE
aertun_verify-$version.dist-info/licenses/NOTICE
aertun_verify-$version.dist-info/top_level.txt
aertun_verify.py"
got_whl=$(python3 -c 'import sys, zipfile; print("\n".join(sorted(zipfile.ZipFile(sys.argv[1]).namelist())))' "$whl")
want_tgz="package/LICENSE
package/NOTICE
package/README.md
package/dist/aertun_verify.d.ts
package/dist/aertun_verify.js
package/package.json"
got_tgz=$(tar -tzf "$tgz" | sort)
if [ "$got_whl" != "$want_whl" ]; then
  printf 'the wheel holds:\n%s\nand should hold:\n%s\n' "$got_whl" "$want_whl" >&2
  exit 1
fi
if [ "$got_tgz" != "$want_tgz" ]; then
  printf 'the npm package holds:\n%s\nand should hold:\n%s\n' "$got_tgz" "$want_tgz" >&2
  exit 1
fi

(cd "$root" && go build -o "$work/aertun" ./cmd/aertun)
vector="$root/spec/aep/v1/vectors/02-receipt-agent-ed25519.json"

for py in ${PYTHONS:-python3}; do
  echo "--- the installed Python package, under $("$py" --version)"
  venv="$work/try-$(basename "$py")"
  "$py" -m venv "$venv"
  "$venv/bin/pip" install --quiet --disable-pip-version-check --no-index --no-deps "$whl"
  "$work/aertun" conform --verifier "$venv/bin/aertun-verify"
  # The README's own example, on a vector, as a program would run it.
  "$venv/bin/python" -I -c '
import importlib.metadata, json, sys
import aertun_verify as av
assert importlib.metadata.version("aertun-verify") == sys.argv[1], "the installed version"
v = json.load(open(sys.argv[2]))
raw_bytes = bytes.fromhex(v["statement"])
statement = av.Statement(raw_bytes)
k = v["issuer_keys"][statement.issuer]
statement.message.verify(av.Key(k["alg"], bytes.fromhex(k["public"])))
_, receipt = av.read_receipt(raw_bytes)
' "$version" "$vector"
done

echo "--- the installed npm package, under node $(node --version)"
mkdir "$work/npm"
(cd "$work/npm" && printf '{"private": true}\n' >package.json &&
  npm install --ignore-scripts --no-audit --no-fund --loglevel=error "$tgz")
"$work/aertun" conform --verifier "$work/npm/node_modules/.bin/aertun-verify"
# Imported by a program, and its declarations read by the compiler under
# strict settings, with nothing else installed beside it.
cat >"$work/npm/use.mts" <<'EOF'
import { checkVector, Key, ALG_ED25519, type Vector } from "aertun-verify";
const v: Vector = { kind: "statement", valid: true };
const k: Key = new Key(ALG_ED25519, new Uint8Array(32));
export const ok: boolean = typeof checkVector === "function" && k.alg === ALG_ED25519 && v.valid;
EOF
"$work/ts/node_modules/.bin/tsc" --noEmit --strict --module nodenext --target es2024 \
  "$work/npm/use.mts"
(cd "$work/npm" && node --input-type=module -e '
import { readFileSync } from "node:fs";
import { Statement, Key, readReceipt } from "aertun-verify";
const v = JSON.parse(readFileSync(process.argv[1], "utf-8"));
const rawBytes = Buffer.from(v.statement, "hex");
const statement = new Statement(rawBytes);
const k = v.issuer_keys[statement.issuer];
statement.message.verify(new Key(k.alg, Buffer.from(k.public, "hex")));
const [, receipt] = readReceipt(rawBytes);
' "$vector")

echo "--- packed"
(cd "$out" && sha256sum pypi/* npm/*)

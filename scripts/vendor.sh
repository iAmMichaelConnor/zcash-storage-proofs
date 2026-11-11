#!/usr/bin/env bash
# Rebuild vendor/noir-bignum and vendor/noir_bigcurve from the pinned commits
# of their upstream repositories, or with --check fail if the committed copies
# differ. Each copy keeps Nargo.toml, README.md, LICENSE and src/. Where the
# pinned commit has no LICENSE, the file comes from the commit in the fourth
# column. A patch in the fifth column (from patches/) is applied on top with a
# three-way merge. noir_bigcurve's bignum dependency is rewritten to the
# vendored path so that both packages use the same BigNum. Moving to a new
# commit: CONTRIBUTING.md, section "Vendored code".
# Needs git and network access to github.com.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
check=false
[[ "${1:-}" == "--check" ]] && check=true

# name | repository | commit | commit providing LICENSE | patch
vendored=(
    "noir-bignum|https://github.com/noir-lang/noir-bignum|78ed0df23307a9a6be7af68f09fca6a3d6a1b34e||bignum-prechecked.patch"
    "noir_bigcurve|https://github.com/noir-lang/noir_bigcurve|f9af3d8892db14c5f57d01e712455c1d6d9336f1|04b663b18ef2244f103faa5eff666927a1c65e17|"
)
upstream_bignum='bignum = { git = "https://github.com/noir-lang/noir-bignum", tag = "v0.11.0" }'
vendored_bignum='bignum = { path = "../noir-bignum" }'

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
status=0

for entry in "${vendored[@]}"; do
    IFS='|' read -r name repository commit licence_commit patch <<< "$entry"
    clone="$scratch/$name"
    git init -q "$clone"
    git -C "$clone" fetch -q --depth 1 "$repository" "$commit"
    git -C "$clone" checkout -q FETCH_HEAD
    if [[ -n "$patch" ]]; then
        git -C "$clone" -c user.name=vendor -c user.email=vendor@localhost \
            am -q -3 "$root/patches/$patch"
    fi

    out="$scratch/out/$name"
    mkdir -p "$out"
    for file in Nargo.toml README.md LICENSE src; do
        if [[ -e "$clone/$file" ]]; then cp -r "$clone/$file" "$out/"; fi
    done
    if [[ ! -e "$out/LICENSE" && -n "$licence_commit" ]]; then
        git -C "$clone" fetch -q --depth 1 "$repository" "$licence_commit"
        git -C "$clone" show FETCH_HEAD:LICENSE > "$out/LICENSE"
    fi
    if [[ "$name" == noir_bigcurve ]]; then
        grep -qF "$upstream_bignum" "$out/Nargo.toml"
        sed -i "s|${upstream_bignum}|${vendored_bignum}|" "$out/Nargo.toml"
    fi

    if $check; then
        if ! diff -r "$out" "$root/vendor/$name" > "$scratch/$name.diff"; then
            echo "vendor/$name differs from $repository at $commit${patch:+ with patches/$patch}:" >&2
            cat "$scratch/$name.diff" >&2
            status=1
        fi
    else
        rm -rf "$root/vendor/$name"
        cp -r "$out" "$root/vendor/$name"
    fi
done

if $check && [[ $status -eq 0 ]]; then echo "vendor: up to date"; fi
exit $status

#!/usr/bin/env bash
# Build the selected checkout and serve it only after a successful build.
set -euo pipefail
source_dir=${1:?container development root}/yunohost-admin/app
tools=/var/cache/lebureau-integration-tests/build-tools
cache=/var/cache/ynh-dev/yunohost-admin
if ! command -v node >/dev/null || ! command -v npm >/dev/null; then
    apt-get update
    apt-get install -y nodejs npm
fi
mkdir -p "$tools" "$cache/node_modules"
npm install --prefix "$tools" --no-audit --no-fund --ignore-scripts yarn@1.22.22
if [[ ! -e "$source_dir/node_modules" && ! -L "$source_dir/node_modules" ]]; then
    ln -s "$cache/node_modules" "$source_dir/node_modules"
fi
cd "$source_dir"
node "$tools/node_modules/yarn/bin/yarn.js" install --frozen-lockfile
node "$tools/node_modules/yarn/bin/yarn.js" type-check
node "$tools/node_modules/yarn/bin/yarn.js" build
test -s dist/index.html
if [[ ! -L /usr/share/yunohost/admin ]]; then
    test ! -e /usr/share/yunohost/admin-bkp
    mv /usr/share/yunohost/admin /usr/share/yunohost/admin-bkp
fi
ln -sfn "$source_dir/dist" /usr/share/yunohost/admin

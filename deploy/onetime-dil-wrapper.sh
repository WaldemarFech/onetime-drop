#!/bin/sh
# /usr/local/bin/onetime-dil - runs the DIL CLI as the unprivileged DIL service user.
set -eu
CFG=${ONETIME_DIL_CONFIG:-/etc/onetime-dil/dil.toml}
cd /opt/onetime-dil
if [ "$(id -un)" = onetime-dil ]; then
  exec env PYTHONPATH=/opt/onetime-dil PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m onetime_drop.dil --dil-config "$CFG" "$@"
fi
exec runuser -u onetime-dil -- env PYTHONPATH=/opt/onetime-dil PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -m onetime_drop.dil --dil-config "$CFG" "$@"

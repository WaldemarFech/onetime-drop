#!/bin/sh
# /usr/local/bin/onetime-drop (+ symlinks drop-create-reveal, drop-create-input, drop-outbox)
# Runs the CLI as the unprivileged service user.
set -eu
case "$(basename "$0")" in
  drop-create-reveal) set -- create-reveal "$@" ;;
  drop-create-input)  set -- create-input "$@" ;;
  drop-outbox)        set -- outbox "$@" ;;
esac
CFG=${ONETIME_DROP_CONFIG:-/etc/onetime-drop/config.toml}
cd /opt/onetime-drop
if [ "$(id -un)" = onetime-drop ]; then
  exec env PYTHONPATH=/opt/onetime-drop /usr/bin/python3 -m onetime_drop --config "$CFG" "$@"
fi
exec runuser -u onetime-drop -- env PYTHONPATH=/opt/onetime-drop \
  /usr/bin/python3 -m onetime_drop --config "$CFG" "$@"

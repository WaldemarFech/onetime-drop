#!/bin/sh
# Install/upgrade onetime-drop on a Debian/Ubuntu host (run as root from the repo root).
# Idempotent: never overwrites an existing config, key or proxy secret.
set -eu
apt-get install -y -qq python3 python3-cryptography openssh-client >/dev/null
id onetime-drop >/dev/null 2>&1 || useradd --system --home-dir /var/lib/onetime-drop \
  --no-create-home --shell /usr/sbin/nologin onetime-drop
install -d -m 755 /opt/onetime-drop/onetime_drop
install -m 644 onetime_drop/*.py /opt/onetime-drop/onetime_drop/
install -d -m 755 /opt/onetime-drop/onetime_drop/recipes
install -m 644 onetime_drop/recipes/*.py /opt/onetime-drop/onetime_drop/recipes/
chmod 755 /opt/onetime-drop/onetime_drop/askpass.py   # SSH_ASKPASS helper for action links
install -d -m 750 -o root -g onetime-drop /etc/onetime-drop
install -d -m 700 -o onetime-drop -g onetime-drop /var/lib/onetime-drop
FRESH=0
if [ ! -f /etc/onetime-drop/config.toml ]; then
  install -m 640 -o root -g onetime-drop deploy/config.example.toml /etc/onetime-drop/config.toml
  FRESH=1
fi
chgrp onetime-drop /etc/onetime-drop/config.toml && chmod 640 /etc/onetime-drop/config.toml
[ -s /etc/onetime-drop/key ] || (umask 077; head -c 32 /dev/urandom > /etc/onetime-drop/key)
[ -s /etc/onetime-drop/proxy_secret ] || (umask 077; python3 -c \
  'import secrets;print(secrets.token_urlsafe(48))' > /etc/onetime-drop/proxy_secret)
chown onetime-drop:onetime-drop /etc/onetime-drop/key /etc/onetime-drop/proxy_secret
chmod 600 /etc/onetime-drop/key /etc/onetime-drop/proxy_secret
install -m 755 deploy/onetime-drop-wrapper.sh /usr/local/bin/onetime-drop
for n in drop-create-reveal drop-create-input drop-outbox; do
  ln -sf onetime-drop /usr/local/bin/$n
done
[ -d /etc/logrotate.d ] && install -m 644 deploy/onetime-drop.logrotate /etc/logrotate.d/onetime-drop
install -m 644 deploy/onetime-drop.service /etc/systemd/system/onetime-drop.service
systemctl daemon-reload
systemctl enable onetime-drop >/dev/null 2>&1
if [ "$FRESH" = 1 ]; then
  echo "Installed. Edit /etc/onetime-drop/config.toml, put /etc/onetime-drop/proxy_secret into"
  echo "your reverse-proxy config, then: systemctl start onetime-drop"
  exit 0
fi
systemctl restart onetime-drop
systemctl is-active onetime-drop

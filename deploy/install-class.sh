#!/bin/sh
# Install/update the class drop-in service (idempotent). Run as root from the repo root.
set -eu
apt-get install -y -qq python3 python3-cryptography python3-pil >/dev/null
id onetime-class >/dev/null 2>&1 || useradd --system --home /var/lib/onetime-class --shell /usr/sbin/nologin onetime-class
for d in onetime_drop onetime_drop/dil onetime_drop/classdrop; do install -d -m 755 /opt/onetime-drop/$d; done
install -m 644 onetime_drop/__init__.py /opt/onetime-drop/onetime_drop/
install -m 644 onetime_drop/dil/*.py /opt/onetime-drop/onetime_drop/dil/
install -m 644 onetime_drop/classdrop/*.py /opt/onetime-drop/onetime_drop/classdrop/
install -d -m 750 -o root -g onetime-class /etc/onetime-class
install -d -m 700 -o onetime-class -g onetime-class /var/lib/onetime-class
[ -f /etc/onetime-class/class.toml ] || install -m 640 -g onetime-class deploy/class.example.toml /etc/onetime-class/class.toml
[ -s /etc/onetime-class/key.bin ] || (umask 077; head -c 32 /dev/urandom > /etc/onetime-class/key.bin)
chown root:onetime-class /etc/onetime-class/key.bin; chmod 640 /etc/onetime-class/key.bin
install -m 644 deploy/onetime-class.service /etc/systemd/system/onetime-class.service
systemctl daemon-reload
systemctl enable onetime-class >/dev/null 2>&1
systemctl restart onetime-class
sleep 1; systemctl is-active onetime-class

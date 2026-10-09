# CrowdSec for onetime-class.service (CT 100031) -> Traefik bouncer (CT 1003)

Plan + config only. No live changes.

## Context

- `onetime-class.service` runs in CT 100031 (Debian 13).
- It writes one line per security event to stderr/journald:
  `classdrop event=<bad-password|locked|rate-limited|denied-peer> ip=<client ip>`
- CrowdSec LAPI + Traefik bouncer run in CT 1003 (Traefik host).
- Goal: brute-force / credential-stuffing protection on theTraefik entry point.
- Config files in this repo:
  - `deploy/crowdsec-class-acquis.yaml` — journald acquisition.
  - `deploy/crowdsec-class-bad-password.yaml` — leaky scenario.
  - Parser below (inline) — extracts `ip=` into `evt.Meta.source_ip`.
  - Whitelist below (inline) — WireGuard `192.0.2.0/24`.

## Option (a) — CrowdSec agent in CT 100031, journald acquisition, registered to LAPI in CT 1003 [RECOMMENDED]

Install `crowdsec` (agent-only, no local LAPI) in CT 100031:

1. Point it at the CT 1003 LAPI (`/etc/crowdsec/config.yaml`: `url: http://<ct1003-ip>:8080/`, `login/password` from `cscli machines add` on CT 1003).
2. Install `deploy/crowdsec-class-acquis.yaml` as e.g. `/etc/crowdsec/acquis.d/classdrop.yaml`.
3. Install the s01-parse parser below as e.g. `/etc/crowdsec/parsers/s01-parse/classdrop-parse.yaml`.
4. Install `deploy/crowdsec-class-bad-password.yaml` as e.g. `/etc/crowdsec/scenarios/class-bad-password.yaml`.
5. Install the whitelist below.
6. `systemctl restart crowdsec`; verify with `cscli explain --log "classdrop event=bad-password ip=1.2.3.4" --type classdrop` and `cscli lapi status`.
7. Decisions (ban 10m on 20 hits / 30s leak) are created in the CT 1003 LAPI, where the Traefik bouncer is already subscribed, so the attacker IP is blocked at the edge.

Pros:

- Decision is made where logs exist, enforced where traffic enters (Traefik in CT 1003). This is the only option that reaches the Traefik bouncer without log forwarding.
- Native journald tail (`journalctl_filter: _SYSTEMD_UNIT=onetime-class.service`); no syslog/file plumbing, no dropped stderr.
- Scales: CT 100031 stays a lightweight log processor; all decisions, CAPI, and bouncer API stay in CT 1003.
- Scenario/parser updates are standard `cscli` / hub-style files.

Cons:

- Requires LAPI registration (machine token) and egress 8080 from CT 100031 to CT 1003.
- Clock skew between CTs can affect leakspeed; keep NTP/Chrony in sync.

## Option (b) — Local firewall bouncer in CT 100031 [NOT RECOMMENDED]

Install `crowdsec-firewall-bouncer` (nftables/iptables) in CT 100031 alongside a local agent+LAPI, or pointed at the same logs.

Pros:

- Blocks at the app host itself; works even if CT 1003 is unreachable.
- Simple single-host setup.

Cons:

- **Decision never reaches Traefik (CT 1003).** Attacker traffic still hits Traefik, still consumes connections/TLS, still reaches the backend; only dropped late at CT 100031.
- Duplicates LAPI/bouncer state; two places to manage decisions, whitelists, and upgrades.
- Firewall bouncer on an app CT risks lockout (SSH, WireGuard) on false positives and complicates the CT firewall.
- Does not protect any other backend behind Traefik.

## Comparison

|                       | (a) agent in 100031 -> LAPI/bouncer in 1003 | (b) local firewall bouncer in 100031 |
|-----------------------|---------------------------------------------|--------------------------------------|
| Enforced at Traefik   | yes (LAPI decision, bouncer pulls it)       | no (local nftables only)             |
| Log source            | journald `onetime-class.service` in place   | same, but decision stays local       |
| Blast radius          | edge block, app CT untouched                | firewall churn on app CT             |
| Ops                   | one LAPI, one bouncer set                   | two LAPIs/bouncers to maintain       |
| Recommendation        | **use (a)**                                 | reject                               |

**Recommendation: (a).** The security requirement is to stop brute force at the Traefik edge. Only (a) puts the decision in the LAPI that the Traefik bouncer queries.

## Files provided

`deploy/crowdsec-class-acquis.yaml`:

```yaml
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=onetime-class.service"
labels:
  type: classdrop
```

`deploy/crowdsec-class-bad-password.yaml` (leaky, capacity 20, leakspeed 30s, blackhole 10m):

```yaml
type: leaky
name: custom/class-bad-password
description: "onetime-class classdrop: bad-password / locked brute force"
filter: "evt.Meta.log_type == 'classdrop' && (evt.Line.Raw contains 'classdrop event=bad-password' || evt.Line.Raw contains 'event=locked')"
groupby: evt.Meta.source_ip
capacity: 20
leakspeed: "30s"
blackhole: "10m"
labels:
  service: onetime-class
  type: bruteforce
  confidence: 2
  spoofable: 0
```

Only `bad-password` and `locked` trigger this scenario. `rate-limited` / `denied-peer` are logged but intentionally not counted (avoid double-counting app-level throttles).

## Minimal s01-parse parser (inline, install alongside the scenario)

A parser is used instead of grok-in-scenario so the IP is extracted once into `evt.Meta.source_ip` and the scenario can `groupby` it. Install as `parsers/s01-parse/classdrop-parse.yaml`:

```yaml
filter: "evt.Meta.log_type == 'classdrop'"
name: s01-parse/classdrop-parse
description: "Parse onetime-class classdrop lines: classdrop event=<ev> ip=<ip>"
onsuccess: next_stage
nodes:
  - grok:
      pattern: "classdrop event=%{WORD:classdrop_event} ip=%{IP:source_ip}"
      apply_on: Line.Raw
statics:
  - meta: source_ip
    expression: "evt.Parsed.source_ip"
```

Result: `evt.Parsed.classdrop_event` in `{bad-password, locked, rate-limited, denied-peer}`, `evt.Meta.source_ip` = client IP, grouped by the scenario above. No separate grok in the scenario itself.

## Whitelist: WireGuard 192.0.2.0/24

Do not ban internal WG clients. Install as e.g. `/etc/crowdsec/parsers/s02-enrich/classdrop-whitelist.yaml`:

```yaml
name: s02-enrich/classdrop-whitelist
description: "Whitelist WireGuard management network"
whitelist:
  reason: "WireGuard internal network"
  ip:
    - "192.0.2.0/24"
```

Alternatively via `cscli decisions` / LAPI whitelist for `custom/class-bad-password`. Verify WG SSH/admin traffic with `cscli explain` still parses as `whitelisted`.

## Validation (plan-time)

```bash
python -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('deploy/crowdsec-class-*.yaml')]; print('YAML OK')"
crowdsec -t -c /etc/crowdsec/config.yaml
cscli explain --log "classdrop event=bad-password ip=203.0.113.7" --type classdrop
cscli scenarios list
curl -s http://127.0.0.1:8080/v1/decisions -H "Authorization: Bearer <bouncer-key>" | head
journalctl -u onetime-class.service -o cat | head
```

Expected: `classdrop event=bad-password ip=203.0.113.7` parses with `Meta.source_ip=203.0.113.7`; 20 such lines in a 30s leak window yields a 10m ban visible in Traefik bouncer logs; `192.168.100.x` never banned.

## Rollout checklist (for operator, not executed here)

1. On CT 1003: `cscli machines add ct100031-class --auto` (save token).
2. On CT 100031: install `crowdsec` agent-only, register to CT 1003 LAPI, copy the three files above.
3. `systemctl enable --now crowdsec; cscli lapi status`.
4. Generate test line via `systemd-cat -t onetime-class echo "classdrop event=bad-password ip=203.0.113.7"` (lab only), confirm `cscli decisions list`.
5. Confirm Traefik bouncer blocks the test IP, then delete the test decision.

# DIL-lite: public passphrase download links

The first slice of the Drop-In-Link design. It only offers downloads: no uploads, no channel and no shell. It runs as its own listener (`python -m onetime_drop.dil dil-serve`, unit `onetime-dil.service`, user `onetime-dil`) on a private address behind the reverse proxy. The SSO-protected onetime-drop service is not touched.

```
printf '%s\n' "$PASSPHRASE" | onetime-dil dil-create --label "ThinkPad Paket" --passphrase-stdin \
    --file a.zip --file b.txt --ttl 2h --max-downloads 8      # -> https://dil.example.com/d/<token>
onetime-dil dil-list | dil-revoke <id> | dil-gc
```

## Security model
- **Token:** 256-bit random. Only `sha256(token)` is stored, and it names the metadata file and the blob directory.
- **Passphrase:** stored as an scrypt hash (n=2^15, r=8, random salt) and compared in constant time. The 3rd wrong attempt in total burns the link. Verification and the counter update run under one lock, so parallel guesses are serialized.
- **Unknown tokens:** an unlock with an unknown token pays the same KDF cost, outside the lock.
- **Burn:** happens after 3 wrong passphrases, at TTL, when max downloads is reached, when the guest clicks "Erledigt – Link jetzt löschen", or on `dil-revoke`. A burn deletes the metadata first, then the private file copies (dirs 0700, files 0600). A 30-second GC sweeps expired links and orphaned files.
- **Routes:** only `GET /d/<t>`, `POST /d/<t>/unlock`, `POST /d/<t>/burn` and `GET /d/<t>/f/<n>` exist. Everything else gets one identical 404. That covers unknown, expired and burned tokens, other methods, malformed and non-canonical paths, query strings, and peers other than the proxy.
- **Session cookie:** HMAC-signed with a per-link key and bound to the token hash. It is HttpOnly, Secure, SameSite=Strict, `Path=/d/<t>`, and lives at most 15 minutes. The burn form also carries an HMAC form token.
- **Abuse limits:**
  - per IP: 20 requests per minute; IPv6 is counted per /64
  - global: 600 requests per minute
  - at most 64 connections and at most 4 parallel KDF runs
  - unlock body at most 1 KB, read within a 10-second deadline; chunked bodies and duplicate Content-Length headers are rejected
  - foreign `Origin` or `Sec-Fetch-Site` headers are refused without counting as an attempt
- **Logs:** an event type, a link-id prefix and a salted IP hash only. Never the token, path, passphrase or cookie.
- **Headers:** a strict CSP (style allowed by hash only; downloads get `sandbox`), nosniff, no-store, noindex and DENY framing. Downloads are sent as `attachment` with a sanitized ASCII filename.
- **Proxy (`deploy/traefik-dil.example.yaml`):** no forward-auth. It adds HSTS, a rate limit of 30 per minute per IP, and an in-flight cap of 4 per IP. The CrowdSec bouncer runs on the whole entrypoint. The CrowdSec scenario `local/dil-abuse` (`deploy/crowdsec-dil-abuse.yaml`) bans a source after more than 8 non-static 403/404/429 responses on the DIL host, with a 30-second leak. Existing whitelists stay in force.
- **Unit:** hardened with ProtectSystem=strict, only the state dir writable, NoNewPrivileges, an empty capability set, a syscall filter, MemoryMax and TasksMax.

## Residual risks
1. **Tokens in the proxy access log.** The URL carries the token, and the router keeps Traefik's access log on so CrowdSec can see abuse. The proxy host's access log therefore contains tokens. A token alone is useless without the passphrase, which allows 3 tries and is short-lived. Restrict who can read the log.
2. **Weak passphrases.** The passphrase is the real secret. With 3 tries, online guessing is negligible. If the metadata file leaked, though, a short dictionary word falls to offline scrypt cracking, which reveals only that link's passphrase.
3. **Deliberate burn.** Anyone who holds the link can burn it on purpose with 3 wrong tries. That is intended: fail closed.
4. **Interrupted downloads.** Every started download counts, including aborted ones. There is no Range support.
5. **Proxy-level slowloris.** Traefik's own timeouts and the per-IP in-flight cap cover it. The backend relies on the proxy for header-phase slowloris.
6. **No E2E encryption.** TLS ends at the proxy, and the files sit in plain form on the service host until burned. Do not use DIL-lite for secrets; use reveal links behind SSO.

## Rollback
```
# app host
systemctl disable --now onetime-dil && rm /etc/systemd/system/onetime-dil.service && systemctl daemon-reload
# proxy host (Traefik reloads conf.d on its own)
rm /etc/traefik/conf.d/dil.yaml; rm /etc/crowdsec/scenarios/dil-abuse.yaml && systemctl reload crowdsec
# DNS: delete the dil A record.   Leftovers you may remove: /opt/onetime-dil*, /etc/onetime-dil,
# /var/lib/onetime-dil, /usr/local/bin/onetime-dil, user onetime-dil
```

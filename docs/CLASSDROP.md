# Class-Drop (classdrop) – design

Students upload images and documents to a class drop. Each class also has its own gallery.
The package is `onetime_drop/classdrop/` and runs as a separate listener, `onetime-class.service`
(127.0.0.1:8082, user `onetime-class`), on the same host as onetime-drop (drop.example.com, LXC 100029).
It uses the Python 3.11+ stdlib plus `cryptography`. `Pillow` is optional and used only for thumbnails.
The style follows `onetime_drop/dil/`: stdlib http.server, one identical 404, no path logging,
strict security headers/CSP, and the same RateLimiter and IP handling.

## Routes (Traefik maps drop.example.com → :8082 for exactly these)
| Route | Access | Purpose |
|---|---|---|
| `GET /<code>` | public | Upload page. `code` = `[a-z0-9]{3}`; the step-1 password form, or the upload form if the cookie is valid |
| `POST /<code>/unlock` | public | password → class cookie `cd_<code>` (HMAC, 12h, HttpOnly, Secure, SameSite=Strict, Path=/<code>) |
| `POST /<code>/upload` | public | multipart: `name` (1–60 chars), `csrf`, `files` (1..max_files). Needs the cookie |
| `GET /g/<link>` | public | Gallery. `link` = short `[a-z0-9-]{3,24}` (random 4 chars or set by admin, with validity); password form or the grid. Upload unlock also sets the gallery cookie |
| `POST /g/<token>/unlock` | public | same password as the class → cookie `cg` (Path=/g/<token>) |
| `GET /g/<token>/f/<id>` / `GET /g/<token>/t/<id>` | public | file download (Content-Disposition attachment, except images inline) / thumbnail |
| `GET /admin/klassen` + `POST /admin/klassen/*` | Authelia 2FA (Traefik forwardAuth, `Remote-User`) | admin |

`/admin` itself remains onetime-drop's admin. Class admin lives under `/admin/klassen` and is linked from there.

## Data model (state_dir, default /var/lib/onetime-class, dirs 0700, files 0600)
- `classes/<code>.json`: `{code, label, pw_salt, pw_hash (scrypt n=2^15,r=8,p=1), created, expires, gallery_key (sha256 of the gallery token), gallery_enabled, max_bytes, used_bytes}`
- `items/<code>/<id>.json`: `{id (16 hex), name (student), filename (sanitized), mime, size, ts, hidden, has_thumb}`
- `items/<code>/<id>.bin` + `<id>.thumb`: AES-256-GCM (key from `key_file`, 32 bytes), nonce(12) || ct, AAD = `code/id`
- `events.log`: event + salted IP hash, never passwords, tokens or file names
- Expiry: class `expires` passed → GC deletes the class + items (purge after `expires + grace_days`, default 0)

## Upload rules
- Allowed (sniffed by magic bytes, not by name): jpeg, png, heic/heif, webp, gif, pdf, docx, pptx, xlsx (OOXML = zip with `[Content_Types].xml` + `word/`/`ppt/`/`xl/`, no `vbaProject.bin`), txt is not allowed
- Limits: `max_file_mb` (25), `max_files` per upload (20), `max_request_mb` (100), per-class `max_bytes` (default 2 GB)
- Thumbnail: Pillow for jpeg/png/webp/gif (max 400px, re-encoded as jpeg, EXIF dropped). Without Pillow there is no thumbnail and the gallery shows an icon
- Password check: 5 failures/15 min per IP+class → 429; there is no burn (classes stay usable). CrowdSec scenario on the 401 events

## Admin (`/admin/klassen`)
Classes table (code, label, expiry, item count, MB). Form "Neue Klasse": label, code (empty = random 3 chars without ambiguous ones `0o1il`), password (empty = generated, e.g. `fta2`), expiry in days.
Per class: "Galerie-Link neu erzeugen" shows the link once, revokes the old token; items with hide/unhide/delete; ZIP export (streamed, decrypted); delete the class.
CSRF: an HMAC token per Remote-User + Origin check. POST only.

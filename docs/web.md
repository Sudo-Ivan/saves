# Web UI

savesd can serve a built-in browser UI on the main listener alongside
the /v1 API. It is off by default.

```json
"web": {"enabled": true, "secret": "<64 hex chars>", "public_url": ""}
```

Set the secret with `web.secret` or `web.secret_file`
(`SAVES_WEB_SECRET_FILE`). It must be at least 32 characters. It seeds
HKDF keys for cookie sealing, CSRF tokens, and TOTP secret storage.
`web.instance_name` sets the display name (default "saves").

## What the UI offers

Public pages: the homepage (`web.homepage`, default true), sign in,
registration (only when registration.mode is not closed), and OIDC
sign in. Authenticated pages: an account overview with tier and quota
usage, app and slot browsing, a snapshot table with tar archive
download, snapshot and slot deletion behind a confirm page, a security
page (password change, TOTP setup and disable, recovery code
regeneration, session list with revoke), and API token management
(the token secret is shown once in the create response, never again).

Tokens support an expiry preset or an exact UTC date and time, an
optional allowed-address list (one address or CIDR per line), and a
detail page with usage stats, a 30 day chart, top addresses, denied
counts, and an audit log (created, renamed, expiry_changed,
cidr_changed, revoked, first_use, new_ip, denied_ip, denied_expired,
denied_revoked). Denied events are recorded only when the presented
secret was correct and are rate limited to one per token and address
per minute. A denied request looks exactly like a bad token. The audit
log exports as CSV. Admins see the same data for any user's token. Admins get
user management (tier, quota, disable, delete, session revocation,
web admin grant, TOTP reset) and a GC trigger. Passkeys/WebAuthn are
not implemented.

## Appearance

The UI uses the Coral theme: warm stationery on a felt desk, General
Sans and Geist Mono type. Both are bundled under static/fonts
and nothing is loaded from third parties. Pages work
without JavaScript. The small app.js is progressive enhancement only.

## Sessions and cookies

Login mints a fresh 32 byte session id each time. Only its SHA-256 is
stored server side. The cookie is HttpOnly, SameSite=Lax, never has a
Domain attribute, and is a browser session cookie (no Max-Age). When
cookies are Secure the name is prefixed __Host- at the root base path
or __Secure- under a path prefix. Sessions have an idle timeout
(web.session.idle, 2h) and an absolute cap (web.session.absolute, 24h).
A pending 2FA session lives at most web.session.pending_ttl (5m) and
allows web.session.max_2fa_attempts (5) wrong codes. Password changes,
disabling, deleting, and admin role changes revoke the user's other
sessions. A background sweep purges expired sessions every 10 minutes.

`web.cookie_secure` is auto, always, or never. Auto means Secure when
public_url is https, or the connection has TLS, or a trusted proxy
reports https. A warning is logged when the listener is non-loopback
and cookies end up not Secure.

## Login policy

Password login can be disabled with web.password_login=false. The form
is then not rendered and POST /login returns 404. Failures always
return the same generic message. web.login_per_min (10) bounds attempts
per client IP prefix, and a username is locked for 15 minutes after 10
failures inside 15 minutes. web.require_2fa forces every password user
to enroll TOTP. Web.require_2fa_admin (default true) forces admins who
signed in by password. OIDC sessions are exempt since the IdP owns MFA.

TOTP is RFC 6238 (SHA-1, 6 digits, 30s, +-1 step) with replay
protection via an atomic step counter. The enrollment QR is a
server-rendered inline SVG. TOTP secrets are stored AES-256-GCM sealed.
Ten recovery codes are generated per enrollment or regeneration, shown
once, stored as SHA-256, and single use.

## CSRF

Every non-GET/POST-safe request needs a valid csrf_token form field:
a masked copy of the session secret for authenticated pages, or a
masked HMAC of the csrf cookie for public forms. Fetch Metadata
(Sec-Fetch-Site) or Origin/Referer must also indicate a same-origin
request. A POST with none of those headers is rejected.

## Security headers

All web responses carry a strict Content-Security-Policy (no inline
script or style), X-Frame-Options DENY, frame-ancestors 'none',
nosniff, no-referrer, no-store on dynamic pages, CORP same-origin,
a restrictive Permissions-Policy, HSTS when the effective scheme is
https (web.hsts controls it), and X-Robots-Tag noindex except the
homepage. Static assets are embedded and served under content-hash
fingerprinted URLs with an immutable one-year cache. Error pages are
styled and contain no request data beyond the request id.

## OIDC sign in

```json
"web": {
  "oidc": {
    "enabled": true, "issuer": "https://idp.example.com",
    "client_id": "saves", "scopes": "openid profile email",
    "label": "Single sign-on", "auto_provision": false,
    "admin_claim": "groups", "admin_value": "saves-admins"
  }
}
```

The flow is authorization code with PKCE (S256). A client_secret makes
the client confidential, otherwise it is a public client. The redirect
URI to register is `<public_url>/auth/oidc/callback`. Web.public_url is
required for OIDC. The issuer defaults to auth.oidc.issuer and reuses
auth.oidc.algs. With auto_provision=false an unknown subject is
rejected without creating a user row. admin_claim/admin_value grant
admin for that session when the claim (string or array) contains the
value. When the sandbox is in enforce mode and the issuer is not on
443, add its port to sandbox.extra_connect_tcp_ports.

## Bootstrap

`savesd init` writes web.enabled with a fresh secret and creates web
credentials for the admin user (username "admin", random 24 character
password, must_change=true), printed once or written to
-init -password-file. Manage credentials later with:

```
savesd admin web-user set-password <username|user-id|subject> [-username NAME] [-admin] [-password-file FILE]
savesd admin web-user reset-2fa <username>
```

## Reverse proxy

Set proxy.trusted_cidrs to the proxy addresses and web.public_url to
the external URL. Forwarded headers (X-Forwarded-Proto, X-Forwarded-Host,
X-Forwarded-For, proxy.real_ip_header) are honored only from those
peers. A request whose Host does not match public_url gets a 421 page.
public_url may carry a path prefix. Links and cookie paths use it, and
the proxy may or may not strip it.

nginx:

```
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Caddy:

```
reverse_proxy 127.0.0.1:8787
```

Traefik labels set X-Forwarded-* automatically. Only trusted_cidrs
must list the proxy. A plain h2c backend works. Enable h1+h2c in
listen.protocols.

## Snapshot viewer

Each snapshot under /account has a tree view with directories sorted
first, a file view for text, pretty printed JSON, images rendered inline,
a hex dump for binary files, and a summary panel for NBT save data.
Truncated files get a notice. Two snapshots can be diffed with added,
changed and removed lists plus a line diff for changed text files.
Encrypted snapshots redirect to the snapshot page.

## API docs

/docs is a self hosted API reference rendered from api/openapi.yaml, and
/openapi.yaml serves the raw spec. Both are public and controlled by
web.api_docs.

## Homepage

The homepage doubles as the instance landing page. site.name,
site.description, site.terms_url, site.privacy_url, site.contact and the
announcement banner feed it, and the register button shows open or
invite wording per registration.mode.

# corehttpd

A minimal, secure HTTP/1.1 web server written in C, with built-in TLS 1.3.

corehttpd is intentionally small: one static binary, one optional library
dependency (`libjansson` for parsing the configuration), no other external
programs at runtime. All cryptography (SHA-256, HMAC, HKDF, X25519,
AES-128-GCM, ECDSA P-256) is implemented in-process — no OpenSSL or other
TLS library is needed to run it.

Features:

- HTTP/1.1 with keep-alive, IPv4
- TLS 1.3 (cipher suite `TLS_AES_128_GCM_SHA256`, key exchange X25519,
  ECDSA P-256 certificates) — works with current Firefox, Chrome, curl,
  OpenSSL and GnuTLS clients
- Virtual hosts with a hierarchy of directories (`site -> dir -> subdir …`)
- HTTP Basic authentication with constant-time password comparison
- IP-address / IP-network access control
- CGI programs run through a separate broker process, as a configurable
  per-program user
- Automatic `index.html` for directory requests (no directory listings)
- Automatic HTTP → HTTPS redirect on port 80, with an exception for
  Let's Encrypt ACME challenges
- Path-traversal protection (`./` and `../` are rejected and file paths are
  verified to stay inside the document root)
- Apache-style access log written by the master process (configurable
  name, owner, mode); safe to share one log file between instances
- Error log (configurable in a separate JSONC file) used by all
  processes: startup/shutdown, request problems, CGI failures
- `--daemonize` flag for systems without a service manager
- Companion program `corehttpd-acme` that fetches certificates from
  Let's Encrypt (ACME v2, HTTP-01) and installs them where the config
  expects them — challenge files go into `letsencrypt_root`, where
  corehttpd serves them
- All request memory comes from a single arena that is reset after each
  request

## Building

Requirements:

- a C11 compiler (the Makefile uses `musl-gcc`)
- `libjansson` (static), e.g. `libjansson-dev` on Debian/Ubuntu
- `corehttpd-acme` additionally needs the `curl` program and **up-to-date
  CA certificates** on the system (curl verifies the ACME server's
  certificate; on old systems the Let's Encrypt roots may be missing —
  see the troubleshooting note in the ACME section)

```sh
make
```

This produces the static binaries `./corehttpd` and
`./corehttpd-acme` (the Let's Encrypt companion).

## Running

corehttpd must be started as root, because it binds ports 80 and 443:

```sh
./corehttpd [OPTIONS] [/path/to/config.jsonc]
```

If no path is given, `/etc/corehttpd/config.jsonc` is used. Running
`corehttpd -h` (or `--help`) prints a short usage summary.

Options:

| Option                      | Meaning                                            |
|-----------------------------|----------------------------------------------------|
| `-d`, `--daemonize`         | run in the background (double fork, `setsid`, redirect stdio) |
| `-e`, `--error-log-config P`| error-log config file (default: `/etc/corehttpd/errorlog.jsonc`) |

The server consists of three processes:

1. **master** — runs as root. Reads the configuration, reads the TLS
   certificate and private key *once*, opens ports 80 and 443, and forks
   the other processes. It writes all access-log lines to disk (the httpd
   process sends them to it over a socket pair). After forking it closes
   the listening sockets, so only the unprivileged httpd process holds
   ports 80/443. On `SIGTERM`/`SIGINT` it forwards the signal to the
   httpd process, waits for the in-flight request to finish, then
   terminates the CGI broker and exits.
2. **httpd** — handles all HTTP/HTTPS requests. Drops privileges to the
   configured `httpd_user`. Does not fork per request.
3. **cgi broker** — started privileged (root) so it can switch to the
   configured per-program CGI user with `setuid`/`setgid`. The httpd process
   talks to it over a socket pair created by the master.

The listening sockets use `SO_REUSEPORT`, so an administrator can start
several instances on the same ports to scale across processes (each
connection is served synchronously within one process).

### Without systemd (SysV init and friends)

Use the daemonize flag from an init script or `rc.local`:

```sh
/usr/local/sbin/corehttpd --daemonize /etc/corehttpd/config.jsonc
```

The process double-forks into the background; the starting process
exits with status 0 once the master is up (config, TLS key and log
files are loaded and validated *before* detaching, so configuration
errors are still visible on the terminal). `SIGTERM` stops it.

Note: with `--daemonize` the process changes its working directory to
`/`, so use **absolute paths** in the configuration (cert/key files,
document roots, log files). Without `--daemonize` the server stays in
the foreground — which is what you want under systemd.

### systemd example

A template unit makes it easy to run several corehttpd instances for
concurrent request handling: the listening sockets use `SO_REUSEPORT`,
so all instances bind the same ports 80/443 and the kernel distributes
incoming connections across them.

`/etc/systemd/system/corehttpd@.service`:

```ini
[Unit]
Description=corehttpd instance %i
After=network.target

[Service]
ExecStart=/usr/local/sbin/corehttpd /etc/corehttpd/config.jsonc
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Start e.g. four instances (each runs its own master, httpd and CGI
broker processes):

```sh
systemctl enable --now corehttpd@{1,2,3,4}
```

The number of instances is a scaling knob; any of them can be stopped or
started at any time without disturbing the others.

Under systemd you can skip the log-file configuration entirely: without
an `access_log` and an error-log file, both logs go to stdout in the
foreground, and systemd forwards stdout to the journal
(`journalctl -u corehttpd@1`).

## Configuration

The configuration file is **JSONC** — JSON with C-style comments
(`// …`, `/* … */`). A full example:

```jsonc
{
  // Users for the helper processes.
  "httpd_user": "nobody",      // httpd drops to this user (default: nobody)
  "cgi_user": "nobody",        // default user for CGI programs (default: nobody)

  // TLS material. Read once by the master; the httpd process never
  // accesses these files, so the key may be root-only (mode 600).
  "cert_file": "/etc/corehttpd/fullchain.pem",
  "key_file":  "/etc/corehttpd/privkey.pem",

  // Directory served for Let's Encrypt ACME challenges on port 80
  // (default: /var/www/letsencrypt).
  "letsencrypt_root": "/var/www/letsencrypt",

  // Where the ACME companion keeps its account key (optional; the
  // companion program reads this).  Point it at a writable filesystem
  // when the root filesystem is mounted read-only.
  "acme_account_key": "/var/lib/corehttpd/acme-account.pem",

  // ACME directory URL used by the companion program (optional).
  // Defaults to Let's Encrypt; set this to use a different ACME
  // provider (ZeroSSL, Buypass, an internal CA, ...).
  "acme_url": "https://acme.zerossl.com/v2/DV90",

  // Access log (optional).  Written by the master process in the
  // Apache "common" format.  If omitted, no access log is written.
  "access_log": "/var/log/corehttpd/access.log",
  "access_log_owner": "root:adm",   // "user" or "user:group" (default: root)
  "access_log_mode": "0640",        // octal string (default: 0640)

  // Size of the per-connection request arena (default: 32 MB).
  "arena_size": 33554432,

  // Global timeouts in seconds.  Individual directories may override
  // them (see below).
  "defaults": {
    "header_timeout": 10,     // reading the request line + headers
    "body_timeout": 30,       // reading the request body
    "keepalive_timeout": 60,  // reserved for the next request
    "cgi_timeout": 30         // a CGI program's total run time
  },

  // Virtual hosts, matched against the HTTP Host header (and, for TLS
  // certificate selection, against the SNI server name).
  // The first site is the fallback for unknown hosts.
  "sites": [
    {
      "name": "example.com",
      "documentroot": "/srv/www/example.com",

      // Optional per-site TLS certificate.  When a client connects with
      // SNI "example.com", this certificate is served instead of the
      // global one.  Omit to use the global cert_file/key_file.
      "cert_file": "/etc/corehttpd/certs/example.com.pem",
      "key_file":  "/etc/corehttpd/certs/example.com.key",

      // Basic authentication (optional).  Inherited by all subdirectories
      // unless a subdirectory defines its own auth block.
      "auth": { "user": "alice", "pass": "secret" },

      // IP allow-list (optional).  Entries are single addresses or
      // networks: "192.168.1.7", "10.0.0.0/8".  Without ip_allow
      // everyone is allowed; a malformed entry or an empty list is a
      // config error.  Subdirectories can only ever be stricter: their
      // list is intersected with the parent's.
      "ip_allow": ["127.0.0.1", "192.168.0.0/16"],

      // Per-directory timeouts (optional, inherited; may be longer or
      // shorter than the parent's).
      "header_timeout": 15,
      "body_timeout": 60,

      // CGI programs for this directory (see below).
      "cgi": [
        {
          "name": "status.cgi",   // matched against the URL path
          "user": "www-status"    // run as this user (default: cgi_user)
        }
      ],

      // Subdirectories, in the same format.  Name is relative to the
      // parent directory; the filesystem path is derived from it unless
      // an explicit documentroot is given.
      "subdirs": [
        {
          "name": "admin",
          "auth": { "user": "admin", "pass": "hunter2" },
          "ip_allow": ["10.0.0.0/8"],
          "cgi": [
            { "name": "backup.cgi", "user": "backup" }
          ]
        }
      ]
    }
  ]
}
```

### Top-level keys

| Key                | Meaning                                             | Default               |
|--------------------|-----------------------------------------------------|-----------------------|
| `httpd_user`       | user the httpd process runs as                     | `nobody`              |
| `cgi_user`         | fallback user for CGI programs                     | `nobody`              |
| `cert_file`        | PEM certificate chain (or single DER); the default cert | —               |
| `key_file`         | PEM/DER EC private key (P-256, SEC1 or PKCS#8)     | —                     |
| `letsencrypt_root` | where ACME challenge files are read from           | `/var/www/letsencrypt`|
| `acme_account_key` | where corehttpd-acme stores its account key         | `acme-account.pem` next to the config |
| `acme_url`         | ACME directory URL used by corehttpd-acme           | Let's Encrypt production |
| `access_log`       | access log file (absent = no access log)           | —                     |
| `access_log_owner` | owner of the access log file (`user[:group]`)      | `root`                |
| `access_log_mode`  | mode of the access log file (octal string)         | `0640`                |
| `arena_size`       | request arena size (bytes)                         | 32 MB                 |
| `defaults`         | global timeouts (see below)                        | 10 / 30 / 60 seconds  |
| `sites`            | array of virtual hosts                             | —                     |

### Sites and directories

Each site has a `name` (matched case-insensitively against the `Host`
header, with an optional `:port` suffix ignored) and a `documentroot`,
which is required: a site without one is a config error (there is no
default, so a forgotten entry can never serve `/`).
Directories are nested through the `subdirs` array; each entry has a
`name` (the URL component) and an optional `documentroot` (default:
parent path + `/<name>`). Every `documentroot` must be an absolute path.

A subdir `name` may be a **glob pattern** with `*` (any run of
characters) and `?` (one character) — useful to cover many similarly
named directories at once:

```jsonc
"subdirs": [
  { "name": "0*", "auth": { "user": "bob", "pass": "builder" } },
  { "name": "*.cgi-bin", "ip_allow": ["10.0.0.0/8"] }
]
```

`0*` matches every URL component starting with `0`; all settings of
the matched entry (auth, ACLs, timeouts, CGI) apply to every match.
Rules: literal names win over patterns, the *longest* matching pattern
wins, ties go to the first entry in the config. For pattern entries
without an explicit `documentroot`, the filesystem path is derived from
the *actual matched component* (so `0*` matching `0123` maps to
`<parent>/0123`), including for nested patterns. Names that contain `*`
or `?` are always treated as patterns — literal directories with those
characters in the name cannot be configured.

**Deny entries**: a subdir with `"deny": true` is not served at all —
the whole subtree below it answers `404 Not Found` (before any
authentication, so protected names are not even revealed):

```jsonc
"subdirs": [
  { "name": "0secret*", "deny": true },   // hide e.g. backups, drafts
  { "name": ".git",      "deny": true }
]
```

Deny entries can be literal or glob, and a denied directory stays
denied even if deeper entries are configured (children inherit `deny`,
also from a denied site root). Among matching *patterns* a deny entry
always wins, regardless of length or order; a *literal* name still wins
over patterns, so a literal entry can carve out an exception. `deny`
must be a JSON boolean — any other value is a config error.

Request paths containing `.` or `..` segments are rejected with
`400 Bad Request`, so they cannot be used to step around deny, auth or
`ip_allow` entries.

A site may carry its own TLS certificate (`cert_file`/`key_file`, always
a pair). The certificate is chosen during the TLS handshake from the
client's SNI server name; see "TLS / HTTPS" below. Sites without their
own certificate use the global one.

Restrictions are inherited and can only become **stricter**:

- **auth** — a child without its own `auth` block inherits the parent's.
- **ip_allow** — a child's list is *intersected* with the parent's: an
  address must be allowed by both. Parent `127.0.0.0/8` and child
  `127.0.0.5/32` give `127.0.0.5/32`; parent `0.0.0.0/0` and child
  `10.0.0.0/8` give `10.0.0.0/8`. If the lists do not overlap at all,
  nobody can access the child (a warning is logged at startup). Every
  entry must be `a.b.c.d` or `a.b.c.d/n` with `n` from 0 to 32;
  anything else, and an empty list, refuses to start.
- **sites and subdirs** need a `name` (a single path component for
  subdirs); a missing name is a config error.
- **timeouts** — freely adjustable per directory (inherited).
- **cgi** — a directory's CGI programs apply **only to that directory**;
  they are not inherited by subdirectories.

### Timeouts

`header_timeout`, `body_timeout`, `keepalive_timeout` and `cgi_timeout`
are seconds. They can be set in `defaults` and per directory (inherited
through the hierarchy). The httpd process applies the global values
when reading a request:

- `header_timeout` is the time for the **whole** TLS handshake and for
  the whole request line + headers — not per read, so a client that
  trickles bytes is cut off.
- `body_timeout` plus 1 second per 32 KB is the time for the whole
  request body; the same allowance applies to sending a static file. A
  single write to a client that stops reading fails after
  `body_timeout`.
- `cgi_timeout` (per directory) limits a CGI program's run time; it is
  then killed.

Because a process handles one connection at a time, a connection that
has sent nothing for 2 seconds is dropped as soon as another client is
waiting (idle keep-alive connections are dropped immediately).

### CGI

A CGI program is activated by listing it in `cgi`:

```jsonc
{
  "name": "gen.cgi",        // URL path component(s), e.g. "sub/gen.cgi"
  "path": "/opt/bin/gen",   // optional: absolute, or relative to the dir;
                            // omit to execute the matched file itself
  "user": "www-data"        // optional: user to run as (default: cgi_user)
}
```

The longest matching name wins, so `"gen.cgi/x/y"` runs `gen.cgi` with
`PATH_INFO=/x/y`. The CGI receives the standard environment variables
(`REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`, `CONTENT_TYPE`,
`CONTENT_LENGTH`, `SCRIPT_NAME`, `SCRIPT_FILENAME`, `DOCUMENT_ROOT`,
`PATH_INFO`, …) and its stdin is the request body (at most 16 MB;
larger bodies get `413`).

Output: the program writes CGI headers (`Content-Type:`, `Status: 404
Not Found`, `Location:` …), a blank line, then the body; corehttpd turns
the headers into an HTTP/1.1 response. Output that starts with
`HTTP/` is passed through unchanged (non-parsed headers). Output without
a valid header block gets `502`. The response is not length-delimited,
so the connection is closed after it.

The broker runs as root so it can switch users. It does not trust the
httpd: the httpd only passes on the requested URL, and the broker
resolves the program and user from its own copy of the configuration,
so it only ever starts configured programs. CGI users must exist and
must not be root (checked at startup and again per request). The
program runs in its own process group, is fed its input and drained of
its output concurrently, and is killed (with its children) when it
exceeds `cgi_timeout`.

## Logging

### Access log

Every completed HTTP request is logged by the **master** process in the
Apache "common" format:

```
127.0.0.1 - alice [22/Nov/2026:12:34:56 +0100] "GET /index.html HTTP/1.1" 200 1234
```

`client-ip - user [timestamp] "method path?query version" status bytes`.
The second field (ident) is always `-`; `user` is the configured auth
user when Basic authentication was required and succeeded, otherwise `-`;
`bytes` is the size of the response (header + body, nothing for
aborted connections).

The httpd process never opens the log file — it sends each line over a
socket pair to the master, which appends it. The file is opened with
`O_APPEND` and each line is written with a single `write()`, so several
corehttpd instances may share one access log file without corrupting
each other's lines. The owner and mode are applied by the master at
startup (it runs as root, so `chown`/`chmod` work).

Configuration (in the main config file):

| Key                | Meaning                                        | Default |
|--------------------|------------------------------------------------|---------|
| `access_log`       | path of the log file (absent = no access log)  | —       |
| `access_log_owner` | `"user"` or `"user:group"` (names or numeric)  | `root`  |
| `access_log_mode`  | mode as an octal string like `"0640"`          | `0640`  |

If `access_log` is not set and the server runs in the **foreground**,
access-log lines are written to **stdout** instead — which is exactly
what you want under systemd, where stdout is collected by the journal.
(The same happens if the configured file cannot be opened.) When
daemonized without an `access_log`, no access log is written.

### Error log

The error log is configured in a **separate JSONC file**, so it can be
maintained independently of the main configuration:

```jsonc
{
  // Where to write (mandatory for file logging).
  "file": "/var/log/corehttpd/error.log",

  // Ownership and mode, applied by the master at startup.
  "owner": "root:adm",
  "mode": "0640",

  // Minimum severity: "debug" < "info" < "warning" < "error"
  // (default: "info").
  "level": "warning"
}
```

Pass it with `-e` / `--error-log-config` (default:
`/etc/corehttpd/errorlog.jsonc`). If the file is missing or cannot be
parsed, corehttpd logs to **stdout** only and continues — except when
the file was requested explicitly, in which case a note is printed.
Under systemd, stdout ends up in the journal, so no error-log file is
needed at all.

The master opens the error log and **all three processes** (master,
httpd, CGI broker) write to it directly through an inherited
descriptor with `O_APPEND`, so concurrent writers never interleave
lines. Typical messages: startup and shutdown, TLS handshake failures,
CGI `setuid`/`exec` failures, bind errors. In the foreground, messages
are mirrored to stdout (the terminal / the systemd journal); with
`--daemonize`, stdout is redirected into the error log (so *all*
output lands there — configure an error log when daemonizing).

Example:

```
[Sat Nov 21 09:12:03 2026] [info] corehttpd starting, config /etc/corehttpd/config.jsonc
[Sat Nov 21 09:12:03 2026] [info] listening on ports 80 and 443
[Sat Nov 21 09:14:22 2026] [warning] TLS handshake failed (client 203.0.113.7)
[Sat Nov 21 09:20:41 2026] [info] received signal 15, shutting down
[Sat Nov 21 09:20:41 2026] [info] shutdown complete
```

### Multiple instances

Both logs are safe to share between instances running on the same
machine (or writing to a shared volume): every writer appends with
`O_APPEND` and writes one line per `write()` call. Set `access_log` to
the same path in each instance's config and point `-e` at the same
error-log config; the file owner/mode are simply re-applied by every
master at startup.

## TLS / HTTPS

- TLS 1.3 only, cipher suite `TLS_AES_128_GCM_SHA256`, X25519 key
  exchange, `ecdsa_secp256r1_sha256` signatures.
- The certificate **must be an ECDSA P-256 certificate** (e.g. a Let's
  Encrypt ECDSA certificate: point `cert_file` at `fullchain.pem` and
  `key_file` at `privkey.pem`). RSA certificates are not supported.
- **Per-site certificates via SNI**: a site with `cert_file`/`key_file`
  serves that certificate to clients whose ClientHello names the site
  in SNI (every browser, curl, … does). Connections without SNI — or
  with an unknown server name — get the default certificate: the global
  `cert_file`/`key_file`, or the first site's certificate if no global
  pair is configured. HTTP requests are still routed by the `Host`
  header independently of which certificate was served.
- The private key may be PEM (`BEGIN EC PRIVATE KEY` or
  `BEGIN PRIVATE KEY`, i.e. SEC1 or PKCS#8) or raw DER. The curve and
  the key value are validated, and the key must belong to the first
  (leaf) certificate in `cert_file`; otherwise startup is refused.
- All cryptography touching secrets — ECDSA signing (nonce and key),
  AES (bitsliced S-box, no lookup tables) and GHASH — runs in constant
  time, so signing time does not leak the key. A client key share that
  yields the all-zero X25519 secret is rejected, as are records that
  break the TLS 1.3 record rules (size limits, plaintext after
  ServerHello).
- The master process loads and parses **every** certificate and key
  (the global pair plus each site's own pair) **once at startup** and
  shares them with the httpd child, so key files only need to be
  readable by root — the unprivileged httpd user never reads them.
  Identical `(cert_file, key_file)` pairs referenced by several sites
  are loaded only once.
- Certificate files that do not exist yet are **not fatal**: corehttpd
  starts with a warning and serves the default certificate for those
  sites (this is what makes the ACME HTTP-01 bootstrap possible, see
  below). Unreadable or invalid files, however, abort startup.
- When no certificate is configured at all, connections to port 443 are
  rejected with a proper TLS `handshake_failure` alert — clients fail
  fast with a clear error instead of hanging. Connections that never
  send a ClientHello (telnet, port scanners) are closed after a brief
  2-second grace period.
- No PSK, session resumption, early data or ALPN. Clients get a fresh
  full handshake per connection, which is fine for browsers.
- The `openssl` CLI is *not* required at runtime; it is only convenient
  for generating the certificate in the first place, e.g.:

  ```sh
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout privkey.pem -out cert.pem -days 90 -nodes \
      -subj "/CN=example.com" \
      -addext "subjectAltName=DNS:example.com"
  ```

## Let's Encrypt (ACME)

`corehttpd-acme` is a companion program that obtains certificates from
Let's Encrypt using the ACME v2 protocol with **HTTP-01 verification**
and installs them at the paths corehttpd's configuration expects. It
only needs the `curl` program for talking to the ACME server; account
key generation, the ES256 JWS signatures and the CSR are computed
in-process (same ECDSA P-256 code as tls.c).

### Getting a certificate

1. Configure a site with `cert_file`/`key_file` paths and a
   `letsencrypt_root` (the HTTP-01 challenge files are written there;
   the directory need not exist yet — it is created by the server):

   ```jsonc
   {
     "letsencrypt_root": "/var/www/letsencrypt",
     "sites": [
       {
         "name": "example.com",
         "documentroot": "/srv/www/example.com",
         "cert_file": "/etc/corehttpd/certs/example.com.pem",
         "key_file":  "/etc/corehttpd/certs/example.com.key"
       }
     ]
   }
   ```

   Note that corehttpd *starts even when these certificate files do not
   exist yet* (it logs a warning and uses the default certificate for
   that site) — that is exactly the state you need for the first run,
   because the HTTP-01 challenge must be served on port 80.

2. Make sure the domain resolves to the server and port 80 is reachable
   from the internet, then run:

   ```sh
   corehttpd-acme
   ```

   It reads `/etc/corehttpd/config.jsonc`, issues one certificate for
   every site with `cert_file`/`key_file` configured, writes the
   challenge into `letsencrypt_root` (which corehttpd serves under
   `/.well-known/acme-challenge/`), verifies the challenge itself over
   HTTP before asking Let's Encrypt, downloads the certificate chain
   and writes it (mode 0644) plus a fresh P-256 private key (mode
   0600). The key format is SEC1 PEM, which corehttpd loads directly.

3. Restart corehttpd to load the new certificates:
   `kill $(pidof corehttpd)` (or `systemctl restart corehttpd@1`).

### Renewing

Run the same command again. Certificates that are still valid for more
than `--renew-days` (default: 30) days are skipped; everything else is
re-issued. This makes the tool cron-friendly:

```cron
17 3 * * * root /usr/local/sbin/corehttpd-acme
30 3 * * * root pkill -x corehttpd || true
```

### Options

```
corehttpd-acme [OPTIONS] [CONFIG]
  -d, --domain NAME    domain for the certificate (repeatable)
  --cert FILE          output certificate chain (with -d)
  --key FILE           output private key (with -d)
  --account-key FILE   ECDSA P-256 account key; created with mode 0600
                       if missing (default: the acme_account_key from
                       CONFIG, else acme-account.pem next to CONFIG)
  --contact EMAIL      email to register with the ACME account
  --staging            use the Let's Encrypt staging directory
  --acme-url URL       ACME directory URL (default: the acme_url from
                       CONFIG, else Let's Encrypt production)
  --renew-days N       skip certificates valid for more than N days
                       (default: 30; 0 = always renew)
  --self-check-base U  fetch challenge files from U instead of
                       http://<domain> (for testing)
  -h, --help           show this help and exit
```

Without `-d`, one certificate per site (its configured paths are used).
With `-d NAME`, one certificate for the given domain(s); `--cert`/`--key`
name the output files (or the matching site's paths are used). Use
`--staging` for your first experiments — the staging directory issues
untrusted certificates but has generous rate limits.

The ACME account is identified by the account key; the first run
creates it. `--contact` is only needed on that first run — it is stored
with the account and later runs ignore it, so you can leave it out of
cron jobs. (If you *do* pass it again it must be the same address: the
ACME server rejects contact changes through `newAccount`.) Where the
account key lives is resolved in this order: the `--account-key`
option, then the `acme_account_key` entry in the configuration file,
then `acme-account.pem` next to the configuration file. The config
entry exists for machines whose root filesystem is mounted read-only —
point it at a writable location (e.g. `/var/lib/corehttpd/`). If the
account key is lost, a new account is created on the next run. Keep the
account key file safe (mode 0600, root only).

### From staging to production

After a successful `--staging` test run, a *staging-issued* certificate
is installed. If you then run without `--staging`, the renewal check
would normally skip the still-valid certificate — but corehttpd-acme
recognizes the Let's Encrypt staging CA in the certificate's issuer and
replaces it automatically when talking to a non-staging directory:

```sh
corehttpd-acme                 # staging cert -> real cert, no flags needed
```

(Previously this required `--renew-days 0`; no longer.)

### Troubleshooting

- `cannot fetch directory ...: curl failed: ...` — the program shows
  curl's own error message. Common causes:
  - `cannot run curl: No such file or directory` — install curl.
  - `Could not resolve host` — DNS problem.
  - `SSL certificate problem ... unable to get local issuer
    certificate` — the system's CA certificates are outdated (e.g. the
    Let's Encrypt ISRG Root X1 missing on an old distribution). Fix it
    properly with `apt update && apt install ca-certificates` (or the
    equivalent), or point curl at a fresh CA bundle without touching
    the system:

    ```sh
    SSL_CERT_FILE=/path/to/fresh-ca-bundle.crt corehttpd-acme
    ```

    (`CURL_CA_BUNDLE` works the same way.)

### Other ACME providers

Any ACME v2 directory works, not just Let's Encrypt. Set `acme_url` in
the configuration:

```jsonc
{
  "acme_url": "https://acme.zerossl.com/v2/DV90",   // or Buypass, GTS, ...
  "sites": [ ... ]
}
```

The directory URL is resolved in this order: the `--acme-url` option,
then `--staging` (the Let's Encrypt staging directory), then the
`acme_url` entry in the configuration, then the Let's Encrypt
production directory. The directory URL — and every URL the ACME
server hands back — must be `https://`; anything else is refused
(only the local self-check of the challenge file uses plain HTTP).
Everything else — HTTP-01 verification, the ECDSA P-256 keys, the CSR —
is provider-independent. Note that the
certificates must still be ECDSA P-256 for corehttpd.

## Request handling

- **Port 80** accepts only `GET` and `HEAD`. Everything else is answered
  with `405 Method Not Allowed`. Ordinary requests receive a `301`
  redirect to `https://<host><path>`. Requests under
  `/.well-known/acme-challenge/` are served from `letsencrypt_root`
  instead, so Let's Encrypt HTTP-01 validation works.
- **Port 443** handles the full pipeline: host selection, IP allow-list,
  authentication, CGI dispatch, then static files. `HEAD` is handled like
  `GET` without the body; `POST` reaches CGI programs (a `POST` to a
  static path serves the file).
- Directory requests serve `<dir>/index.html`; there is no directory
  listing.
- Requests are parsed strictly: exactly one `Host` header is required,
  control characters and bare CR/LF are rejected (`400`), so is a
  malformed or repeated `Content-Length`; `Transfer-Encoding` (chunked
  bodies) gets `501`. The connection is closed after such errors.
- After 10 failed Basic-auth attempts within 60 seconds, a client IP
  gets `429 Too Many Requests` on protected paths for the rest of that
  minute.
- Connections support HTTP keep-alive; the server processes requests on
  a connection sequentially. While waiting for the next request on an
  idle keep-alive connection, the server watches the listening sockets
  and drops the idle connection as soon as a new connection arrives —
  so a client that keeps a connection open (e.g. after the port-80
  redirect) never delays other clients.
- Path traversal is rejected: `./`/`../` components and symlinks that
  escape the document root are denied (`403`/`404`). The check is made
  on the file actually opened, so swapping a symlink between check and
  use does not help.

## Security notes

- Memory for request handling comes from one arena per process; it is
  reset — and zeroed — between requests, so credentials and bodies do
  not linger. If the arena is exhausted the request is aborted. All
  other allocations are checked; a system allocation failure terminates
  the process. TLS keys and handshake secrets are wiped after use.
- User names and passwords are compared in constant time (both are
  always compared, and the time does not depend on the password
  length).
- Access-log fields are escaped (`\xHH` for control characters, `"`,
  `\` and non-ASCII bytes), so requests cannot forge log lines.
- Log files are opened by root without following symlinks and must be
  regular files with a single link; otherwise they are not used.
- The configuration file contains the Basic-auth passwords in clear
  text — protect it (`chmod 600`).
- The httpd process runs unprivileged; the only privileged operations
  (binding low ports, reading the private key, switching CGI users) live
  in the master and the CGI broker.
- `corehttpd-acme` keeps an ACME account key (mode 0600; location:
  `--account-key`, else `acme_account_key` in the config, else
  `acme-account.pem` next to the config). It identifies your ACME
  account — protect it like any private key.

## Known limitations

- IPv4 only.
- One connection at a time per process; scale by running more
  instances (`SO_REUSEPORT` allows them to share ports 80/443). Total
  deadlines and idle-connection preemption (see "Timeouts") limit how
  long one slow or silent client can hold a process, but a client that
  keeps sending slowly can still occupy it for up to the timeouts, so
  run several instances on exposed servers.
- TLS 1.3 only; clients limited to TLS ≤ 1.2 cannot connect.
- ECDSA P-256 certificates only.
- No TLS session resumption, no HTTP/2.
- Access-log lines are batched by the master on a ~1 second cycle, so a
  freshly completed request may take up to a second to appear in the
  file.
- Very large certificate chains: each file is limited to 1 MB and all
  config/TLS material (the global pair *plus every site's pair*) must
  fit in the master's 10 MB config arena. Keep the total number of
  sites with distinct certificates modest, or raise the arena.
- `corehttpd-acme` requires the `curl` program at runtime; only HTTP-01
  verification is supported (no DNS-01, no wildcard certificates).

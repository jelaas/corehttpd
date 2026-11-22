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
- All request memory comes from a single arena that is reset after each
  request

## Building

Requirements:

- a C11 compiler (the Makefile uses `musl-gcc`)
- `libjansson` (static), e.g. `libjansson-dev` on Debian/Ubuntu

```sh
make
```

This produces a static binary `./corehttpd`.

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
   process sends them to it over a socket pair). On `SIGTERM`/`SIGINT` it
   forwards the signal to the httpd process, waits for the in-flight
   request to finish, then terminates the CGI broker and exits.
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
    "keepalive_timeout": 60   // reserved for the next request
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
      // networks: "192.168.1.7", "10.0.0.0/8".  An empty/absent list
      // means everyone is allowed.  Subdirectories can only ever be
      // stricter: their list is intersected with the parent's.
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
| `access_log`       | access log file (absent = no access log)           | —                     |
| `access_log_owner` | owner of the access log file (`user[:group]`)      | `root`                |
| `access_log_mode`  | mode of the access log file (octal string)         | `0640`                |
| `arena_size`       | request arena size (bytes)                         | 32 MB                 |
| `defaults`         | global timeouts (see below)                        | 10 / 30 / 60 seconds  |
| `sites`            | array of virtual hosts                             | —                     |

### Sites and directories

Each site has a `name` (matched case-insensitively against the `Host`
header, with an optional `:port` suffix ignored) and a `documentroot`.
Directories are nested through the `subdirs` array; each entry has a
`name` (the URL component) and an optional `documentroot` (default:
parent path + `/<name>`).

A site may carry its own TLS certificate (`cert_file`/`key_file`, always
a pair). The certificate is chosen during the TLS handshake from the
client's SNI server name; see "TLS / HTTPS" below. Sites without their
own certificate use the global one.

Restrictions are inherited and can only become **stricter**:

- **auth** — a child without its own `auth` block inherits the parent's.
- **ip_allow** — a child's list is *intersected* with the parent's.
- **timeouts** — freely adjustable per directory (inherited).
- **cgi** — a directory's CGI programs apply **only to that directory**;
  they are not inherited by subdirectories.

### Timeouts

`header_timeout`, `body_timeout` and `keepalive_timeout` are seconds.
They can be set in `defaults` and per directory (inherited through the
hierarchy). The httpd process applies the global `header_timeout` and
`body_timeout` when reading a request.

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
`PATH_INFO`, …), its stdin is the request body, and its stdout is
forwarded to the client (headers such as `Status:` are honoured).
The broker switches to the configured user (if it can; otherwise the
program exits with status 126).

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
  `BEGIN PRIVATE KEY`, i.e. SEC1 or PKCS#8) or raw DER. The curve is
  validated; keys for other curves or algorithms are rejected at
  startup.
- The master process loads and parses **every** certificate and key
  (the global pair plus each site's own pair) **once at startup** and
  shares them with the httpd child, so key files only need to be
  readable by root — the unprivileged httpd user never reads them.
  Identical `(cert_file, key_file)` pairs referenced by several sites
  are loaded only once.
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
- Connections support HTTP keep-alive; the server processes requests on
  a connection sequentially.
- Path traversal is rejected: `./`/`../` components and symlinks that
  escape the document root are denied (`403`/`404`).

## Security notes

- Memory for request handling comes from one arena per process; it is
  reset between requests. If the arena is exhausted the request is
  aborted. All other allocations are checked; a system allocation
  failure terminates the process.
- Passwords are compared in constant time to reduce timing side
  channels.
- The configuration file contains the Basic-auth passwords in clear
  text — protect it (`chmod 600`).
- The httpd process runs unprivileged; the only privileged operations
  (binding low ports, reading the private key, switching CGI users) live
  in the master and the CGI broker.

## Known limitations

- IPv4 only.
- One request at a time per process; scale by running more instances
  (`SO_REUSEPORT` allows them to share ports 80/443).
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

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
./corehttpd [/path/to/config.jsonc]
```

If no path is given, `/etc/corehttpd/config.jsonc` is used.

The server consists of three processes:

1. **master** — runs as root. Reads the configuration, reads the TLS
   certificate and private key *once*, opens ports 80 and 443, and forks
   the other processes. On `SIGTERM`/`SIGINT` it forwards the signal to the
   httpd process, waits for the in-flight request to finish, then terminates
   the CGI broker and exits.
2. **httpd** — handles all HTTP/HTTPS requests. Drops privileges to the
   configured `httpd_user`. Does not fork per request.
3. **cgi broker** — started privileged (root) so it can switch to the
   configured per-program CGI user with `setuid`/`setgid`. The httpd process
   talks to it over a socket pair created by the master.

The listening sockets use `SO_REUSEPORT`, so an administrator can start
several instances on the same ports to scale across processes (each
connection is served synchronously within one process).

### systemd example

```ini
[Unit]
Description=corehttpd
After=network.target

[Service]
ExecStart=/usr/local/sbin/corehttpd /etc/corehttpd/config.jsonc
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

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

  // Size of the per-connection request arena (default: 32 MB).
  "arena_size": 33554432,

  // Global timeouts in seconds.  Individual directories may override
  // them (see below).
  "defaults": {
    "header_timeout": 10,     // reading the request line + headers
    "body_timeout": 30,       // reading the request body
    "keepalive_timeout": 60   // reserved for the next request
  },

  // Virtual hosts, matched against the HTTP Host header.
  // The first site is the fallback for unknown hosts.
  "sites": [
    {
      "name": "example.com",
      "documentroot": "/srv/www/example.com",

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
          "cgi_clear": true,           // drop inherited CGI programs
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
| `cert_file`        | PEM certificate chain (or single DER)              | —                     |
| `key_file`         | PEM/DER EC private key (P-256, SEC1 or PKCS#8)     | —                     |
| `letsencrypt_root` | where ACME challenge files are read from           | `/var/www/letsencrypt`|
| `arena_size`       | request arena size (bytes)                         | 32 MB                 |
| `defaults`         | global timeouts (see below)                        | 10 / 30 / 60 seconds  |
| `sites`            | array of virtual hosts                             | —                     |

### Sites and directories

Each site has a `name` (matched case-insensitively against the `Host`
header) and a `documentroot`. Directories are nested through the
`subdirs` array; each entry has a `name` (the URL component) and an
optional `documentroot` (default: parent path + `/<name>`).

Restrictions are inherited and can only become **stricter**:

- **auth** — a child without its own `auth` block inherits the parent's.
- **ip_allow** — a child's list is *intersected* with the parent's.
- **timeouts** — freely adjustable per directory (inherited).
- **cgi** — a child inherits the parent's CGI programs; entries with the
  same `name` are overridden, `"disabled": true` removes an entry, and
  `cgi_clear: true` drops everything inherited before applying the
  child's own list.

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
  "user": "www-data",       // optional: user to run as (default: cgi_user)
  "disabled": true          // optional: remove an inherited entry
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

## TLS / HTTPS

- TLS 1.3 only, cipher suite `TLS_AES_128_GCM_SHA256`, X25519 key
  exchange, `ecdsa_secp256r1_sha256` signatures.
- The certificate **must be an ECDSA P-256 certificate** (e.g. a Let's
  Encrypt ECDSA certificate: point `cert_file` at `fullchain.pem` and
  `key_file` at `privkey.pem`). RSA certificates are not supported.
- The private key may be PEM (`BEGIN EC PRIVATE KEY` or
  `BEGIN PRIVATE KEY`, i.e. SEC1 or PKCS#8) or raw DER. The curve is
  validated; keys for other curves or algorithms are rejected at
  startup.
- The master process loads and parses the certificate and key **once at
  startup** and shares them with the httpd child, so the key file only
  needs to be readable by root — the unprivileged httpd user never reads
  it.
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
- Very large certificate chains: each file is limited to 1 MB and all
  config/TLS material must fit in the master's 10 MB config arena.

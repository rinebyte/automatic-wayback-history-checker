# Standalone Wayback Checker

A single-file, zero-dependency Python 3.10+ CLI for reviewing the monthly
root-page history of a domain in the Internet Archive.

## Run

```bash
python3 wayback_checker.py example.com
python3 wayback_checker.py example.com --json
python3 wayback_checker.py example.com --full-scan
```

Requires only the standard library, but Python must be able to verify TLS
certificates. A python.org build on macOS ships without a CA bundle until you
run `Install Certificates.command` from its `/Applications` folder; otherwise
every request fails with `CERTIFICATE_VERIFY_FAILED`. `SSL_CERT_FILE` also
works.

Options:

- `--json` writes one machine-readable JSON document.
- `--full-scan` attempts every returned monthly capture (maximum 500).
- `--proxy URL` overrides the fallback in `WAYBACK_PROXY_URL`.
- `--timeout 1..120` overrides both per-attempt socket timeouts.
- `--workers 1..8` controls replay concurrency; default `3`.
- `--keyword TERM` adds a custom literal risk term and may be repeated.
- `--verbose` writes progress and retry diagnostics to stderr.

Supported proxies are `http://host:port`,
`http://user:password@host:port`, `host:port`, and
`host:port:user:password`. Credentials are redacted from output.

Requests start with a direct attempt. The configured proxy is used after a
retryable status or network failure; after rescuing a request, it is preferred
for 60 seconds.

A `429` or `503` is treated as a request to slow down rather than a transient
error: it starts a 10-second cooldown shared by every worker, so the whole scan
backs off together instead of each thread hammering the same closed door. A
`Retry-After` header overrides that delay, honoured up to 60 seconds. Other
retryable statuses keep the fast exponential backoff. Ctrl-C interrupts a
pending backoff or cooldown immediately. This is fallback routing, not an anonymity mode: a successful
first request goes directly to Archive.org. Explicit proxy routing ignores
ambient `NO_PROXY` settings.

Prefer `WAYBACK_PROXY_URL` for authenticated proxies so credentials do not
appear in shell history or the command's process-list arguments. Proxy
authentication is HTTP Basic over the plaintext connection to an `http://`
proxy; HTTPS Archive.org traffic remains protected inside the CONNECT tunnel.

## Scan modes

Adaptive mode samples up to 20 captures, expands around risk/redirect
findings and title transitions, and stops at 40 submitted captures. Use
`--full-scan` when completeness is more important than runtime. Each replay is
attempted up to three times, so a worst-case 500-capture full scan can run for
a couple of hours under repeated timeouts, and longer if Archive.org keeps
asking for cooldowns.

## Interpretation

Built-in categories cover gambling, pharma, adult, and loan/scam terms.
Matches are heuristic indications, not legal conclusions. False positives
and false negatives are possible. The scanner does not execute JavaScript,
perform OCR, inspect images, or crawl internal archived paths, so root-page
results do not prove the history of an entire site.

## Exit codes

- `0`: lookup completed, including heuristic findings or partial replay errors
- `2`: invalid input or CLI usage
- `3`: fatal CDX lookup failure
- `4`: unexpected internal failure
- `130`: interrupted by the user

JSON failures contain only `{"error":{"code":"...","message":"..."}}`.

## JSON overview

Successful JSON has five top-level fields:

- `domain`: normalized ASCII/IDNA domain.
- `snapshots`: valid monthly CDX capture metadata.
- `summary`: capture years, range, last status, and CDX redirect history.
- `scan`: coverage plus public replay results, `titleChanges`,
  `riskFindings`, and `redirects`.
- `warnings`: objects containing `code`, `message`, and nullable `timestamp`.

Within `scan`, `selected` is the number attempted, `completed` and `failed`
split that total, and `partial` is true when any selected replay failed.
`redirectType`, `redirectTarget`, and `crossHost` are nullable when no
redirect was observed or a target could not be classified.

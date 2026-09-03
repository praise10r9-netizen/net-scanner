## netscan

`netscan` is a small IPv4 TCP connect scanner intended for controlled network
diagnostics. It reports four explicit states: `open`, `closed`, `filtered`, and
`error`. A connect scan is intentionally used here because it gives reliable
results without requiring raw-socket privileges.

### Build and run

```bash
make
./netscan 127.0.0.1 22,80,443 1000
./netscan 192.168.1.10 1-1024 500 --json
```

The JSON mode is the integration contract for other tools. The scanner only
supports IPv4 targets today and should be used with authorization.

### Operator interface

After building, launch the dependency-free Tkinter console:

```bash
python3 ui/netscan_ui.py
```

The UI keeps scans off the main event loop, validates the timeout, supports a
 comma-separated port list or range, and presents results in an easy-to-scan
table with restrained state colors. On Linux, install the distribution's
Tkinter package if `import tkinter` is unavailable.

### What remains for an intermediate scanner

- Add CIDR and IPv6 target expansion with a concurrency and rate limit policy.
- Add interface selection, retries, cancellation, and scan timing metadata.
- Add protocol-aware service detection with banners only when explicitly enabled.
- Add packet-level tests, CLI integration tests, and CI across Linux targets.
- Add structured logging and an export format that includes tool version and
	scan assumptions.

This project is a diagnostic foundation, not a replacement for a full scanner.

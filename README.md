# Magus OpenSecMCP

# Magus OpenSecMCP

![CI Status](https://github.com/vahive-tobias/magus-opensecmcp/actions/workflows/ci.yml/badge.svg)

A deterministic execution firewall for MCP agents. Local-first, open source, no
LLM judging the thing it's meant to secure, no cloud dependency, no telemetry
leaving your machine.

It sits between your MCP client (Claude Desktop, Claude Code, Cursor, etc.)
and your real MCP servers. It approves or blocks each tool call using explicit
rules, a per-tool risk registry, cryptographic hash-pinning of tool
definitions, and a structural taint-tracking state machine over tool
*responses* never a model call. If it blocks something, nothing downstream
of it ever runs.

## Status

This is a working v0.1, not a prototype that only compiles. Everything below
has been run for real, against the real published `@modelcontextprotocol/server-filesystem`
package, not simulated:

- The gateway spawns the real downstream server and speaks real MCP to it.
- `tools/list` returns the server's real, live tool definitions.
- `tools/call` forwards approved calls and returns the server's real response.
- Every tool definition is hash-pinned at discovery; `config.yaml` ships with
  the real hashes captured from a real run, and one of them (`move_file`) is
  deliberately off by one character so your first run shows you the mismatch
  warning firing for real, not just described in a comment.
- The taint-tracking demo works end to end: reading a file with an injection
  attempt in it gets approved (reading is low-risk), but the *next* call
  even an identical, previously-successful read gets blocked, because the
  connection is now flagged. The blocked write genuinely does not happen; the
  file on disk is untouched.

What isn't done yet: dynamic (learned) server trust grading, more than one
downstream server at a time in the demo config, and a packaged binary release
— see [Roadmap](#roadmap).

## Installation & Quickstart

### macOS (via Homebrew)
You can install the gateway globally without needing to handle Apple developer signing certificates:

```bash
brew tap vahive-tobias/tap
brew install magus-opensecmcp

Requires Rust and Node (the demo downstream server is `npx`-launched).

```bash
git clone [https://github.com/vahive-tobias/magus-opensecmcp.git](https://github.com/vahive-tobias/magus-opensecmcp.git)
cd magus-opensecmcp
cargo build --release
# ... rest of your existing quickstart instructions ...
mkdir -p /tmp/magus-demo
echo "hello" > /tmp/magus-demo/notes.txt
./target/release/magus-gateway config.yaml
```

Point your MCP client at this binary instead of the real filesystem server
directly, and watch `~/.magus/audit.jsonl` for the decision log. Or drive it
by hand to see it work without wiring up a client yet:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/magus-demo/notes.txt"}}}' \
  | ./target/release/magus-gateway config.yaml
```

## About the pinned dependency versions in Cargo.toml

`blake3`, `getrandom`, `uuid`, and `indexmap` are pinned to specific older
versions. That's not a requirement of this code it's because this was
verified in a sandbox stuck on an 18-month-old `rustc` (1.75) that can't parse
manifests requiring `edition2024`, which recent releases of those crates need.
If you're on a current toolchain (almost certainly true), delete those pin
lines and run `cargo update`, or just leave them either works. `Cargo.lock`
is committed on purpose, since this is a binary, and it's the exact lockfile
this was verified against.

## How it works

```
[MCP Client] <-- stdio/JSON-RPC --> [magus-gateway] <-- stdio/JSON-RPC --> [Real MCP Server]
                                          |
                                          |-- registry.rs   : per-tool risk_class / authority_source,
                                          |                   read from config.yaml, never self-attested
                                          |                   by the calling agent
                                          |-- hasher.rs      : recursive canonical blake3 hash of every
                                          |                   tool definition, pinned in config.yaml
                                          |-- membrane.rs    : per-agent risk budget, replay protection,
                                          |                   authority checks
                                          |-- provenance.rs  : Clean -> Elevated -> Contaminated -> Poisoned
                                          |                   state machine over real tool RESPONSES
                                          |-- downstream.rs  : the actual MCP client half - spawns and
                                          |                   talks to the real server
                                          |-- audit.rs       : local JSONL log, ~/.magus/audit.jsonl,
                                          |                   never leaves the machine
                                          |-- quota.rs       : local, in-memory, calendar-reset counter
```

`risk_class` and `authority_source` come from `config.yaml`'s `tools:` list —
the calling agent has no field in the MCP wire protocol to claim its own risk
level, so this can't be self-attested even by accident.

## config.yaml

```yaml
downstream_servers:
  - server_id: "local-filesystem"
    transport: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/magus-demo"]
    source_grade: "Known"   # Attested | Known | Unvalidated | Suspicious - defaults to Unvalidated

tools:
  - mcp_server_id: "local-filesystem"
    tool_name: "read_file"
    risk_class: "Low"        # Low | Medium | High | Critical
    authority_source: "User" # User | System | External
    pinned_definition_hash_hex: "..."  # optional; gateway prints the real hash on first run
```

Any tool the downstream server advertises that *isn't* in `tools:` still
works it's auto-registered at a `Medium` ceiling (`bootstrap: true` in the
audit log), never silently trusted at `Low` and never silently blocked
outright, so an unclassified tool doesn't break your agent on day one, but is
visibly flagged for you to go classify properly.

## registry-packs/

A pack is a pre-reviewed risk classification for a well-known server, meant
to be copied into your own `config.yaml`. `filesystem.yaml` is the one pack
in the repo that's been verified end-to-end against the real published
package as of this commit every hash in it is real. Treat any pack added
later as community-contributed until its own header says otherwise; a wrong
classification shipped under a "curated" banner is worse than guessing on
your own, so packs get reviewed like the security-relevant claims they are,
not merged like documentation. Contributions welcome — see below.

## Contributing a registry pack

1. Point `magus-gateway` at the real server with an empty `tools:` list and
   read the startup log, it prints every real tool name and its real hash.
2. Classify each tool's `risk_class` / `authority_source` honestly. When in
   doubt, classify one tier higher, not lower.
3. Submit the pack with the server's real package/repo link and the date you
   verified it, in the same format as `filesystem.yaml`.
4. Anything above `Medium` gets a second reviewer before merge.

## Roadmap

- [ ] `SourceRegistry`-style dynamic grading (promotion/demotion over time)
      v1 intentionally ships static, config-set grades only.
- [ ] More than one downstream server exercised in the shipped demo config.
- [ ] Packaged release binaries / Homebrew tap.
- [ ] More registry packs (GitHub, Postgres, Slack) verified against the
      real server before merge, per the contribution rule above.

## License

Apache-2.0. See `LICENSE`.

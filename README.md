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
  file on disk is untouched. The `~/.magus/audit.jsonl` line for that
  rejection now also names the exact rule that caused it (e.g. `DSO-001`),
  not just the resulting state.
- Detection rules are no longer compiled into the binary as a handful of
  hardcoded strings. They live in `locked-rules.yaml` (embedded into the
  binary at build time) and an optional `user-rules.yaml` you provide
  yourself — see "Detection rules" below.
- A tool's declared `outputSchema` is now actually checked. `SchemaConformance`
  used to sit at `NotDeclared` permanently because nothing populated it; a
  tool that declares an `outputSchema` and returns a `structuredContent`
  that doesn't match it now drives the state machine to `Poisoned`, the
  same as any other signature hit — see "Output schema conformance" below.

What isn't done yet: dynamic (learned) server trust grading, more than one
downstream server at a time in the demo config, a packaged binary release,
and the fuller normalization pipeline (NFKC/confusables skeletonization,
base64-peel-and-rescan) that `rules_engine.rs` deliberately stops short of
for now — see that file's module comment for exactly what's in v1 versus
noted as follow-up. See [Roadmap](#roadmap).

## Installation & Quickstart

### macOS (via Homebrew)
You can install the gateway globally without needing to handle Apple developer signing certificates:

```bash
brew tap vahive-tobias/tap
brew install magus-opensecmcp
```

Requires Rust and Node (the demo downstream server is `npx`-launched).

```bash
git clone [https://github.com/vahive-tobias/magus-opensecmcp.git](https://github.com/vahive-tobias/magus-opensecmcp.git)
cd magus-opensecmcp
cargo build --release
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

No `user-rules.yaml` is required to run any of the above — `locked-rules.yaml`
ships inside the binary and is active by default.

## About the pinned dependency versions in Cargo.toml

`blake3`, `getrandom`, `uuid`, and `indexmap` are pinned to exact versions
(`=1.5.4`, not `1.5`) in `Cargo.toml` itself — not just in `Cargo.lock`.
That's deliberate, not an accident of caret-range syntax: this project has
been verified against a sandbox stuck on an 18-month-old `rustc` (1.75) that
can't parse manifests requiring `edition2024`, which recent releases of
those specific crates need. An earlier version of this pin used loose
ranges (`"1.5"`) and relied on the committed `Cargo.lock` alone for
protection — that turned out to be fragile: deleting `Cargo.lock` and
letting the loose range re-resolve pulled in a `cpufeatures` dependency
requiring `edition2024`, breaking the build. **Exact pins in `Cargo.toml`
close that failure mode structurally** — no caret range can drift past an
exact pin, regardless of what happens to `Cargo.lock`.

Practical result: **`Cargo.lock` is safe to delete and regenerate freely**
(`cargo generate-lockfile` or just deleting it and running `cargo build`).
Only these four crates are constrained; everything else resolves normally
and picks up real updates over time. If you're on a current toolchain
(almost certainly true) and want the four pinned crates to move too, loosen
the `=` in `Cargo.toml` deliberately, in its own commit — don't let it
happen as a side effect of an unrelated dependency bump.

## How it works

```
[MCP Client] <-- stdio/JSON-RPC --> [magus-gateway] <-- stdio/JSON-RPC --> [Real MCP Server]
                                          |
                                          |-- registry.rs     : per-tool risk_class / authority_source,
                                          |                     read from config.yaml, never self-attested
                                          |                     by the calling agent
                                          |-- hasher.rs        : recursive canonical blake3 hash of every
                                          |                     tool definition, pinned in config.yaml
                                          |-- rules_engine.rs  : loads + compiles locked-rules.yaml (embedded)
                                          |                     and optional user-rules.yaml (disk) into an
                                          |                     Aho-Corasick + bounded-regex scanning engine.
                                          |                     Fail-closed: a broken user-rules.yaml refuses
                                          |                     to start, no silent fallback to locked-only.
                                          |-- membrane.rs      : per-agent risk budget, replay protection,
                                          |                     authority checks
                                          |-- provenance.rs    : Clean -> Elevated -> Contaminated -> Poisoned
                                          |                     state machine over real tool RESPONSES,
                                          |                     combining structural signals (shape, size,
                                          |                     schema) with rules_engine.rs's pattern hits
                                          |                     and schema_check.rs's outputSchema conformance
                                          |-- schema_check.rs  : narrow structural check of a tool response's
                                          |                     structuredContent against its declared
                                          |                     outputSchema, when one exists
                                          |-- downstream.rs    : the actual MCP client half - spawns and
                                          |                     talks to the real server
                                          |-- audit.rs         : local JSONL log, ~/.magus/audit.jsonl,
                                          |                     never leaves the machine, now includes which
                                          |                     rule id(s) caused a state escalation
                                          |-- quota.rs         : local, in-memory, calendar-reset counter
```

`risk_class` and `authority_source` come from `config.yaml`'s `tools:` list —
the calling agent has no field in the MCP wire protocol to claim its own risk
level, so this can't be self-attested even by accident.

## Detection rules: `locked-rules.yaml` + `user-rules.yaml`

Detection used to be four hardcoded literal strings compiled into
`provenance.rs`. It's now a real rules engine with a taxonomy across six
categories (system-override attempts, model control tokens, secret
exfiltration, command execution, encoding/smuggling, covert exfiltration
channels), configured from two YAML sources:

- **`locked-rules.yaml`** — the maintainer-shipped default set, embedded
  into the compiled binary via `include_str!`. It is not read from disk at
  runtime, on purpose: editing it requires rebuilding and redistributing the
  binary, which is a meaningfully higher bar than local file-write access.
  That's what makes it a real floor rather than just "the other config
  file."
- **`user-rules.yaml`** — optional, read from disk next to `config.yaml`.
  Copy `user-rules.example.yaml` to `user-rules.yaml` in the same directory
  to activate it and add your own rules. Its grammar is strictly additive:
  `action` only supports `flag | elevate | poison` there is no `allow` or
  `bypass` value, so a rule that tries to weaken enforcement fails to load
  rather than needing to be specially detected and rejected.

**Loading is fail-closed, with no fallback mode.** A missing
`user-rules.yaml` is a completely normal configuration and produces no error
at all. A `user-rules.yaml` that exists but is broken in any way invalid
YAML, a pattern that won't compile, a duplicate rule id, a suppression
aimed at a critical-severity rule stops the gateway from starting, with a
line-numbered error telling you what to fix:

```
[MAGUS] FATAL: rule engine failed to load — refusing to start.
[MAGUS]   user-rules.yaml, line 12: rule 'MY-RULE' pattern failed to compile: '(unclosed group'
[MAGUS]     caused by: regex parse error: ...
```

This is deliberate. A gateway that silently drops your custom rules and
keeps running on locked defaults would leave you believing protections were
active that weren't which is a worse failure than the gateway refusing to
start. If you want locked-rules.yaml only while you fix the problem, delete
or rename `user-rules.yaml` that's a supported, fully visible
configuration, not a hidden degraded mode.

Regex patterns run through Rust's `regex` crate, not a backtracking engine:
matching is worst-case linear time in the input regardless of pattern shape,
which is what makes it safe to run against attacker-controlled tool output.
Compiling a pathological *pattern* is a separate, real, historically-CVE'd
concern for untrusted-pattern input (`CVE-2022-24713`), which is why
`user-rules.yaml` patterns are compiled under an explicit `size_limit` /
`dfa_size_limit` and a raw source-length cap rather than trusted to compile
cheaply just because they're syntactically valid.

Any tool the downstream server advertises that *isn't* in `tools:` still
works it's auto-registered at a `Medium` ceiling (`bootstrap: true` in the
audit log), never silently trusted at `Low` and never silently blocked
outright, so an unclassified tool doesn't break your agent on day one, but is
visibly flagged for you to go classify properly.

## Output schema conformance

Some MCP tools declare an `outputSchema` alongside their `inputSchema` — a
promise about the shape of the `structuredContent` field they'll return
(per the MCP 2025-06-18 spec; older or simpler servers, like the reference
filesystem server this repo demos against, typically declare none at all,
and that's a completely normal `NotDeclared` case, not a problem). When a
tool DOES declare one, the gateway now checks the response against it:

- Conforms → `SchemaConformance::Conformant`.
- A `structuredContent` field is present but doesn't match → `Violated`,
  which drives the provenance state straight to `Poisoned` — the same
  enforcement path any other signature hit already uses.
- The schema is declared but the response has no `structuredContent` at
  all → stays `NotDeclared`, deliberately. Real-world servers are
  inconsistent about actually populating `structuredContent` even when
  they declare the schema; treating every such gap as a violation would
  make this noisy against legitimate, slightly-behind-spec tools rather
  than precise against malicious ones.

`schema_check.rs` is a deliberately narrow structural checker (`type`,
`properties`, `required`, `items`, `enum`, `additionalProperties: false`) —
not a general-purpose JSON Schema validator. A real one (the `jsonschema`
crate) pulls in URL/IDNA parsing for `$ref` resolution against remote URIs
and hits the same `edition2024` wall documented above, for machinery this
project's actual schemas — self-contained structural descriptions, not
multi-document schemas with external references — don't need. See that
file's header comment for the exact list of JSON Schema keywords this does
and doesn't understand.



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
- [ ] Fuller normalization pipeline in `rules_engine.rs` — NFKC, TR39
      confusables/homoglyph skeletonization, and a depth-capped
      base64/hex decode-and-rescan peel. v1 covers case-folding, whitespace
      collapse, zero-width stripping, and Unicode Tag-block decode only.
- [ ] Entropy-based escalation for secret-shaped rules (e.g. distinguishing
      a real AWS key from AWS's own documented `AKIAIOSFODNN7EXAMPLE`
      placeholder) rather than today's flag-only default for that category.
- [ ] Fetch and validate a tool's declared `outputSchema` at discovery time
      (alongside the hash-pinning already done), so `SchemaConformance` can
      actually reach `Violated` instead of sitting at `NotDeclared` — DONE.
      Still open: `pattern`-keyword support (cheap, given `regex` is already
      a dependency with size-bounded compilation this could reuse), and the
      full JSON Schema vocabulary `schema_check.rs` deliberately doesn't
      cover — see that file's header comment for the exact list.
- [ ] Escalate registration-time tool-description hits (currently a
      warning only, `scope: tool_description` in rules.yaml) to actually
      withholding a tool on a high/critical match, the way an
      `Unvalidated`/`Suspicious` source grade already withholds
      descriptions.

## License

Apache-2.0. See `LICENSE`.

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

**Before relying on this for anything, read [`THREAT_MODEL.md`](THREAT_MODEL.md)** —
what this actually defends against, what it doesn't, and why. Found a gap
between what that document claims and what the code does? See
[`SECURITY.md`](SECURITY.md) for how to report it.

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
- False-positive claims in `locked-rules.yaml`'s rule comments are backed by
  an actual three-tier test (`tests/false_positive_corpus.rs`), not just
  comments: known-legitimate content (Dockerfiles, install READMEs,
  `.env.example`, security write-ups quoting attack phrases as examples)
  must stay silent or non-blocking; known-attack-shaped content must still
  escalate. This test process is also what found and fixed a real gap —
  a genuine leaked AWS key and AWS's own documented placeholder key used
  to produce identical flag-only output; they don't anymore.
- The provenance state machine and risk-evaluation engine (`provenance.rs`,
  `membrane.rs`) — the oldest and most security-critical code in this
  repo — now have direct unit test coverage (56 tests) instead of only
  ever having been checked by hand. Covers the full source-grade/
  response-shape classification table, the rule-hit corroboration logic
  (a second heuristic signal while already `Contaminated` escalates to
  `Poisoned` — a single one doesn't), the invariant that a `Poisoned` session never
  auto-recovers regardless of how much subsequent activity occurs, and
  the full replay/quota/authority/risk-budget rejection matrix.
- Each provenance state now carries exactly one meaning, and the split
  between the middle two is deliberate: `Elevated` means external content
  was consumed with nothing detected — the routine case for a vetted
  server, not itself a signal. `Contaminated` means a heuristic rule hit
  fired and hasn't been corroborated yet. `Poisoned` means either a
  corroborated second hit or a deterministic contract breach (a malformed
  response, or a declared `outputSchema` that was violated) — the latter
  has no false-positive class, so it never needs corroboration. See
  `THREAT_MODEL.md` for the full reasoning.
- A confirmed hash-pin mismatch can now actually be enforced, not just
  logged. `security_policy.strict_schema_pinning: true` quarantines the
  specific mismatched tool — absent from `tools/list`, a distinct
  rejection if called by name anyway — without taking the rest of the
  gateway down. A stronger `refuse_startup_on_pin_mismatch: true` opt-in
  refuses the whole gateway to start, with a distinct exit code for
  script/CI detection. Both default off; an existing `config.yaml` is
  completely unaffected.
- When a response causes a genuine state escalation, the gateway now
  appends a plainly-labeled advisory into the response itself instead of
  silently changing state while forwarding the original content
  untouched. The wire format was settled by testing against a real MCP
  client, not by assumption — the first approach tried (a new field on
  the response envelope) actually broke the connection outright on a
  real client; see `THREAT_MODEL.md` for what was tested and why.
- Tools can be tagged `communicates_externally: true` to raise the cost
  of using them once a session shows evidence of compromise — see "How
  it works" below. The ordering question that determines whether this is
  a proportionate control or one that blocks routine operation was
  checked directly against the compiled binary, not just the test suite.
- `magus-gateway --version` and `magus-gateway --help` are real, tested
  flags (`tests/cli_flags.rs`, spawning the actual compiled binary, not
  calling internal functions) — added specifically because Homebrew's
  formula test needs `--version` to work, but useful regardless of how
  you installed it.
- Provenance decay now requires a verified-clean round trip, not the size
  of the agent's own outbound request, to heal a session's state back
  down. The earlier byte-based version let one padded, otherwise-unrelated
  call decay `Contaminated` back to `Elevated` for free, indefinitely —
  closing it meant moving the decay check from pre-response to
  post-response, keyed on the call's own verified outcome rather than
  anything the agent claims about itself.
- Rule scanning now evaluates every occurrence of a pattern in a response,
  not just the first. The earlier first-match-only scan meant a real
  secret appearing after a known-benign placeholder (the exact case
  `exempt_if_contains` exists to handle) was never evaluated at all, since
  the placeholder match consumed the scanner's only attempt. Multiple
  occurrences of the same rule still collapse to one signal for
  corroboration purposes — that's deliberate, not a regression.
- Configuring more than one downstream server no longer risks a silent
  bare-name collision. Tool names are resolved through an explicit
  three-phase discovery pipeline (discover, quarantine, resolve) that
  excludes every tool sharing an ambiguous name across servers, rather
  than letting whichever server was processed last in config order
  silently win. A `--discovery-report` flag shows the full picture —
  what's available to the agent, what's quarantined, what's excluded, and
  why — without wiring up a client first.
- A tool description from a trusted (`Attested`/`Known`-graded) server is
  now actually sanitized before being forwarded to the agent, not just
  scanned for a console warning that never touched what the agent
  received. Smuggling attempts — invisible Unicode characters used to
  hide instructions in plain sight — are stripped outright, not decoded
  and revealed.
- Downstream tool calls and the discovery handshake are both bounded by a
  configurable timeout now, so a stalled or hung downstream server no
  longer wedges the gateway indefinitely. A timeout rejects only that one
  call; a server that times out twice in a row is marked unavailable for
  the rest of the session (a restart clears it) rather than silently
  re-hanging on every subsequent call.

What isn't done yet: dynamic (learned) server trust grading, a packaged
binary release, and the fuller normalization pipeline (NFKC/confusables
skeletonization, base64-peel-and-rescan) that `rules_engine.rs`
deliberately stops short of for now — see that file's module comment for
exactly what's in v1 versus noted as follow-up. Multi-server tool
resolution itself is built and tested (see above); the shipped
`config.yaml` demo still only configures one server — see
[Roadmap](#roadmap).

## Installation & Quickstart

### macOS (via Homebrew)

```bash
brew tap vahive-tobias/tap
brew install magus-opensecmcp
```

Requires no local Rust toolchain — Homebrew builds it for you via the
formula's own `rust` dependency.

### Build from source

Requires Rust and Node (the demo downstream server is `npx`-launched).
On Windows, if the gateway fails to spawn the demo server, change
`command: "npx"` to `command: "npx.cmd"` in `config.yaml` — `npx` alone
resolves differently there. This is a real, hands-on-verified fix, not a
guess — but it's a point-in-time check, not an ongoing guarantee: CI
(the badge above) currently runs `ubuntu-latest`/`macos-latest` only, so
the Windows path isn't re-verified automatically on every change the way
the other two platforms are.

```bash
git clone https://github.com/vahive-tobias/magus-opensecmcp.git
cd magus-opensecmcp
cargo build --release
mkdir -p /tmp/magus-demo
echo "hello" > /tmp/magus-demo/notes.txt
./target/release/magus-gateway config.yaml
```

Point your MCP client at this binary instead of the real filesystem server
directly, and watch `~/.magus/audit.jsonl` for the decision log.

This is the entire security model, stated plainly: if your client is
*also* configured to reach the real downstream server directly — not
just through this gateway — nothing here can detect or prevent
whatever happens through that other path. The gateway only sees
traffic that's actually routed through it.

Or drive it by hand to see it work without wiring up a client yet:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/magus-demo/notes.txt"}}}' \
  | ./target/release/magus-gateway config.yaml
```

`magus-gateway --version` and `magus-gateway --help` both work if you just
want to confirm what's installed or see basic usage without a config file.

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
                                          |                     talks to the real server, discovery and
                                          |                     tools/call both bounded by a configurable
                                          |                     timeout; two consecutive timeouts on one
                                          |                     server mark that connection degraded for the
                                          |                     rest of the session (fails fast, no
                                          |                     auto-retry — see "Downstream timeouts" below)
                                          |-- audit.rs         : local JSONL log, ~/.magus/audit.jsonl,
                                          |                     never leaves the machine, now includes which
                                          |                     rule id(s) caused a state escalation
                                          |-- quota.rs         : local, in-memory, calendar-reset counter
```

Before any of this serves the agent, startup itself runs as an explicit
three-phase discovery pipeline: **discover** every tool from every
configured server, **quarantine** any tool whose hash-pin doesn't match
(before collision detection runs, deliberately — a tool already excluded
for a pin mismatch shouldn't also register as an ambiguous collision for
an unrelated reason), then **resolve** bare tool names, excluding every
tool whose name is still claimed by more than one surviving server once
quarantine has run. Only names left with exactly one claimant become
callable. Run `magus-gateway config.yaml --discovery-report` to see the
full breakdown — available, quarantined, excluded, or failed to
discover — without wiring up a client first.

Each state in that chain carries exactly one meaning as of this writing — see `THREAT_MODEL.md` for what `Clean`/`Elevated`/`Contaminated`/`Poisoned` actually mean and why the split between the middle two is deliberate.

`risk_class` and `authority_source` come from `config.yaml`'s `tools:` list —
the calling agent has no field in the MCP wire protocol to claim its own risk
level, so this can't be self-attested even by accident.

Each tool entry also accepts an optional `communicates_externally: true` —
operator-declared only, never auto-detected, defaulting to `false` so an
existing `config.yaml` written before this field existed parses and behaves
identically. It's for tools that reach outside the local machine (a
`fetch_url`, an HTTP client, anything hitting a network endpoint): once a
session shows evidence of compromise, a tagged tool's `risk_class` is bumped
up one tier (`Low→Medium→High→Critical`, saturating) on top of whatever the
provenance state table already applied — raising the cost of exfiltrating
through that specific tool, not blocking it outright. See `THREAT_MODEL.md`
for what this does and doesn't guarantee.

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

## Downstream timeouts

Both halves of the downstream connection — the discovery handshake
(`initialize`/`tools/list`) and every `tools/call` — are bounded by a
configurable timeout, so a stalled or hung downstream server can no
longer wedge the gateway indefinitely.

- Per-tool `timeout_seconds` in a `tools:` entry overrides the global
  `security_policy.default_tool_timeout_seconds` (30s). Per-server
  `discovery_timeout_seconds` in a `downstream_servers:` entry overrides
  `security_policy.default_discovery_timeout_seconds` (15s). Neither
  default is a measurement — they're policy judgment calls, the same as
  this codebase's other tuning constants. Zero, negative, NaN, and
  infinite values are all rejected at config-load time; there is no
  "wait forever" setting.
- A timeout rejects only that one call, with a distinct
  `DownstreamTimeout` rejection code. It does not retry — most tools
  aren't idempotent, and this project doesn't invent an
  "idempotent/safe-to-retry" property to make retrying safe.
- A SECOND consecutive timeout on the same connection marks it degraded
  for the rest of the process's life: every further call to that server
  fails immediately with `DownstreamConnectionDegraded`, without
  attempting or waiting at all. A successful call resets the streak.
  There's no automatic recovery — a genuinely wedged process needs a
  gateway restart, not a health-check loop guessing at when it's safe
  to try again.
- A discovery-time timeout excludes just that server and starts the
  gateway with whatever else discovered successfully — the hung server
  shows up in the `--discovery-report`/console summary's failed-servers
  section. The opt-in `security_policy.refuse_startup_on_discovery_timeout`
  makes any discovery failure a hard startup refusal instead.
- None of this — a single timeout, a degraded connection, either
  discovery outcome — ever feeds the provenance/risk-budget machinery.
  An absence isn't evidence about content, and there's no calibration
  basis for treating it as a signal the way an actual rule hit is.

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

Worth setting expectations here: even among servers that support the
newer MCP spec revisions, declaring `outputSchema` at all is still
uncommon in practice as of this writing — so `Conformant`/`Violated`
firing rarely, or not at all, in your own audit log doesn't mean the
mechanism is broken. The enforcement path is real and already tested;
it's waiting on more of the ecosystem to declare contracts, not on
anything missing here.

`schema_check.rs` is a deliberately narrow structural checker (`type`,
`properties`, `required`, `items`, `enum`, `additionalProperties: false`,
`pattern`) — not a general-purpose JSON Schema validator. A real one (the `jsonschema`
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
- [x] Multi-server tool resolution — DONE. Configuring more than one
      `downstream_servers:` entry is now resolved through an explicit
      three-phase discovery pipeline (discover, quarantine, resolve) that
      excludes any bare tool name claimed by more than one server, tested
      end to end against real spawned processes. Separate, smaller item
      still open: the shipped `config.yaml` demo itself only configures
      one server — this is a demo-content gap now, not a capability gap.
- [x] Homebrew tap — DONE. `vahive-tobias/homebrew-tap`, formula verified
      (correct license, version, and a real tested tag/revision pin), now
      backed by its own CI (`brew tap` → `brew audit --strict` →
      `brew install --build-from-source` → `brew test` →
      `--version`/`--help`) running on a real `macos-latest` GitHub Actions
      runner against the published formula and tag, rerunning on every
      future formula change — the install path itself is demonstrated now,
      not asserted.
- [ ] Packaged release binaries (e.g. prebuilt GitHub Release artifacts
      for Linux/other platforms) — separate from the Homebrew tap above,
      still not done.
- [ ] More registry packs (GitHub, Postgres, Slack) verified against the
      real server before merge, per the contribution rule above.
- [ ] Fuller normalization pipeline in `rules_engine.rs` — NFKC, TR39
      confusables/homoglyph skeletonization, and a depth-capped
      base64/hex decode-and-rescan peel. v1 covers case-folding, whitespace
      collapse, zero-width stripping, and Unicode Tag-block decode only.
- [x] Entropy-based escalation for secret-shaped rules — DONE for both
      `SECRET-AWS-001` and `SECRET-GH-001`: a real leaked key/token and
      each provider's own documented placeholder example no longer
      produce identical flag-only outcomes.
- [x] Fetch and validate a tool's declared `outputSchema` at discovery time
      so `SchemaConformance` can actually reach `Violated` instead of
      sitting at `NotDeclared` — DONE, including `pattern`-keyword support.
      Still open: the full JSON Schema vocabulary `schema_check.rs`
      deliberately doesn't cover — see that file's header comment for the
      exact list.
- [x] Escalate registration-time tool-description hits beyond a
      console-only warning — DONE, though what shipped routes through the
      existing detection-severity tiers rather than a new
      high/critical-specific rule: a poison-tier hit withholds a
      description unconditionally, an elevate/flag-tier hit is sanitized
      for forwarding and, under `security_policy.strict_description_scanning`,
      withheld too — the same tiering `locked-rules.yaml`/`user-rules.yaml`
      already use everywhere else, not a parallel one just for this.

## License

Apache-2.0. See `LICENSE`.

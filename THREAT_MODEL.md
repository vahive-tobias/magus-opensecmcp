# Threat Model

This document describes what `magus-opensecmcp` defends against, how, and
— just as importantly — what it does not defend against and why. It covers
only the code in this repository: a local, single-machine, stdio-based
proxy sitting between one MCP client and one or more MCP servers. Every
limitation below is a property of that architecture, not a withheld
capability — there is no larger system this document is deferring to.

If you find a gap in this document — a real attack this design doesn't
actually stop, despite claiming to — see `SECURITY.md` for how to report
it.

## What this is

A deterministic execution firewall. It intercepts MCP `tools/list` and
`tools/call` traffic and makes allow/block decisions using explicit rules,
a per-tool risk registry, cryptographic hash-pinning, and a taint-tracking
state machine over tool *responses*. No model call is ever in the decision
path. If it blocks a call, nothing downstream of it runs — the block
happens before the request reaches the real MCP server, not after.

## The actual security boundary

This is the one thing in this document worth reading even if nothing else
is: **the guarantee this tool makes is not "we detect every attack." It's
"once a session is judged `Poisoned`, destructive actions are refused,
regardless of why."**

Everything else — the six-category signature taxonomy in
`locked-rules.yaml`, the `outputSchema` conformance check in
`schema_check.rs`, the structural response classification in
`provenance.rs` — exists to get that judgment made with better precision
and recall. None of it is the boundary itself. A gap in signature coverage
degrades detection *sensitivity*; it does not degrade the capability gate
that fires once detection succeeds. This distinction matters for reading
every "not yet implemented" item below correctly: most of them make the
tool less likely to *notice* an attack, not less able to *stop* one it has
noticed.

Concretely, the gate: `membrane::modulate_risk_class` requires
`ProvenanceState::Clean` for any `RiskClass::Critical` action, full stop.
`ProvenanceState::Poisoned` refuses every subsequent action regardless of
its classified risk. There is no override, no LLM re-judgment, no
retry-with-different-framing path around this — it's a plain state
comparison.

The four states each carry exactly one meaning, with one documented
exception: `SourceGrade::Suspicious` still forces `Poisoned` directly,
independent of any observed evidence. That carve-out is deliberate, not an
oversight — it's an explicit administrative trust assertion (the operator
declared this server suspicious in `config.yaml`) rather than something
inferred from runtime evidence, and it's left in place rather than
generalized into the classification logic; see the comment at that check in
`provenance.rs` for the full reasoning. Elsewhere, the split between the
middle two states is the one worth understanding precisely: `Clean` — no
external influence observed. `Elevated` — external content was consumed,
but nothing was detected; this is the normal resting state for a routine
call against a graded server, not itself a signal. `Contaminated` —
heuristic evidence fired: a rule hit, uncorroborated, recoverable.
`Poisoned` — either a deterministic contract breach (a declared
`outputSchema` violated, or a response that didn't even parse) or
corroborated heuristic evidence (a second independent signal while already
`Contaminated`). The
`Contaminated`/`Poisoned` split is specifically heuristic vs. deterministic
evidence: a rule hit has a real false-positive class — see
`tests/fixtures/should_not_poison/security_blogpost_excerpt.md`, which
exists precisely because a legitimate security write-up can match a
signature — so it earns corroboration before reaching the capability gate's
full force. A schema violation or an unparseable payload has no
false-positive class; there is nothing to corroborate, so it poisons
directly.

## What this defends against

**Tool definition tampering ("rug-pull") between discovery and use.**
Every tool definition is canonically hashed (`hasher.rs`, recursive
blake3, length-prefixed and type-tagged to prevent concatenation
collisions) at discovery time. A pinned hash in `config.yaml` that
mismatches what the server actually returns is surfaced immediately — see
`main.rs`'s discovery loop. This defends against exactly the class of attack
behind `CVE-2025-54136` ("MCPoison") and its sibling `CVE-2025-54135`
("CurXecute"), both disclosed against Cursor in August 2025: a client
approved a tool identifier once, then the payload changed while the
approved name stayed the same. Hash-pinning the full definition — not
just the name — is what closes that specific, disclosed gap.

**Indirect prompt injection via tool output.** Tool *responses* — not the
agent's own conversation — are scanned against `locked-rules.yaml`
(embedded in the binary) and an optional, strictly additive
`user-rules.yaml`. Six categories: direct system-override attempts, model
control tokens, secret exfiltration, command execution patterns, encoding/
smuggling (Unicode Tag-block decode, zero-width stripping), and covert
exfiltration channels. See `rules_engine.rs`'s module header for exactly
which normalization steps are and aren't implemented — this list is
deliberately incomplete and says so in the source, not just here.

**Structural anomalies in tool responses.** Independent of signature
matching: response shape, aggregate size, and (when a tool declares one)
conformance to its own `outputSchema`. A tool that promised a small
structured object and returns something else entirely is anomalous
regardless of whether any signature fires — this catches shapes nobody
wrote a specific rule for.

**Config that tries to weaken itself.** `user-rules.yaml`'s action grammar
has no `allow`/`bypass` value — a rule that tries to weaken enforcement
fails to parse rather than needing to be specially detected and rejected.
A broken `user-rules.yaml` refuses to start the gateway entirely rather
than silently falling back to a lower protection level. See README,
"Detection rules."

**Regex-based DoS against the detection engine itself.** Pattern matching
uses Rust's `regex` crate specifically for its non-backtracking, linear-time
guarantee — not chosen for convenience. Because `user-rules.yaml` patterns
are, by definition, untrusted (anyone who can write that file controls
them), compiled pattern size is also bounded (`size_limit`/
`dfa_size_limit` in `rules_engine.rs`) against the separate, real
compile-time resource-exhaustion class of attack (CVE-2022-24713
precedent, not a hypothetical).

## What this does NOT defend against, and why

**Anything an already-*approved* tool call does.** This tool decides
whether a call is allowed to happen — not what happens once it does. If a
`Critical`-classified `write_file` call is approved, it writes with
whatever permissions the underlying OS process has. This is a proxy over
MCP traffic, not a sandbox, container, or OS-level access control layer;
those are a different problem with different tools.

**Misclassification in `config.yaml` itself.** Risk and authority
classification is operator-supplied. A tool marked `Low` risk that
shouldn't be is not something the gateway can independently discover —
static classification quality is a property of the config, not the
enforcement engine. (Registry packs exist specifically to reduce this risk
by centralizing reviewed classifications for well-known servers — see
README, "registry-packs/" — but an unreviewed or careless classification
in your own `config.yaml` is still yours to get right.)

**A compromised local machine.** This tool assumes the gateway binary,
`config.yaml`, `locked-rules.yaml`, and `user-rules.yaml` are themselves
trustworthy at startup. If an attacker already has local file-write access
sufficient to modify those before the gateway starts, they can weaken what
gets enforced — the monotonic `user-rules.yaml` grammar prevents an
*in-band* attacker (one only reaching the gateway through MCP traffic) from
doing this via a poisoned tool response, but it does not, and structurally
cannot, defend against an attacker who already has the access needed to
edit local files directly. This is an inherent property of a local,
single-machine tool with no independent trust anchor — not a gap specific
to this implementation.

**Attacks that don't route through this gateway.** If an agent has any
communication channel to a tool, network endpoint, or file system that
this proxy doesn't mediate, this tool has no visibility into it at all.

**The agent's own reasoning, system prompt, or the human operator's
instructions.** This watches tool call requests and responses. It has no
opinion on, and no visibility into, why the agent decided to make a
particular call in the first place.

**Detection completeness.** Stated plainly rather than implied: the
six-category signature taxonomy, the deliberately narrow normalization
pipeline, and the deliberately narrow `schema_check.rs` (structural
conformance only — no `$ref`, no `oneOf`/`anyOf`/`allOf`, no `format`
validators; see that file's header for the exact list) will all miss real
attacks a more thorough implementation would catch. Every one of these
scope boundaries is stated explicitly in the relevant source file's own
comments, not discovered by reading this document instead of the code.
This is why the capability gate, not detection coverage, is the section
above worth trusting.

## Reporting a gap

If you find tool output that should have triggered a state change and
didn't — or, more usefully, a way to get a genuinely dangerous action
approved when it shouldn't have been — that's a real finding. See
`SECURITY.md`.

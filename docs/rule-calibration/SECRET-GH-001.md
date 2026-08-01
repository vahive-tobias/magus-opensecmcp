# Calibration record: `SECRET-GH-001`

Why `entropy_gt: 4.4`, with the actual measurements behind it — so that
"why 4.4 and not 4.2" has an answer grounded in evidence six months from
now, not memory. Companion to `locked-rules.yaml`'s own inline notes on
this rule, with the full data those notes summarize.

## The actual justification — not "the midpoint of the gap"

`4.4` is numerically the midpoint between two values below, but that's a
description of where the number sits, not why it's correct. The real
justification is three separate requirements, each independently
checkable against the data:

1. **`4.4` excludes the highest verified benign example** — GitHub's own
   documented placeholder, measured at `4.231`.
2. **`4.4` stays below the lowest observed realistic token** — the
   weakest of ten real-random samples, measured at `4.613`.
3. **The documented placeholder still gets an explicit lexical exemption**
   (`exempt_if_contains: ["1234567890abcdef"]`), independent of the
   entropy check, *because* entropy alone was already known to be an
   insufficient margin for it — the same reasoning `SECRET-AWS-001`'s
   `EXAMPLE` exemption rests on.

The midpoint is a consequence of (1) and (2), not the reason for the
choice. If future corpus work finds a genuinely benign sample scoring
`4.45`, the correct response is to recalibrate against that new evidence
— not to defend `4.4` because it was once a midpoint. Requirements (1)
and (2) are what actually need to keep holding; the specific number is
just whatever currently satisfies them.

## Measurements

All values computed with the real `shannon_entropy` function in
`rules_engine.rs` (not reimplemented, not estimated), over the full
regex match span including the `ghp_`-style prefix — matching exactly
how `push_hit` calls it in production.

| Sample | Entropy (bits/char) | Role |
|---|---|---|
| 10 real-random tokens, 36–62 chars, 62-char alphabet | `4.613`, `4.692`, `4.722`, `4.784`, `4.803`, `4.803`, `4.853`, `4.853`, `4.953`, `5.111` | Lowest (`4.613`) sets the upper bound `4.4` must stay under |
| GitHub's own documented placeholder (`docs.github.com/en/rest/credentials/revoke`, repeating hex block) | `4.231` | Sets the lower bound `4.4` must stay over |
| Digit-cycle placeholder (`0123456789` repeated) | `3.641` | Confirms `exempt_if_contains` isn't doing all the work alone — this stays at `Flag` on entropy alone, correctly, with no exemption needed |
| All-same-character placeholder | `0.669` | Sanity floor |
| Sequential, non-repeating placeholder (`abcdefghijklmnopqrstuvwxyz0123456789AB`) | `5.249` | **Known limitation, not a calibration failure** — see below |

## Research: does GitHub publish an AWS-style canonical placeholder?

Checked directly against `docs.github.com`, not assumed. **No single
canonical value exists** — GitHub's docs scatter several different,
inconsistent example tokens across different pages
(`ghp_16C7e42F292c6912E7710c838347Ae178B4a`,
`ghp_123456789abcde`, `ghp_mygeneraltoken`, among others). The value used
for the exemption here — the repeating-hex-block token from
`docs.github.com/en/rest/credentials/revoke` — was chosen as the most
citable, primary-sourced example, not because it's uniquely canonical
the way AWS's `AKIAIOSFODNN7EXAMPLE` is.

## Known limitation: `shannon_entropy` is blind to sequence

Frequency-based Shannon entropy cannot distinguish "every character
appears once, in a meaningful order" from "every character appears once,
at random" — a string with no repeated characters caps out at exactly
`log2(length)` bits/char regardless of whether it's actually random. The
sequential sample above (`5.249`) scores *higher* than every one of the
ten real-random samples. No choice of `entropy_gt` fixes this — it's a
property of the metric, not a calibration problem, and no threshold
value in this document's table changes that fact.

**This is not new to `SECRET-GH-001`** — it already exists in
`SECRET-AWS-001`, in production: a 16-character suffix with no repeated
characters caps at `log2(16) = 4.0`, comfortably clearing that rule's
`3.5` threshold regardless of whether those 16 characters are actually
random. It surfaced here because this rule's calibration was measured
more carefully than the original `AWS-001` work, not because it's a new
risk introduced by this change.

Bounded severity: the failure mode is a false-positive escalation
(`flag → elevate`) for a sequential placeholder, not a missed detection.
`elevate` from a single signal still needs corroboration to reach
`Poisoned` under the current provenance semantics. A real fix needs a
second, order-sensitive signal alongside frequency entropy (e.g. longest
monotonic run length) — deliberately out of scope here; see
`PROJECT-STATUS-AND-ROADMAP.md`'s architectural debt section for the
standing entry.

## If this needs revisiting

Recalibrate against new measurements, not against preserving `4.4`
specifically. The two requirements above (`> highest verified benign`,
`< lowest observed real`) are what matter; if new evidence narrows or
closes that gap, that's a real finding worth acting on, not something to
paper over by keeping the existing number.

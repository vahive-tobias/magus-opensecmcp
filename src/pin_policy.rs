// src/pin_policy.rs
//
// Pure decision logic for SEC-03/OP-2: what to do with a discovery-time
// hash-pin comparison. Kept separate from main.rs's I/O (spawning
// downstream processes, printing) so "given this pin status and these
// flags, what happens" can be unit tested directly, without spinning up a
// real downstream connection (docs/specs/spec-sec03-hash-pin-enforcement.md).
//
// `validate_policy` has grown into the general SecurityPolicy-wide sanity
// check as later fixes landed (F3's `refuse_startup_on_tool_name_collision`,
// now F5's two timeout defaults below) — not pin-specific anymore in
// practice, even though the module name still is. Per-entry `tools:`/
// `downstream_servers:` timeout overrides are validated in registry.rs's
// `load_from_yaml` instead, not here — those live on YAML structs that
// module already owns parsing for, while this function's job stays "is
// SecurityPolicy internally self-consistent," the same scope it always had.

use crate::registry::SecurityPolicy;

/// The outcome of comparing a tool's freshly-computed definition hash
/// against whatever `config.yaml` has pinned for it, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    Matched,
    Mismatched { expected: String, actual: String },
    NotYetPinned,
}

impl PinStatus {
    /// `pinned` is the `pinned_definition_hash_hex` from config, if any.
    /// `actual_hex` is the hash just computed from what the server actually
    /// returned. Comparison is case-insensitive, matching the hex-encoding
    /// comparison main.rs already used before this module existed.
    pub fn from_pin(pinned: Option<&str>, actual_hex: &str) -> Self {
        match pinned {
            Some(p) if p.eq_ignore_ascii_case(actual_hex) => PinStatus::Matched,
            Some(p) => PinStatus::Mismatched {
                expected: p.to_string(),
                actual: actual_hex.to_string(),
            },
            None => PinStatus::NotYetPinned,
        }
    }
}

/// Whether a single tool should be quarantined, given its pin status and
/// whether `strict_schema_pinning` is on. `Matched` and `NotYetPinned` NEVER
/// quarantine, regardless of `strict` — "no pin set yet" must never be
/// treated as a mismatch trigger, at any strictness level, or day-one usage
/// of a newly-added server breaks by default.
pub fn decide_quarantine(status: &PinStatus, strict: bool) -> bool {
    matches!(status, PinStatus::Mismatched { .. }) && strict
}

/// Validates `security_policy`'s own internal consistency. Called once,
/// right after config load and before discovery runs at all — there's no
/// reason to spawn downstream servers and do discovery work just to refuse
/// over a config error. `refuse_startup_on_pin_mismatch: true` only makes
/// sense as a stronger opt-in layered on top of `strict_schema_pinning`;
/// setting it without strict mode is a nonsensical configuration, not a
/// state that should silently do nothing or silently imply strict mode.
///
/// `refuse_startup_on_tool_name_collision` deliberately gets NO equivalent
/// check here — confirmed by re-deriving the reasoning, not assumed from
/// the flag's similar name/shape to `refuse_startup_on_pin_mismatch`:
/// quarantine has a real warn-only middle tier (`strict_schema_pinning:
/// false` still runs the mismatched tool, just without hash-pin
/// enforcement), so "escalate past strict mode without strict mode set"
/// is a genuine misconfiguration worth rejecting. Name-collision exclusion
/// has no such middle tier — two tools genuinely cannot both answer to
/// one bare name over a wire protocol with no server_id field, so
/// exclusion is unconditional, not gated behind any flag. There is
/// nothing for `refuse_startup_on_tool_name_collision` to be "layered on
/// top of" that isn't already always on, so no prerequisite check applies.
pub fn validate_policy(policy: &SecurityPolicy) -> Result<(), String> {
    if policy.refuse_startup_on_pin_mismatch && !policy.strict_schema_pinning {
        return Err(
            "security_policy.refuse_startup_on_pin_mismatch: true requires \
             security_policy.strict_schema_pinning: true. \
             refuse_startup_on_pin_mismatch is a stronger opt-in layered on top of \
             strict per-tool quarantine, not a standalone flag — set both, or neither."
                .to_string(),
        );
    }

    // F5 (see docs/specs/Adversarial Review magus-opensecmcp.md): a zero,
    // negative, NaN, or infinite global timeout default is refused
    // outright, not silently clamped or treated as "no timeout" — a
    // supported "wait forever" configuration would just resurrect the
    // finding this field exists to close. registry.rs's own
    // `validate_timeout_value` does the identical check for per-entry
    // `timeout_seconds`/`discovery_timeout_seconds` overrides; duplicated
    // here rather than shared across modules for the same reason as
    // everywhere else in this codebase a two-line check gets repeated
    // instead of abstracted — it's small enough that a shared helper
    // would cost more (a cross-module dependency for a five-line
    // function) than it saves.
    if !policy.default_tool_timeout_seconds.is_finite() || policy.default_tool_timeout_seconds <= 0.0 {
        return Err(format!(
            "security_policy.default_tool_timeout_seconds must be a positive, finite number of seconds \
             ({} is not) — a zero, negative, NaN, or infinite timeout would mean \"wait forever\" (or crash), \
             exactly the unbounded-hang behavior this field exists to prevent.",
            policy.default_tool_timeout_seconds
        ));
    }
    if !policy.default_discovery_timeout_seconds.is_finite() || policy.default_discovery_timeout_seconds <= 0.0 {
        return Err(format!(
            "security_policy.default_discovery_timeout_seconds must be a positive, finite number of seconds \
             ({} is not) — same reasoning as default_tool_timeout_seconds above.",
            policy.default_discovery_timeout_seconds
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(strict: bool, refuse: bool) -> SecurityPolicy {
        SecurityPolicy {
            strict_schema_pinning: strict,
            refuse_startup_on_pin_mismatch: refuse,
            ..Default::default()
        }
    }

    // ---- PinStatus::from_pin ----

    #[test]
    fn from_pin_none_is_not_yet_pinned() {
        assert_eq!(PinStatus::from_pin(None, "abc123"), PinStatus::NotYetPinned);
    }

    #[test]
    fn from_pin_matching_is_matched() {
        assert_eq!(PinStatus::from_pin(Some("abc123"), "abc123"), PinStatus::Matched);
    }

    #[test]
    fn from_pin_matching_is_case_insensitive() {
        assert_eq!(PinStatus::from_pin(Some("ABC123"), "abc123"), PinStatus::Matched);
    }

    #[test]
    fn from_pin_differing_is_mismatched_with_both_values_preserved() {
        let status = PinStatus::from_pin(Some("expected-hash"), "actual-hash");
        assert_eq!(
            status,
            PinStatus::Mismatched {
                expected: "expected-hash".to_string(),
                actual: "actual-hash".to_string(),
            }
        );
    }

    // ---- decide_quarantine: the core "no pin yet != mismatch" guarantee ----

    #[test]
    fn matched_never_quarantines_regardless_of_strict() {
        assert!(!decide_quarantine(&PinStatus::Matched, true));
        assert!(!decide_quarantine(&PinStatus::Matched, false));
    }

    #[test]
    fn not_yet_pinned_never_quarantines_regardless_of_strict() {
        assert!(!decide_quarantine(&PinStatus::NotYetPinned, true));
        assert!(
            !decide_quarantine(&PinStatus::NotYetPinned, false),
            "day-one usage of a newly-added, unpinned server must never quarantine"
        );
    }

    #[test]
    fn mismatched_quarantines_only_when_strict() {
        let mismatched = PinStatus::Mismatched {
            expected: "e".to_string(),
            actual: "a".to_string(),
        };
        assert!(decide_quarantine(&mismatched, true));
        assert!(!decide_quarantine(&mismatched, false));
    }

    // ---- validate_policy ----

    #[test]
    fn refuse_without_strict_is_a_config_error() {
        assert!(validate_policy(&policy(false, true)).is_err());
    }

    #[test]
    fn refuse_with_strict_is_valid() {
        assert!(validate_policy(&policy(true, true)).is_ok());
    }

    #[test]
    fn neither_flag_is_valid() {
        assert!(validate_policy(&policy(false, false)).is_ok());
    }

    #[test]
    fn strict_without_refuse_is_valid() {
        assert!(validate_policy(&policy(true, false)).is_ok());
    }

    // ---- validate_policy: F5 timeout defaults ----

    #[test]
    fn default_policy_has_sane_nonzero_timeouts_and_is_valid() {
        // Guards the exact landmine this Default impl exists to avoid: if
        // SecurityPolicy::default() ever regressed back to a derived
        // (zero-valued) Default, every test in this module using
        // ..Default::default() would start failing this same check.
        let p = SecurityPolicy::default();
        assert!(p.default_tool_timeout_seconds > 0.0);
        assert!(p.default_discovery_timeout_seconds > 0.0);
        assert!(validate_policy(&p).is_ok());
    }

    #[test]
    fn zero_default_tool_timeout_is_a_config_error() {
        let mut p = policy(false, false);
        p.default_tool_timeout_seconds = 0.0;
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn zero_default_discovery_timeout_is_a_config_error() {
        let mut p = policy(false, false);
        p.default_discovery_timeout_seconds = 0.0;
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn negative_or_non_finite_default_timeout_is_a_config_error() {
        let mut negative = policy(false, false);
        negative.default_tool_timeout_seconds = -1.0;
        assert!(validate_policy(&negative).is_err());

        let mut nan = policy(false, false);
        nan.default_discovery_timeout_seconds = f64::NAN;
        assert!(validate_policy(&nan).is_err());

        let mut infinite = policy(false, false);
        infinite.default_tool_timeout_seconds = f64::INFINITY;
        assert!(validate_policy(&infinite).is_err());
    }
}

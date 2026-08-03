// src/pin_policy.rs
//
// Pure decision logic for SEC-03/OP-2: what to do with a discovery-time
// hash-pin comparison. Kept separate from main.rs's I/O (spawning
// downstream processes, printing) so "given this pin status and these
// flags, what happens" can be unit tested directly, without spinning up a
// real downstream connection. See
// docs/specs/spec-sec03-hash-pin-enforcement.md for the full spec this
// implements.

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
}

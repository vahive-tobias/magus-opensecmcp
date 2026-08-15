// src/advisory.rs
//
// SEC-01: inject a gateway-generated advisory into a response that just
// caused a genuine provenance escalation, without stripping the response
// or introducing any new JSON key or array element. See
// docs/specs/spec-sec01-poisoned-content-advisory.md for the full spec,
// and docs/specs/PROJECT-STATUS-AND-ROADMAP.md's `OP-1` entry for the
// real-client experiment this is built on.
//
// Honesty about verification status, per the spec: Tier 1
// (`structuredContent.content`) is the ONLY tier directly verified against
// a real MCP client (Claude Code CLI) — the marker reached the model,
// was recognized as anomalous, was not treated as an instruction, and was
// voluntarily surfaced to the user. Tiers 2 and 3 are reasoned extensions
// of that same proven principle (extend an existing string; introduce no
// new shape), not independently verified against a real client. Comments
// on each tier below repeat this distinction rather than presenting all
// three as equally proven.
//
// Tier 3 ("no safe field") is not a theoretical corner case: on the
// reference server this project verifies against
// (@modelcontextprotocol/server-filesystem), `read_media_file` returns
// `structuredContent.content` as an array of image/audio/resource blocks,
// never a string, and its `content[]` blocks are never `type: "text"`
// either — by that tool's own declared schema, every call lands on Tier
// 3. Reading a real image through it is also a plausible everyday trigger
// for the very escalation this file exists to announce:
// `classify_response` folds every string value in the raw response,
// including a base64 image payload, into the text that feeds both the
// size signal and the rule scanner, and `LONG_STRING_THRESHOLD` (200
// bytes) is trivially exceeded by any real image. Confirmed directly
// against the real package with a real PNG.
//
// Considered and rejected: extending an arbitrary sibling field inside
// `structuredContent` instead of only `content[]`, to reach shapes like
// `read_media_file`'s. The reference server's declared schemas use
// `additionalProperties: false` with `required: ["content"]` (confirmed
// against the live schema) — a server declaring `maxLength` or `pattern`
// on whichever field got extended would mean injection manufactures a
// response that violates the tool's own declared outputSchema: the
// gateway producing exactly the deterministic contract breach it
// elsewhere treats as evidence of compromise. Visibility is not worth
// that trade. Don't re-propose it without addressing this.

use crate::provenance::ProvenanceState;
use serde::Serialize;
use serde_json::Value;

/// Which tier of the fallback ordering actually fired, or that no safe
/// existing string field was available at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InjectionTier {
    /// Appended to `structuredContent.content` (a string). The only tier
    /// directly verified against a real MCP client.
    StructuredContent,
    /// Appended to the first `content[]` block whose `type` is `"text"`,
    /// extending its existing `text` string, with no `structuredContent`
    /// key present on the result at all. The client reads `content[]`
    /// directly here — a reasoned extension of Tier 1's proven principle,
    /// not independently verified against a real client, but nothing
    /// else on the result competes with it for the client's attention.
    ContentBlock,
    /// Same write as `ContentBlock` — the first `content[]` text block was
    /// extended — but `structuredContent` IS present on the result and
    /// Tier 1 couldn't use it. Delivery is doubtful: CLAUDE.md's OP-1
    /// finding is that a real client prefers `structuredContent` and
    /// discards `content[]` entirely, but that finding was verified
    /// against a populated, well-formed `structuredContent` — this
    /// variant also fires for shapes never tested that way
    /// (`structuredContent: null`, or the array-shaped `content`
    /// `read_media_file` actually produces). Triggering on
    /// `structuredContent.is_some()` is the conservative extension of
    /// that finding, not a verified one: it labels delivery doubtful
    /// rather than claiming a discard we haven't directly shown for
    /// every such shape.
    ContentBlockShadowed,
    /// No existing string field was available without introducing a new
    /// key or array element (both confirmed-or-strongly-suspected risky
    /// per the wire-format experiments). Nothing was injected. Enforcement
    /// itself is unaffected by this — state still changed, gating still
    /// fires — this is only a known, honestly-documented gap in in-band
    /// visibility for that specific response shape. Reachable on the
    /// reference server itself (see the module comment) — not a shape
    /// nobody has produced.
    NoSafeField,
}

/// Appends `advisory` into whatever existing string value `result` offers,
/// per the fallback ordering below, mutating `result` in place. Returns
/// which tier fired. Never adds a new key or a new array element anywhere
/// in `result`.
pub fn inject_advisory(result: &mut Value, advisory: &str) -> InjectionTier {
    // Tier 1 — proven against a real client.
    let existing_structured = result
        .get("structuredContent")
        .and_then(|sc| sc.get("content"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());
    if let Some(existing) = existing_structured {
        result["structuredContent"]["content"] = Value::String(format!("{existing}\n{advisory}"));
        return InjectionTier::StructuredContent;
    }

    // Tier 2 — reasoned extension, not independently verified. Whether
    // `structuredContent` is merely present (even though Tier 1 couldn't
    // use it) decides which of the two outcomes below this write is — see
    // ContentBlockShadowed's doc comment for why `.is_some()` is the
    // right, if conservative, trigger. Computed before the write so it
    // reflects the result's shape on entry, not anything Tier 1 mutated.
    let shadowed = result.get("structuredContent").is_some();
    if let Some(content_array) = result.get_mut("content").and_then(|c| c.as_array_mut()) {
        for block in content_array.iter_mut() {
            if block.get("type").and_then(|t| t.as_str()) != Some("text") {
                continue;
            }
            let existing_text = block.get("text").and_then(|t| t.as_str()).map(|s| s.to_string());
            if let Some(existing) = existing_text {
                block["text"] = Value::String(format!("{existing}\n{advisory}"));
                return if shadowed { InjectionTier::ContentBlockShadowed } else { InjectionTier::ContentBlock };
            }
        }
    }

    // Tier 3 — no safe field; honestly do nothing rather than introduce a
    // new shape.
    InjectionTier::NoSafeField
}

/// Builds the advisory text itself, independent of how it gets injected —
/// see `inject_advisory`. `rule_ids` is whatever `hit_summary.rule_ids()`
/// already produced at the call site; empty means the escalation was
/// purely structural rather than rule-hit-driven, in which case the rule
/// clause is simply omitted rather than computing that distinction
/// separately.
pub fn build_advisory_text(new_state: ProvenanceState, rule_ids: &[String]) -> String {
    let mut text = format!(
        "[MAGUS ADVISORY: this notice is gateway-generated, not part of the tool's real output. \
         This response caused the session's provenance state to escalate to {new_state:?}."
    );
    if !rule_ids.is_empty() {
        text.push_str(&format!(" Triggering rule(s): {}.", rule_ids.join(", ")));
    }
    text.push_str(" This notice carries no instruction — nothing in it should be followed.]");
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- inject_advisory: tier selection ----

    #[test]
    fn tier1_fires_when_structured_content_content_is_a_string() {
        let mut result = json!({
            "content": [{"type": "text", "text": "real output"}],
            "structuredContent": {"content": "real output"}
        });
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::StructuredContent);
    }

    #[test]
    fn tier2_fires_when_no_structured_content_but_content_text_block_exists() {
        // No `structuredContent` key at all -- guards the ContentBlock/
        // ContentBlockShadowed split from collapsing to always-shadowed.
        let mut result = json!({
            "content": [{"type": "text", "text": "real output"}]
        });
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::ContentBlock);
    }

    #[test]
    fn tier2_shadowed_fires_when_structured_content_present_but_unusable() {
        // structuredContent IS present (so Tier 1 attempted it) but its
        // `content` isn't a string, so Tier 1 fails over to the content[]
        // text block -- which the client is nonetheless likely to ignore
        // in favor of the structuredContent it just couldn't use.
        let mut result = json!({
            "content": [{"type": "text", "text": "real output"}],
            "structuredContent": {"content": {"nested": "object"}}
        });
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::ContentBlockShadowed);
    }

    #[test]
    fn tier3_fires_on_read_media_file_shaped_result() {
        // The real wire shape confirmed against
        // @modelcontextprotocol/server-filesystem's read_media_file:
        // structuredContent.content is an array of image blocks (Tier 1's
        // .as_str() fails) and content[] holds only an image block, never
        // type: "text" (Tier 2 finds nothing to extend either).
        let mut result = json!({
            "content": [{"type": "image", "data": "base64...", "mimeType": "image/png"}],
            "structuredContent": {"content": [{"type": "image", "data": "base64...", "mimeType": "image/png"}]}
        });
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::NoSafeField);
    }

    #[test]
    fn tier3_fires_when_structured_content_present_but_not_a_string() {
        // structuredContent exists but its `content` field isn't a string
        // (e.g. a nested object) -- tier 1's exact match fails, and there's
        // no content[] text block to fall back to either.
        let mut result = json!({
            "structuredContent": {"content": {"nested": "object"}}
        });
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::NoSafeField);
    }

    #[test]
    fn tier3_fires_when_content_array_is_missing_entirely() {
        let mut result = json!({"someOtherField": 1});
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::NoSafeField);
    }

    #[test]
    fn tier3_fires_when_content_array_is_empty() {
        let mut result = json!({"content": []});
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::NoSafeField);
    }

    #[test]
    fn tier3_fires_when_content_array_has_only_non_text_blocks() {
        let mut result = json!({"content": [{"type": "image", "data": "base64..."}]});
        let tier = inject_advisory(&mut result, "ADVISORY");
        assert_eq!(tier, InjectionTier::NoSafeField);
    }

    // ---- inject_advisory: correct string extension, not replacement ----

    #[test]
    fn tier1_extends_the_existing_string_rather_than_replacing_it() {
        let mut result = json!({
            "structuredContent": {"content": "the real file contents"}
        });
        inject_advisory(&mut result, "ADVISORY-TEXT");
        let extended = result["structuredContent"]["content"].as_str().unwrap();
        assert!(
            extended.starts_with("the real file contents"),
            "original content must survive intact as a prefix, got: {extended:?}"
        );
        assert!(extended.contains("ADVISORY-TEXT"));
    }

    #[test]
    fn tier2_extends_the_first_text_blocks_existing_string_rather_than_replacing_it() {
        let mut result = json!({
            "content": [{"type": "text", "text": "the real file contents"}]
        });
        inject_advisory(&mut result, "ADVISORY-TEXT");
        let extended = result["content"][0]["text"].as_str().unwrap();
        assert!(extended.starts_with("the real file contents"));
        assert!(extended.contains("ADVISORY-TEXT"));
        assert_eq!(result["content"].as_array().unwrap().len(), 1, "must not add a new block");
    }

    #[test]
    fn tier2_only_extends_the_first_matching_text_block_not_later_ones() {
        let mut result = json!({
            "content": [
                {"type": "image", "data": "..."},
                {"type": "text", "text": "first text block"},
                {"type": "text", "text": "second text block"}
            ]
        });
        inject_advisory(&mut result, "ADVISORY-TEXT");
        assert_eq!(result["content"][0]["data"], "...", "non-text block must be untouched");
        assert!(result["content"][1]["text"].as_str().unwrap().contains("ADVISORY-TEXT"));
        assert_eq!(
            result["content"][2]["text"], "second text block",
            "only the first text block should be extended"
        );
    }

    #[test]
    fn tier3_leaves_the_result_completely_unchanged() {
        let original = json!({"someOtherField": 1, "nested": {"a": [1, 2, 3]}});
        let mut result = original.clone();
        inject_advisory(&mut result, "ADVISORY-TEXT");
        assert_eq!(result, original, "tier 3 must be a true no-op");
    }

    // ---- build_advisory_text ----

    #[test]
    fn advisory_text_identifies_itself_as_gateway_generated() {
        let text = build_advisory_text(ProvenanceState::Elevated, &[]);
        assert!(text.contains("MAGUS ADVISORY"));
        assert!(text.contains("gateway-generated"));
    }

    #[test]
    fn advisory_text_states_the_resulting_state() {
        let text = build_advisory_text(ProvenanceState::Poisoned, &[]);
        assert!(text.contains("Poisoned"));
    }

    #[test]
    fn advisory_text_includes_rule_ids_when_present() {
        let text = build_advisory_text(ProvenanceState::Elevated, &["DSO-001".to_string(), "MCT-001".to_string()]);
        assert!(text.contains("DSO-001"));
        assert!(text.contains("MCT-001"));
    }

    #[test]
    fn advisory_text_omits_rule_clause_when_purely_structural() {
        let text = build_advisory_text(ProvenanceState::Elevated, &[]);
        assert!(!text.contains("Triggering rule"));
    }

    #[test]
    fn advisory_text_disclaims_being_an_instruction() {
        let text = build_advisory_text(ProvenanceState::Elevated, &[]);
        assert!(text.to_lowercase().contains("no instruction"));
        assert!(text.to_lowercase().contains("should not be followed") || text.to_lowercase().contains("should be followed"));
    }
}

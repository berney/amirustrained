use super::Renderer;
use super::style::{self, ColorSupport};
use crate::pipeline::Event;

/// Bulk JSON renderer (spec §7 `json`): the whole report is the output, so
/// streaming events are dropped and the single pretty document lands on
/// `Summary`. Colour is a post-render tokeniser over the pretty bytes
/// ([`highlight`]) — never a second serializer, and the machine stream
/// counterpart (`jsonl`) stays RAW by contract: it is a line protocol for
/// `jq`/log shippers, so escape codes there would break every consumer,
/// while pretty JSON is the human-facing document the user asked to paint.
pub struct Json {
    pub color: ColorSupport,
}

impl Renderer for Json {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        // One document, one write: `to_string_pretty` renders the whole report
        // in memory, so no partial/invalid JSON can reach the consumer even if
        // the write is interrupted. Serde errors fold into IO (exit 2), the
        // same contract the other renderers use.
        if let Event::Summary { report, .. } = ev {
            let doc = serde_json::to_string_pretty(&**report).map_err(std::io::Error::other)?;
            let mut s = highlight(&doc, self.color);
            s.push('\n');
            w.write_all(s.as_bytes())?;
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

/// Post-render titanium tokeniser over `serde_json::to_string_pretty` output:
/// keys electricBlue, strings titaniumGold, numbers warningAmber, bool/null
/// readoutGreen, structural punctuation dimAluminum ([`style`] table). With
/// [`ColorSupport::Off`] it is the identity — the byte-identical piped
/// contract every cli/snapshot test relies on. Only pretty JSON goes through
/// here; `jsonl` emits raw lines (see [`Json`]'s doc).
pub fn highlight(src: &str, color: ColorSupport) -> String {
    if color == ColorSupport::Off {
        return src.to_owned();
    }
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len() + src.len() / 4);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let end = string_end(b, i);
                let token = &src[i..end];
                // A string is a key iff the next non-space byte is `:`.
                let is_key = src[end..].bytes().find(|c| !c.is_ascii_whitespace()) == Some(b':');
                let hex = if is_key {
                    style::ELECTRIC_BLUE
                } else {
                    style::TITANIUM_GOLD
                };
                out.push_str(&color.fg(hex, token));
                i = end;
            }
            b'{' | b'}' | b'[' | b']' | b',' | b':' => {
                out.push_str(&color.fg(style::DIM_ALUMINUM, &src[i..i + 1]));
                i += 1;
            }
            c if c == b'-' || c.is_ascii_digit() => {
                let mut j = i + 1;
                while j < b.len() && matches!(b[j], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    j += 1;
                }
                out.push_str(&color.fg(style::WARNING_AMBER, &src[i..j]));
                i = j;
            }
            b't' | b'f' | b'n' => {
                // serde_json emits exactly true/false/null unquoted; the
                // fallback keeps the scanner total for foreign input.
                match ["true", "false", "null"]
                    .iter()
                    .find(|w| src[i..].starts_with(**w))
                {
                    Some(w) => {
                        out.push_str(&color.fg(style::READOUT_GREEN, w));
                        i += w.len();
                    }
                    None => {
                        out.push(b[i] as char);
                        i += 1;
                    }
                }
            }
            _ => {
                // Outside strings only ASCII whitespace occurs in serde
                // output, but stay UTF-8-total: advance one whole char.
                let end = i + src[i..].chars().next().map_or(1, |c| c.len_utf8());
                out.push_str(&src[i..end]);
                i = end;
            }
        }
    }
    out
}

/// Index just past the closing quote of the string starting at `start`,
/// honouring `\"` (and `\\`) escapes.
fn string_end(b: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Candidate, Fact, Finding, ProbeOutcome, Report, Rule, RuntimeKind, ScanMeta, Severity,
        Verdict,
    };

    static RULE: Rule = Rule {
        id: "AMR-098",
        slug: "json-render-shape",
        severity: Severity::High,
        summary: "s",
        why: "w",
        remediation: "r",
        references: &["https://example.test/doc"],
        requires_root: false,
        container_only: false,
        check: |_| Some(vec![]),
    };

    /// Fixture mirroring spec §7: scan complete, high-confidence verdict with
    /// one alternative, one finding carrying evidence, two probe outcomes.
    fn fixture_report() -> Report {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.verdict = Some(Verdict {
            runtime: RuntimeKind::Podman,
            variant: None,
            confidence: "high".into(),
            alternatives: vec![Candidate {
                runtime: RuntimeKind::Docker,
                score: 0.2,
            }],
            evidence: vec!["cgroup: podman slice".into()],
        });
        r.push_probe(ProbeOutcome::empty("namespaces"));
        r.push_probe(ProbeOutcome::empty("sockets"));
        r.findings = vec![Finding::new(
            &RULE,
            vec![Fact::ok(
                "sockets",
                "found",
                serde_json::json!(true),
                "/run/podman/podman.sock".into(),
            )],
        )];
        r.compute_counts();
        r
    }

    fn render(r: Report) -> String {
        let complete = r.scan.complete;
        let mut buf = vec![];
        Json {
            color: ColorSupport::Off,
        }
        .on_event(
            &mut buf,
            &Event::Summary {
                verdict: r.verdict.clone(),
                findings: r.findings.clone(),
                counts: r.counts.clone(),
                complete,
                report: Box::new(r),
            },
        )
        .unwrap();
        Json {
            color: ColorSupport::Off,
        }
        .finish(&mut buf)
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn json_full_report_shape() {
        let out = render(fixture_report());
        assert!(out.ends_with('\n'), "pretty JSON must end with a newline");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "schemaVersion",
                "tool",
                "scan",
                "verdict",
                "probes",
                "findings",
                "counts"
            ]
        );
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["tool"]["name"], "amirustrained");
        assert_eq!(v["scan"]["complete"], true);
        // Confidence is the report-schema string ladder, not a number.
        assert_eq!(v["verdict"]["confidence"], "high");
        // serde emits struct field order (preserve_order), so this pins the
        // spec §7 finding layout: evidence before remediation.
        let fkeys: Vec<&str> = v["findings"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fkeys,
            [
                "rule",
                "severity",
                "summary",
                "why",
                "evidence",
                "remediation",
                "references"
            ]
        );
        assert_eq!(v["findings"][0]["evidence"].as_array().unwrap().len(), 1);
        assert_eq!(v["probes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_ignores_non_summary() {
        let mut buf = vec![];
        let mut r = Json {
            color: ColorSupport::Off,
        };
        r.on_event(
            &mut buf,
            &Event::Meta {
                tool: fixture_report().tool.clone(),
                scan: ScanMeta::stub(),
            },
        )
        .unwrap();
        r.on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap")))
            .unwrap();
        r.finish(&mut buf).unwrap();
        assert!(
            buf.is_empty(),
            "bulk JSON must buffer nothing before Summary"
        );
    }

    #[test]
    fn json_counts_match_finding_severity_tally() {
        let mut r = fixture_report();
        r.findings.push(Finding::new(
            &RULE,
            vec![Fact::ok("p", "k", serde_json::json!(1), "src".into())],
        ));
        // Second finding demoted to Info so the tally is not single-severity.
        r.findings[1].severity = Severity::Info;
        r.compute_counts();
        let v: serde_json::Value = serde_json::from_str(&render(r)).unwrap();
        let tally = |sev: &str| {
            v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f["severity"] == sev)
                .count()
        };
        assert_eq!(v["counts"]["high"].as_u64().unwrap(), tally("high") as u64);
        assert_eq!(v["counts"]["info"].as_u64().unwrap(), tally("info") as u64);
        assert_eq!(
            v["counts"]["medium"].as_u64().unwrap(),
            tally("medium") as u64
        );
        let total = v["findings"].as_array().unwrap().len() as u64;
        let emitted: u64 = ["critical", "high", "medium", "low", "info"]
            .iter()
            .map(|k| v["counts"][k].as_u64().unwrap())
            .sum();
        assert_eq!(emitted, total, "counts must tally every finding");
    }

    /// Remove every `ESC[ … m` run so content bytes can be compared exactly.
    fn strip_sgr(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '\x1b' {
                out.push(c);
                continue;
            }
            if chars.peek() == Some(&'[') {
                chars.next();
                for t in chars.by_ref() {
                    if t == 'm' {
                        break;
                    }
                }
            }
        }
        out
    }

    #[test]
    fn highlight_is_identity_when_off() {
        // The piped contract: off means byte-identical, not merely parseable.
        let doc = serde_json::to_string_pretty(&serde_json::json!(
            {"a": 1, "s": "x", "b": true, "n": null}
        ))
        .unwrap();
        assert_eq!(highlight(&doc, ColorSupport::Off), doc);
    }

    #[test]
    fn highlight_paints_each_token_class() {
        let doc = serde_json::to_string_pretty(&fixture_report()).unwrap();
        let on = highlight(&doc, ColorSupport::TrueColor);
        assert!(on.contains(&style::fg(style::ELECTRIC_BLUE)), "keys blue");
        assert!(
            on.contains(&style::fg(style::TITANIUM_GOLD)),
            "string values gold"
        );
        assert!(
            on.contains(&style::fg(style::WARNING_AMBER)),
            "numbers amber (schemaVersion)"
        );
        assert!(
            on.contains(&style::fg(style::READOUT_GREEN)),
            "bool/null green"
        );
        assert!(
            on.contains(&style::fg(style::DIM_ALUMINUM)),
            "punctuation dim"
        );
        // Colour never touches content bytes: stripping the SGR runs must
        // rebuild the exact unstyled document (escape-bearing strings included).
        assert_eq!(strip_sgr(&on), doc);
        // Highlighting is not re-applied to its own output twice-over: keys
        // still resolve blue once, and no nested wraps appear.
        assert!(!on.contains("\x1b[38;2;0;180;255m\x1b[38;2;0;180;255m"));
    }

    #[test]
    fn rendered_json_document_stays_valid_under_forced_colour() {
        // The highlighter is cosmetic: even painted, stripping SGR runs must
        // leave parseable pretty JSON for consumers that capture a tty.
        let mut buf = vec![];
        let r = fixture_report();
        let complete = r.scan.complete;
        Json {
            color: ColorSupport::TrueColor,
        }
        .on_event(
            &mut buf,
            &Event::Summary {
                verdict: r.verdict.clone(),
                findings: r.findings.clone(),
                counts: r.counts.clone(),
                complete,
                report: Box::new(r),
            },
        )
        .unwrap();
        let raw = String::from_utf8(buf).unwrap();
        serde_json::from_str::<serde_json::Value>(&strip_sgr(&raw))
            .expect("valid JSON after strip");
    }
}

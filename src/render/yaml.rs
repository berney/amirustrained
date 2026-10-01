//! YAML report renderer (spec §7 formats, user request 2026-10-02).
//!
//! Hand-rolled emitter over `serde_json::Value`: the YAML crates are out —
//! `serde_yaml` is unmaintained (RUSTSEC-2024-0326) and `serde_yml` carries
//! open soundness issues — while our report shape is just maps/seqs/scalars,
//! which the emitter below writes in fixed block style (2-space indent,
//! PyYAML dash alignment) well under the fallback threshold. Colour is
//! applied EMIT-TIME: every token is wrapped as it is written (keys
//! electricBlue — quoted keys included, the role outranks the quoting; plain
//! scalars and numbers warningAmber; bool/null readoutGreen; quoted strings
//! titaniumGold; dashes/colons dimAluminum), so no post-hoc YAML tokenizer
//! exists and the emitter choice stays independent of the palette.
//!
//! Loadability contract: piped (uncoloured) output is strict block YAML —
//! `python3 -c 'import yaml,sys; yaml.safe_load(sys.stdin)'` accepts every
//! document the renderer produces. Strings are quoted only when a plain
//! scalar could change meaning ([`needs_quotes`]): leading indicators, `": "`
//! or trailing colon, `" #"`, leading/trailing space, control characters
//! (multiline becomes a double-quoted `\n` escape), the empty string, and
//! YAML 1.1 reserved words / numeric-looking text (`true`, `yes`, `null`,
//! `~`, `1.5`, `0755`, `1:30`, …).

use super::Renderer;
use super::style::{self, ColorSupport};
use crate::pipeline::Event;
use serde_json::{Map, Value};

pub struct Yaml {
    pub color: ColorSupport,
}

impl Renderer for Yaml {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        // Bulk format like json/markdown: the complete document lands on
        // `Summary` (Serde errors fold into IO → exit 2, house contract).
        if let Event::Summary { report, .. } = ev {
            let v = serde_json::to_value(&**report).map_err(std::io::Error::other)?;
            emit_doc(w, &v, self.color)?;
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

fn pad(w: &mut dyn std::io::Write, indent: usize) -> std::io::Result<()> {
    w.write_all(&[b' '].repeat(indent))
}

/// Top level: a map/seq opens the document directly; a bare scalar stands on
/// its own line. (The report is always a non-empty map; the arms keep `emit`
/// total for any `Value`.)
fn emit_doc(w: &mut dyn std::io::Write, v: &Value, color: ColorSupport) -> std::io::Result<()> {
    match v {
        Value::Object(m) if !m.is_empty() => emit_map(w, m, 0, false, color),
        Value::Array(a) if !a.is_empty() => emit_seq(w, a, 0, color),
        other => {
            w.write_all(scalar(other, color).as_bytes())?;
            w.write_all(b"\n")
        }
    }
}

/// Block map. `skip_pad_first` starts the first key at the current column —
/// exactly where a sequence item placed the dash (`- key: …`).
fn emit_map(
    w: &mut dyn std::io::Write,
    m: &Map<String, Value>,
    indent: usize,
    skip_pad_first: bool,
    color: ColorSupport,
) -> std::io::Result<()> {
    for (i, (k, v)) in m.iter().enumerate() {
        if !(i == 0 && skip_pad_first) {
            pad(w, indent)?;
        }
        let key = if needs_quotes(k) {
            color.fg(style::ELECTRIC_BLUE, &quote(k))
        } else {
            color.fg(style::ELECTRIC_BLUE, k)
        };
        w.write_all(key.as_bytes())?;
        w.write_all(color.wrap(&style::fg(style::DIM_ALUMINUM), ":").as_bytes())?;
        match v {
            Value::Object(mm) if !mm.is_empty() => {
                w.write_all(b"\n")?;
                emit_map(w, mm, indent + 2, false, color)?;
            }
            Value::Array(aa) if !aa.is_empty() => {
                // PyYAML alignment: the dashes sit at the key's own column.
                w.write_all(b"\n")?;
                emit_seq(w, aa, indent, color)?;
            }
            Value::Object(_) => {
                w.write_all(format!(" {}\n", color.fg(style::DIM_ALUMINUM, "{}")).as_bytes())?
            }
            Value::Array(_) => {
                w.write_all(format!(" {}\n", color.fg(style::DIM_ALUMINUM, "[]")).as_bytes())?
            }
            s => w.write_all(format!(" {}\n", scalar(s, color)).as_bytes())?,
        }
    }
    Ok(())
}

fn emit_seq(
    w: &mut dyn std::io::Write,
    a: &[Value],
    indent: usize,
    color: ColorSupport,
) -> std::io::Result<()> {
    for item in a {
        pad(w, indent)?;
        w.write_all(color.wrap(&style::fg(style::DIM_ALUMINUM), "-").as_bytes())?;
        match item {
            Value::Object(m) if !m.is_empty() => {
                // First key rides the dash line; the rest align two columns
                // further, which is exactly where the cursor now stands.
                w.write_all(b" ")?;
                emit_map(w, m, indent + 2, true, color)?;
            }
            Value::Array(aa) if !aa.is_empty() => {
                w.write_all(b"\n")?;
                emit_seq(w, aa, indent + 2, color)?;
            }
            Value::Object(_) => {
                w.write_all(format!(" {}\n", color.fg(style::DIM_ALUMINUM, "{}")).as_bytes())?
            }
            Value::Array(_) => {
                w.write_all(format!(" {}\n", color.fg(style::DIM_ALUMINUM, "[]")).as_bytes())?
            }
            s => w.write_all(format!(" {}\n", scalar(s, color)).as_bytes())?,
        }
    }
    Ok(())
}

/// One scalar token, already colour-wrapped.
fn scalar(v: &Value, color: ColorSupport) -> String {
    match v {
        Value::Null => color.fg(style::READOUT_GREEN, "null"),
        Value::Bool(b) => color.fg(style::READOUT_GREEN, if *b { "true" } else { "false" }),
        Value::Number(n) => color.fg(style::WARNING_AMBER, &n.to_string()),
        Value::String(s) => {
            if needs_quotes(s) {
                color.fg(style::TITANIUM_GOLD, &quote(s))
            } else {
                color.fg(style::WARNING_AMBER, s)
            }
        }
        // Containers are laid out by emit_map/emit_seq; reaching here would
        // mean an empty node, which the callers inline as {} / [].
        Value::Object(_) => color.fg(style::DIM_ALUMINUM, "{}"),
        Value::Array(_) => color.fg(style::DIM_ALUMINUM, "[]"),
    }
}

/// Double-quoted scalar: escapes the JSON set plus YAML control characters;
/// printable non-ASCII (unicode) rides through raw, which block YAML and
/// PyYAML both accept.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // U+0085 NEL: raw is a line break to the YAML 1.1 reader and even
            // raw-in-quotes folds the value; the \U escape round-trips.
            '\u{85}' => out.push_str("\\U00000085"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// True when a plain (unquoted) scalar could re-parse as something else or
/// as invalid YAML — the ONLY reason to quote.
fn needs_quotes(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    // Leading indicators (and `~`, the YAML null glyph) never start a plain
    // scalar safely.
    if s.starts_with([
        '-', ' ', ':', '?', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%',
        '@', '`', '~',
    ]) {
        return true;
    }
    // Trailing space turns a plain scalar ambiguous; a trailing colon merges
    // with the mapping indicator.
    if s.ends_with([' ', ':']) {
        return true;
    }
    // `key: value` mapping noise and comment starts inside a value.
    if s.contains(": ") || s.contains(" #") {
        return true;
    }
    // Control characters (newline included) force the escaped form; U+0085
    // NEL too (YAML 1.1 line break to PyYAML, breaks plain scalars).
    if s.chars()
        .any(|c| (c as u32) < 0x20 || c as u32 == 0x7f || c == '\u{85}')
    {
        return true;
    }
    is_reserved_word(s) || looks_numeric(s)
}

/// YAML 1.1 / PyYAML resolve these to bool/null whatever the case.
fn is_reserved_word(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "null" | "~" | "true" | "false" | "yes" | "no" | "on" | "off" | "y" | "n"
    )
}

/// Anything a resolver would type as a number instead of a string.
fn looks_numeric(s: &str) -> bool {
    if s.parse::<f64>().is_ok() {
        return true; // ints, floats, inf/nan/e-notation
    }
    // Radix literals and YAML 1.1 sexagesimals (PyYAML reads `1:30` as 90).
    if s.starts_with("0x")
        || s.starts_with("0o")
        || s.starts_with("0b")
        || (s.contains(':') && s.bytes().all(|b| b.is_ascii_digit() || b == b':'))
    {
        return true;
    }
    // YAML 1.1 shapes Rust's f64 rejects but PyYAML resolves anyway:
    // dot-inf/dot-nan (any case), digit-separator ints (`1_000` -> 1000),
    // and ISO dates (`2026-10-02` -> datetime.date).
    match s.to_ascii_lowercase().as_str() {
        ".inf" | "-.inf" | "+.inf" | ".nan" | "-.nan" | "+.nan" => return true,
        _ => {}
    }
    if s.contains('_') && s.bytes().all(|b| b.is_ascii_digit() || b == b'_') {
        return true;
    }
    let b = s.as_bytes();
    s.len() >= 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emit_str(v: &Value, color: ColorSupport) -> String {
        let mut buf = vec![];
        emit_doc(&mut buf, v, color).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn block_layout_maps_seqs_and_empty_nodes() {
        let v = serde_json::json!({
            "schemaVersion": 1,
            "tool": { "name": "amirustrained", "version": "0.1.0" },
            "findings": [
                { "rule": "AMR-001", "evidence": [ { "key": "k", "value": true } ] },
            ],
            "emptySeq": [],
            "emptyMap": {},
            "nothing": null,
            "flag": false,
        });
        assert_eq!(
            emit_str(&v, ColorSupport::Off),
            "\
schemaVersion: 1
tool:
  name: amirustrained
  version: 0.1.0
findings:
- rule: AMR-001
  evidence:
  - key: k
    value: true
emptySeq: []
emptyMap: {}
nothing: null
flag: false
"
        );
    }

    #[test]
    fn escaping_edge_cases_quote_only_when_needed() {
        let cases: &[(&str, &str)] = &[
            // (input string, expected emitted scalar token)
            ("- leading dash", "\"- leading dash\""),
            ("colon: inside", "\"colon: inside\""),
            ("trailing colon:", "\"trailing colon:\""),
            ("multi\nline", "\"multi\\nline\""),
            // A `"` only quotes at the START; inside a plain scalar it is
            // literal text that PyYAML round-trips unchanged.
            ("with \"quotes\" in", "with \"quotes\" in"),
            ("\"leading quote", "\"\\\"leading quote\""),
            ("tab\there", "\"tab\\there\""),
            ("", "\"\""),
            ("# hash", "\"# hash\""),
            ("space # comment", "\"space # comment\""),
            ("padded ", "\"padded \""),
            ("true", "\"true\""),
            ("NO", "\"NO\""),
            ("null", "\"null\""),
            ("~", "\"~\""),
            ("1.5", "\"1.5\""),
            ("0755", "\"0755\""),
            ("1:30", "\"1:30\""),
            ("0xff", "\"0xff\""),
            // Safe strings stay plain (no quoting):
            ("AMR-001", "AMR-001"),
            ("1.2.3", "1.2.3"),
            ("scan/complete", "scan/complete"),
            ("ünïcøde wörks", "ünïcøde wörks"),
            ("drop `--privileged`", "drop `--privileged`"),
        ];
        for (input, want) in cases {
            let out = emit_str(&Value::String(input.to_string()), ColorSupport::Off);
            assert_eq!(out, format!("{want}\n"), "scalar for {input:?}");
        }
        // The multiline token carries no raw newline (single line output).
        let multi = emit_str(&Value::String("a\nb".into()), ColorSupport::Off);
        assert_eq!(multi.lines().count(), 1);
    }

    #[test]
    fn forced_colour_wraps_each_token_class() {
        let v = serde_json::json!({
            "key": "needs: quotes",
            "n": 42,
            "b": true,
            "z": null,
            "list": ["plain"],
        });
        let on = emit_str(&v, ColorSupport::TrueColor);
        assert!(
            on.contains(&format!(
                "{}key{}",
                style::fg(style::ELECTRIC_BLUE),
                style::RESET
            )),
            "key blue: {on}"
        );
        assert!(
            on.contains(&format!("{}:", style::fg(style::DIM_ALUMINUM))),
            "colon dim: {on}"
        );
        assert!(
            on.contains(&format!(
                "{}-{}",
                style::fg(style::DIM_ALUMINUM),
                style::RESET
            )),
            "dash dim: {on}"
        );
        assert!(on.contains("\"needs: quotes\""), "quoted present");
        assert!(
            on.contains(&style::fg(style::TITANIUM_GOLD)),
            "quoted string gold"
        );
        assert!(
            on.contains(&style::fg(style::WARNING_AMBER)),
            "plain/number amber"
        );
        assert!(
            on.contains(&style::fg(style::READOUT_GREEN)),
            "bool/null green"
        );
        // Off stays escape-free:
        assert!(!emit_str(&v, ColorSupport::Off).contains('\x1b'));
    }

    #[test]
    fn nel_is_escaped_never_emitted_raw() {
        // PyYAML (YAML 1.1) reads a raw U+0085 as a line break: a plain
        // scalar containing it makes the whole document unparseable.
        let v = serde_json::json!({ "a": "x\u{85}y" });
        assert_eq!(emit_str(&v, ColorSupport::Off), "a: \"x\\U00000085y\"\n");
    }

    #[test]
    fn yaml11_resolver_shapes_are_quoted() {
        // Shapes Rust's f64 parser rejects but PyYAML types anyway.
        for s in [
            "1_000",
            ".inf",
            "-.INF",
            ".nan",
            "2026-10-02",
            "2026-10-02T10:00:00Z",
        ] {
            let out = emit_str(&serde_json::json!({ "k": s }), ColorSupport::Off);
            assert!(
                out.contains(&format!("\"{s}\"")),
                "{s:?} must be quoted, got {out}"
            );
        }
        for s in [
            "kernel-5.14",
            "ext4",
            "2026-10",
            "1_0_or_text",
            "a-2026-10-02b",
        ] {
            let out = emit_str(&serde_json::json!({ "k": s }), ColorSupport::Off);
            assert!(!out.contains('"'), "{s:?} must stay plain, got {out}");
        }
    }

    #[test]
    fn renderer_emits_report_document_on_summary_only() {
        use crate::model::{Report, ScanMeta};
        let mut buf = vec![];
        let mut r = Yaml {
            color: ColorSupport::Off,
        };
        r.on_event(
            &mut buf,
            &Event::Probe(crate::model::ProbeOutcome::empty("x")),
        )
        .unwrap();
        assert!(buf.is_empty(), "bulk format buffers nothing pre-Summary");
        let report = Report::blank(ScanMeta::stub(), 1);
        let complete = report.scan.complete;
        r.on_event(
            &mut buf,
            &Event::Summary {
                verdict: None,
                findings: vec![],
                counts: Default::default(),
                complete,
                report: Box::new(report),
            },
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.starts_with("schemaVersion: 1\n"),
            "document head: {out}"
        );
        assert!(
            out.contains("findings: []\n"),
            "empty findings is []: {out}"
        );
        assert!(
            out.contains("verdict: null\n"),
            "absent verdict is null: {out}"
        );
    }
}

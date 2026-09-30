use super::Renderer;
use crate::model::ProbeOutcome; // keeps the probe-line signature explicit; tests use it via `use super::*`
use crate::pipeline::Event;

pub struct Jsonl;

/// Probe events get a fixed key order — `schemaVersion`, `type`, then the
/// outcome fields (`name`, `availability`, `facts`, `timedOut`; `signals` is
/// `#[serde(skip)]`). Index-assigning the tags onto `to_value(outcome)` would
/// place them by the map's own ordering, so the header keys are inserted first.
fn probe_line(o: &ProbeOutcome) -> serde_json::Result<serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("schemaVersion".into(), serde_json::json!(1));
    m.insert("type".into(), serde_json::json!("probe"));
    let outcome = serde_json::to_value(o)?;
    // Invariant: `ProbeOutcome` is a struct, so serde always emits an object.
    // Anything else would silently drop every field but the header keys.
    debug_assert!(
        matches!(outcome, serde_json::Value::Object(_)),
        "probe outcome must serialize as an object, got {outcome}"
    );
    m.extend(outcome.as_object().cloned().unwrap_or_default());
    Ok(serde_json::Value::Object(m))
}

impl Renderer for Jsonl {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        // `#[serde(flatten)]` needs an inner tagged struct per variant; build lines
        // with serde_json directly to keep control of field order (the `json!`
        // literals below keep their written order via `preserve_order`).
        let line = match ev {
            Event::Meta { tool, scan } => serde_json::json!(
                { "schemaVersion": 1, "type": "meta", "tool": tool, "scan": scan }),
            Event::Probe(o) => probe_line(o).map_err(std::io::Error::other)?,
            Event::Summary {
                verdict,
                findings,
                counts,
                complete,
            } => serde_json::json!(
                { "schemaVersion": 1, "type": "summary", "verdict": verdict,
                  "findings": findings, "counts": counts, "complete": complete }),
        };
        let mut s = serde_json::to_string(&line).map_err(std::io::Error::other)?;
        s.push('\n');
        w.write_all(s.as_bytes())?;
        w.flush() // streaming guarantee: consumer sees each probe the moment it lands
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ScanMeta, Tool};
    use crate::pipeline::Event;
    #[test]
    fn one_object_per_line_with_type_and_schema() {
        let mut buf = vec![];
        let mut r = Jsonl;
        r.on_event(
            &mut buf,
            &Event::Meta {
                tool: Tool {
                    name: "amirustrained".into(),
                    version: "0.1.0".into(),
                },
                scan: ScanMeta::stub(),
            },
        )
        .unwrap();
        r.on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap")))
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with(r#"{"schemaVersion":1,"type":"meta""#));
        assert!(lines[1].contains(r#""type":"probe","name":"uidmap""#));
    }
}

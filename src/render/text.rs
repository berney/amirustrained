use super::Renderer;
use crate::pipeline::Event;

#[cfg(test)]
use crate::model::{Counts, ProbeOutcome, Report, ScanMeta}; // referenced by tests through `use super::*`

pub struct Text {
    pub verbose: bool,
}

impl Renderer for Text {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        match ev {
            Event::Meta { tool, scan } if self.verbose => writeln!(
                w,
                "{} {} scanning pid {} (uid {})",
                tool.name, tool.version, scan.target_pid, scan.uid
            )?,
            // Probe status lines are always on (the minimal-text contract);
            // `verbose` only adds the Meta header above.
            Event::Probe(o) => writeln!(
                w,
                "probe {}: {}",
                o.name,
                match &o.availability {
                    crate::model::Availability::Ok => "ok".into(),
                    crate::model::Availability::Degraded(d) => format!("degraded: {d}"),
                    crate::model::Availability::Unavailable(d) => format!("unavailable: {d}"),
                }
            )?,
            Event::Summary {
                counts, complete, ..
            } => writeln!(
                w,
                "scan complete{}: {} findings (c{} h{} m{} l{} i{})",
                if *complete { "" } else { " INCOMPLETE" },
                counts.critical + counts.high + counts.medium + counts.low + counts.info,
                counts.critical,
                counts.high,
                counts.medium,
                counts.low,
                counts.info
            )?,
            _ => {}
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn minimal_text_emits_probe_lines_and_summary() {
        let mut buf = vec![];
        let mut r = Text { verbose: false };
        r.on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap")))
            .unwrap();
        r.on_event(
            &mut buf,
            &Event::Summary {
                verdict: None,
                findings: vec![],
                counts: Counts::default(),
                complete: true,
                report: Box::new(Report::blank(ScanMeta::stub(), 1)),
            },
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("probe uidmap: ok"));
        assert!(s.contains("scan complete"));
    }
}

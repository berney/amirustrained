//! Output renderers consuming the pipeline's [`Event`] stream.

pub mod json;
pub mod jsonl;
pub mod markdown;
pub mod sarif;
pub mod text;

use crate::opts::Format;
use crate::pipeline::Event;

/// Event sink for one output format. `Send` so the Task 7 CLI can hand the
/// renderer to whichever thread owns the writer; `finish` lets a format flush
/// trailing state after the final event.
pub trait Renderer: Send {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()>;
    fn finish(&mut self, w: &mut dyn std::io::Write) -> std::io::Result<()>;
}

pub fn make(fmt: Format, verbose: bool, color: bool) -> Box<dyn Renderer> {
    match fmt {
        Format::Text => Box::new(text::Text { verbose, color }),
        Format::Jsonl => Box::new(jsonl::Jsonl),
        Format::Json => Box::new(json::Json),
        Format::Markdown => Box::new(markdown::Markdown),
        Format::Sarif => Box::new(sarif::Sarif),
    }
}

use clap::Parser;

mod opts;
// Stub modules: later tasks (2-7) fill these in.
mod model;
mod pipeline;
mod probes;
mod render;
mod sys;

fn main() {
    let _cli = opts::Cli::parse();
    // Full wiring lands in Task 7.
    println!("amirustrained 0.1.0: no probes wired yet");
}

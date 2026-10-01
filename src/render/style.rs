//! Titanium-palette colour detection and SGR helpers (spec §9, OMP theme).
//!
//! Palette extracted from oh-my-pi's `titanium` (dark) theme
//! (`packages/coding-agent/src/modes/theme/defaults/titanium.json`); the
//! detection predicate mirrors `packages/utils/src/chalk.ts`
//! (`detectColorLevel`): an explicit `--no-color` wins, then any `NO_COLOR`
//! presence (no-color.org; chalk.ts treats the bare key, even empty, as
//! off), then `TERM=dumb`, then the stdout TTY test. Truecolor
//! (`ESC[38;2;r;g;bm`) is the only emission mode — the 256-colour degrade is
//! deliberately skipped (brief: "optional, skip if noisy"), so off-vs-on is
//! the only support decision the renderers make.
//!
//! Semantic mapping (controller choice, brief 2026-10-02; text and markdown
//! renderers MUST stay consistent):
//!
//! | role                      | colour                       |
//! |---------------------------|------------------------------|
//! | severity critical         | `ALERT_RED` #ff4757, bold    |
//! | severity high             | `WARNING_AMBER` #ffb347      |
//! | severity medium           | `TITANIUM_GOLD` #d4c090      |
//! | severity low / info       | `DIM_ALUMINUM` #9ca3b0       |
//! | verdict runtime `host`    | `BRIGHT_ALUMINUM` #e8ecf4    |
//! | verdict runtime container | `ELECTRIC_BLUE` #00b4ff      |
//! | verdict runtime vm/sandbox| `READOUT_GREEN` #00ff88      |
//! | incomplete banner         | `ALERT_RED` #ff4757, bold    |
//!
//! JSON (post-render tokeniser, `json::highlight`) and YAML (emit-time,
//! `yaml`) share this palette: keys `ELECTRIC_BLUE`, strings `TITANIUM_GOLD`
//! (quoted) / `WARNING_AMBER` (plain scalars), numbers `WARNING_AMBER`,
//! bool/null `READOUT_GREEN`, punctuation/indent glyphs `DIM_ALUMINUM`.

use crate::model::{RuntimeKind, Severity};

// --- Titanium palette (titanium.json, dark variant) -------------------------
pub const ELECTRIC_BLUE: &str = "#00b4ff";
pub const TITANIUM_GOLD: &str = "#d4c090";
pub const BRIGHT_ALUMINUM: &str = "#e8ecf4";
pub const DIM_ALUMINUM: &str = "#9ca3b0";
pub const WARNING_AMBER: &str = "#ffb347";
pub const READOUT_GREEN: &str = "#00ff88";
pub const ALERT_RED: &str = "#ff4757";
pub const SUBTLE_GRAY: &str = "#2a3038";

// --- SGR sequences -----------------------------------------------------------
pub const BOLD: &str = "\x1b[1m";
pub const UNDERLINE: &str = "\x1b[4m";
pub const RESET: &str = "\x1b[0m";

/// ANSI colour capability. Truecolor is the only "on" level we emit; every
/// off-switch (flag, env, pipe) collapses to [`ColorSupport::Off`], which
/// makes every helper below the identity and keeps piped output byte-identical
/// to the unstyled contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorSupport {
    Off,
    TrueColor,
}

/// Detection: explicit flag first (CI-friendly override), then the chalk.ts
/// environment predicate, then the TTY test. `env` is injected so the unit
/// tests exercise combinations without touching process globals, and `tty`
/// folds "stdout is a terminal AND the sink is stdout" (a `-o file` target is
/// never painted — ReviewT2324).
pub fn detect(no_color: bool, tty: bool, env: &dyn Fn(&str) -> Option<String>) -> ColorSupport {
    if no_color {
        return ColorSupport::Off;
    }
    // chalk.ts: `"NO_COLOR" in environment` — mere presence turns colour off,
    // even `NO_COLOR=`.
    if env("NO_COLOR").is_some() {
        return ColorSupport::Off;
    }
    if env("TERM").as_deref() == Some("dumb") {
        return ColorSupport::Off;
    }
    if !tty {
        return ColorSupport::Off;
    }
    ColorSupport::TrueColor
}

impl ColorSupport {
    /// Wrap `text` in already-composed SGR `prefix` sequences and a single
    /// [`RESET`]; identity when [`ColorSupport::Off`].
    pub fn wrap(self, prefix: &str, text: &str) -> String {
        if self == Self::Off {
            text.to_owned()
        } else {
            format!("{prefix}{text}{RESET}")
        }
    }

    /// Foreground-only convenience around [`ColorSupport::wrap`].
    pub fn fg(self, hex: &str, text: &str) -> String {
        self.wrap(&fg(hex), text)
    }
}

/// Truecolor foreground sequence for `#rrggbb`. Constants are module-local,
/// but a malformed literal must never panic a renderer, hence the 0 fallback.
pub fn fg(hex: &str) -> String {
    let h = hex.strip_prefix('#').unwrap_or(hex);
    let v = u32::from_str_radix(h, 16).unwrap_or(0);
    format!(
        "\x1b[38;2;{};{};{}m",
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff
    )
}

/// Foreground hex for a finding severity (table in the module doc).
pub fn severity_fg(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => ALERT_RED,
        Severity::High => WARNING_AMBER,
        Severity::Medium => TITANIUM_GOLD,
        Severity::Low | Severity::Info => DIM_ALUMINUM,
    }
}

/// Only Critical is bolded: the escalation marks the alarm level, the
/// foreground carries the rest of the ladder.
pub fn severity_bold(sev: Severity) -> bool {
    sev == Severity::Critical
}

/// Verdict-runtime foreground: `host` is the neutral report body colour,
/// container engines the theme's signature blue, microVM/sandbox runtimes the
/// readout green (firecracker / gVisor / kata share that isolation story).
pub fn verdict_fg(kind: RuntimeKind) -> &'static str {
    match kind {
        RuntimeKind::Host => BRIGHT_ALUMINUM,
        RuntimeKind::Firecracker | RuntimeKind::Gvisor | RuntimeKind::Kata => READOUT_GREEN,
        _ => ELECTRIC_BLUE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake environment: lookups answer from `pairs`, `None` otherwise —
    /// detection never reads process globals.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| owned.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.clone())
    }

    #[test]
    fn plain_tty_gets_truecolor() {
        assert_eq!(
            detect(false, true, &env(&[("TERM", "xterm-256color")])),
            ColorSupport::TrueColor
        );
        // COLORTERM is not required for "on": the predicate is tty + no
        // off-switch, truecolor unconditionally.
        assert_eq!(detect(false, true, &env(&[])), ColorSupport::TrueColor);
    }

    #[test]
    fn piped_stdout_is_always_off() {
        assert_eq!(
            detect(false, false, &env(&[("COLORTERM", "truecolor")])),
            ColorSupport::Off
        );
    }

    #[test]
    fn no_color_presence_off_even_empty() {
        // chalk.ts keys on presence, not non-emptiness.
        assert_eq!(
            detect(false, true, &env(&[("NO_COLOR", "")])),
            ColorSupport::Off
        );
        assert_eq!(
            detect(false, true, &env(&[("NO_COLOR", "1")])),
            ColorSupport::Off
        );
    }

    #[test]
    fn term_dumb_off() {
        assert_eq!(
            detect(false, true, &env(&[("TERM", "dumb")])),
            ColorSupport::Off
        );
    }

    #[test]
    fn flag_beats_everything_and_off_wins_over_tty() {
        assert_eq!(detect(true, true, &env(&[])), ColorSupport::Off);
    }

    #[test]
    fn fg_emits_truecolor_triples() {
        assert_eq!(fg(ELECTRIC_BLUE), "\x1b[38;2;0;180;255m");
        assert_eq!(fg(ALERT_RED), "\x1b[38;2;255;71;87m");
        assert_eq!(fg(READOUT_GREEN), "\x1b[38;2;0;255;136m");
    }

    #[test]
    fn wrap_identity_off_single_reset_on() {
        assert_eq!(ColorSupport::Off.wrap(BOLD, "abc"), "abc");
        let on = ColorSupport::TrueColor.wrap(&format!("{}{BOLD}", fg(DIM_ALUMINUM)), "abc");
        assert_eq!(on, format!("\x1b[38;2;156;163;176m\x1b[1mabc\x1b[0m"));
        assert_eq!(
            on.matches("\x1b[0m").count(),
            1,
            "one trailing RESET per wrap"
        );
    }

    #[test]
    fn severity_and_verdict_mapping_follows_the_table() {
        assert_eq!(severity_fg(Severity::Critical), ALERT_RED);
        assert!(severity_bold(Severity::Critical));
        assert!(!severity_bold(Severity::High));
        assert_eq!(severity_fg(Severity::High), WARNING_AMBER);
        assert_eq!(severity_fg(Severity::Medium), TITANIUM_GOLD);
        assert_eq!(severity_fg(Severity::Low), DIM_ALUMINUM);
        assert_eq!(severity_fg(Severity::Info), DIM_ALUMINUM);
        assert_eq!(verdict_fg(RuntimeKind::Host), BRIGHT_ALUMINUM);
        assert_eq!(verdict_fg(RuntimeKind::Docker), ELECTRIC_BLUE);
        assert_eq!(verdict_fg(RuntimeKind::Kubernetes), ELECTRIC_BLUE);
        assert_eq!(verdict_fg(RuntimeKind::Firecracker), READOUT_GREEN);
        assert_eq!(verdict_fg(RuntimeKind::Gvisor), READOUT_GREEN);
        assert_eq!(verdict_fg(RuntimeKind::Kata), READOUT_GREEN);
    }
}

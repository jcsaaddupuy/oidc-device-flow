//! Terminal detection and styling.
//!
//! Provides detection for interactive mode, color support, and
//! consistent styling across the application.

use std::env;

/// Terminal capabilities detected from environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermMode {
    /// Full interactive mode: TTY, not CI, color-capable terminal
    Interactive,
    /// CI/automation mode: running in CI environment
    Ci,
    /// Non-interactive: piped/redirected or dumb terminal
    NonInteractive,
}

impl TermMode {
    /// Returns true if we should show animated spinners.
    pub fn supports_animation(self) -> bool {
        matches!(self, TermMode::Interactive)
    }

    /// Returns true if we should use colors.
    pub fn supports_color(self) -> bool {
        matches!(self, TermMode::Interactive | TermMode::Ci)
    }

    /// Returns true if we're in a fully interactive environment.
    #[allow(dead_code)]
    pub fn is_interactive(self) -> bool {
        matches!(self, TermMode::Interactive)
    }

    /// Returns true if we should output machine-readable format.
    #[allow(dead_code)]
    pub fn prefers_machine_output(self) -> bool {
        matches!(self, TermMode::NonInteractive)
    }
}

/// Detect the terminal mode based on environment and TTY status.
pub fn detect_term_mode() -> TermMode {
    // Not a TTY → non-interactive
    if !atty::is(atty::Stream::Stderr) {
        return TermMode::NonInteractive;
    }

    // CI environment (GitHub Actions, GitLab CI, CircleCI, Travis, etc.)
    if env::var("CI").is_ok() {
        return TermMode::Ci;
    }

    // Dumb terminal (emacs shell buffers, script(1), etc.)
    if env::var("TERM").ok().as_deref() == Some("dumb") {
        return TermMode::NonInteractive;
    }

    // User prefers no colors/animations (https://no-color.org/)
    if env::var("NO_COLOR").is_ok() {
        return TermMode::NonInteractive;
    }

    TermMode::Interactive
}

/// Check if the terminal supports 256 colors or true color.
pub fn supports_color() -> bool {
    // NO_COLOR is set → no colors
    if env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check TERM for known color-capable terminals
    if let Some(term) = env::var("TERM").ok().as_deref() {
        // Terminals known to support at least 256 colors
        let color_terms = [
            "xterm-256color",
            "xterm",
            "screen-256color",
            "screen",
            "tmux-256color",
            "tmux",
            "rxvt-256color",
            "rxvt",
            "vt100",
            "vt220",
            "ansi",
            "color",
            "cygwin",
            "linux",
            "konsole",
            "gnome",
            "iterm",
            "alacritty",
            "kitty",
            "wezterm",
            "foot",
        ];

        // Check if TERM contains any known color terminal type
        let term_lower = term.to_lowercase();
        for known in color_terms {
            if term_lower.contains(known) {
                return true;
            }
        }
    }

    // Check for COLORTERM (set by many modern terminals)
    if env::var("COLORTERM").is_ok() {
        return true;
    }

    // Default: assume color support in interactive terminals
    atty::is(atty::Stream::Stderr)
}

/// Enable colors if the terminal supports it.
/// Should be called once at startup.
pub fn init_colors() {
    if supports_color() {
        // colored crate respects NO_COLOR and CLICOLOR automatically
        colored::control::set_override(true);
    } else {
        colored::control::set_override(false);
    }
}

/// Styling helpers for consistent output appearance.
pub mod style {
    use colored::Colorize;

    /// Style for provider names.
    #[allow(dead_code)]
    pub fn provider(s: &str) -> String {
        s.cyan().bold().to_string()
    }

    /// Style for success messages.
    pub fn success(s: &str) -> String {
        s.green().to_string()
    }

    /// Style for error messages.
    pub fn error(s: &str) -> String {
        s.red().bold().to_string()
    }

    /// Style for warning messages.
    pub fn warning(s: &str) -> String {
        s.yellow().to_string()
    }

    /// Style for URLs (clickable in many terminals).
    pub fn url(s: &str) -> String {
        s.blue().underline().to_string()
    }

    /// Style for user codes (highlighted for visibility).
    pub fn user_code(s: &str) -> String {
        s.bold().to_string()
    }

    /// Style for dim/secondary text.
    pub fn dim(s: &str) -> String {
        s.bright_black().to_string()
    }

    /// Style for tokens (redacted portion).
    #[allow(dead_code)]
    pub fn token_partial(s: &str) -> String {
        s.dimmed().to_string()
    }

    /// Style for labels/headings.
    pub fn label(s: &str) -> String {
        s.bold().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_term_mode_detection() {
        // Just verify it doesn't panic
        let mode = detect_term_mode();
        assert!(matches!(mode, TermMode::Interactive | TermMode::Ci | TermMode::NonInteractive));
    }

    #[test]
    fn test_supports_color_no_panic() {
        // Just verify it doesn't panic
        let _ = supports_color();
    }
}
//! HeraclitusDB Security Operations Console (`heraclitus top`).
//!
//! The command remains intentionally read-only. It correlates telemetry that
//! HeraclitusDB already exposes instead of inventing health from missing data:
//! Core `/stats`, Sentinel, storage integrity, compliance, Raft, Agent Black Box,
//! Agent Policy Gateway and authorized red-team evidence.
//!
//! A global alarm strip is rendered on every tab whenever measured telemetry
//! reaches WARNING/CRITICAL. Red-team records are explicitly labelled as lab
//! evidence and are never silently promoted to production attack attribution.

#[path = "top_http.rs"]
mod http;
#[path = "top_model.rs"]
mod model;
#[path = "top_security.rs"]
mod security;
#[path = "top_ui.rs"]
mod ui;

use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use model::{ActiveTab, AppState, MAX_INTERVAL_SECS, MIN_INTERVAL_SECS};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::{Duration, Instant};

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    }
}

pub fn run_top(
    url_str: &str,
    user: &str,
    pass: &str,
    interval_sec: f64,
) -> Result<String, String> {
    enable_raw_mode().map_err(|e| format!("erro ao ativar raw mode: {e}"))?;
    execute!(io::stdout(), EnterAlternateScreen)
        .map_err(|e| format!("alternate screen: {e}"))?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("terminal Ratatui: {e}"))?;
    let core_authorization = http::core_authorization(user, pass);
    let mut app = AppState::new(url_str.to_string(), core_authorization, interval_sec);
    app.refresh(true);
    let mut last_tick = Instant::now();

    loop {
        terminal
            .draw(|frame| ui::render(frame, &app))
            .map_err(|e| format!("draw: {e}"))?;

        let refresh = Duration::from_secs_f64(app.interval_sec);
        let timeout = refresh.saturating_sub(last_tick.elapsed());
        if event::poll(timeout).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
                    continue;
                }

                if app.help {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('h') => app.help = false,
                        KeyCode::Char('q') => break,
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('p') | KeyCode::Char(' ') => app.paused = !app.paused,
                    KeyCode::Char('u') => {
                        app.refresh(true);
                        last_tick = Instant::now();
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => app.help = true,
                    KeyCode::Char('+') | KeyCode::Char('=') => {
                        app.interval_sec = (app.interval_sec - 0.25).max(MIN_INTERVAL_SECS)
                    }
                    KeyCode::Char('-') => {
                        app.interval_sec = (app.interval_sec + 0.25).min(MAX_INTERVAL_SECS)
                    }
                    KeyCode::Char('1') => app.active_tab = ActiveTab::Overview,
                    KeyCode::Char('2') => app.active_tab = ActiveTab::Tasks,
                    KeyCode::Char('3') => app.active_tab = ActiveTab::Storage,
                    KeyCode::Char('4') => app.active_tab = ActiveTab::Queries,
                    KeyCode::Char('5') => app.active_tab = ActiveTab::Raft,
                    KeyCode::Char('6') => app.active_tab = ActiveTab::Security,
                    KeyCode::Char('7') => app.active_tab = ActiveTab::Agents,
                    KeyCode::Char('8') => app.active_tab = ActiveTab::Indexes,
                    KeyCode::Tab => app.active_tab = app.active_tab.next(),
                    KeyCode::BackTab => app.active_tab = app.active_tab.previous(),
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= Duration::from_secs_f64(app.interval_sec) {
            if !app.paused {
                app.refresh(false);
            }
            last_tick = Instant::now();
        }
    }

    Ok("Heraclitus Security Operations Console finalizado.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_cycle_includes_agent_security() {
        let mut tab = ActiveTab::Overview;
        for _ in 0..6 {
            tab = tab.next();
        }
        assert_eq!(tab, ActiveTab::Agents);
        assert_eq!(tab.next(), ActiveTab::Indexes);
        assert_eq!(tab.next().next(), ActiveTab::Overview);
    }
}

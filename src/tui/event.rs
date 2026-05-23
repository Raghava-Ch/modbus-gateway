// tui/event.rs — Crossterm event handling

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};

use crate::error::AppResult;

/// Terminal input events decoded for the TUI loop.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// A tick from the render timer (no user input this cycle).
    Tick,
    /// User pressed a key.
    Key(KeyEvent),
    /// Terminal was resized.
    #[allow(dead_code)] // Width/height used by future responsive layout logic
    Resize(u16, u16),
}

/// Read the next event within `timeout`.
///
/// Returns `Tick` if no event arrives within the deadline.
pub fn next_event(timeout: Duration) -> AppResult<AppEvent> {
    if event::poll(timeout).map_err(|e| crate::error::AppError::Io(e))? {
        match event::read().map_err(|e| crate::error::AppError::Io(e))? {
            Event::Key(k) => return Ok(AppEvent::Key(k)),
            Event::Resize(w, h) => return Ok(AppEvent::Resize(w, h)),
            _ => {}
        }
    }
    Ok(AppEvent::Tick)
}

/// Returns `true` when the key event should trigger a shutdown.
pub fn is_quit(key: &KeyEvent) -> bool {
    matches!(
        key.code,
        KeyCode::Char('q')
    ) || matches!(
        (key.code, key.modifiers),
        (KeyCode::Char('c'), KeyModifiers::CONTROL)
    )
}

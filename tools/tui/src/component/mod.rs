use std::{cell::RefCell, fmt, ops::Deref, time};

use superconsole::{Component, Dimensions, DrawMode, Lines};

use crate::action::Action;

mod loading;
mod timer;

#[derive(Debug)]
pub struct FmtDuration(time::Duration);

impl From<time::Duration> for FmtDuration {
    fn from(d: time::Duration) -> Self {
        Self(d)
    }
}

impl Deref for FmtDuration {
    type Target = time::Duration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for FmtDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.as_secs();
        if secs == 0 {
            write!(f, "{}ms", self.as_millis())
        } else if secs >= 60 {
            write!(f, "{}min{}s", secs / 60, secs % 60)
        } else {
            let secs = self.as_secs_f32();
            write!(f, "{:.1}s", secs)
        }
    }
}

pub struct Compositor<'a> {
    pub timer: timer::Timer<'a>,
    pub loading_bar: loading::LoadingBar<'a>,
}

impl Component for Compositor<'_> {
    fn draw_unchecked(&self, dimensions: Dimensions, mode: DrawMode) -> anyhow::Result<Lines> {
        let mut lines = self.timer.draw_unchecked(dimensions, mode)?;
        lines.pad_lines_left(2);

        let action = self.timer.action.borrow();
        let is_finished = action.is_finished();
        if !action.show_progress() && !is_finished {
            return Ok(lines);
        }
        let mut loading = self.loading_bar.draw_unchecked(dimensions, mode)?;

        let step_len = action.step_header.len();
        let loading_len = if is_finished {
            action.completion_header.len()
        } else {
            action.loading_bar_header.unwrap_or_default().len()
        };

        let padding = if step_len >= loading_len {
            step_len - loading_len + 2
        } else {
            2usize.saturating_sub(loading_len - step_len)
        };
        loading.pad_lines_left(padding);

        lines.0.extend(loading.0);

        Ok(lines)
    }
}

impl<'a> Compositor<'a> {
    pub fn new(action: &'a RefCell<Action>) -> Self {
        Self {
            timer: timer::Timer::new(action),
            loading_bar: loading::LoadingBar::new(action),
        }
    }

    pub fn finalize(&mut self) -> anyhow::Result<Lines> {
        self.draw_unchecked(Dimensions::default(), DrawMode::Final)
    }
}

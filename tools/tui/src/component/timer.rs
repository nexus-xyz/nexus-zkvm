use std::{cell::Cell, time::Instant};

use superconsole::{
    style::{Color, Stylize},
    Component, Dimensions, DrawMode, Line, Lines, Span,
};

use super::format_duration;
use crate::action::TimedAction;

pub struct Timer {
    pub start: Instant,

    pub(super) finished: bool,
    pub(super) action: TimedAction,

    num_dots: Cell<usize>,
    last_tick: Instant,
    color: Color,
}

impl Component for Timer {
    fn draw_unchecked(&self, _: Dimensions, _: DrawMode) -> anyhow::Result<Lines> {
        if self.finished {
            return Ok(Lines::new());
        }
        let elapsed = self.last_tick.elapsed();
        let action = &self.action;

        let heading_span =
            Span::new_styled(action.step_header().to_owned().bold().with(self.color))?;
        let trailing_span = Span::new_unstyled(action.step_trailing())?;

        // dots
        let num_dots = self.num_dots.get();
        let dots = Span::new_unstyled(format!(
            "{dot:.>num_dots$}{empty:>num_spaces$}",
            dot = '.',
            num_dots = num_dots,
            empty = "",
            num_spaces = 4 - num_dots,
        ))?;
        self.num_dots.set(((num_dots + 1) % 4).max(1));

        let elapsed_span = Span::new_styled(format_duration(elapsed).bold())?;

        let line = Line::from_iter([heading_span, trailing_span, dots, elapsed_span]);
        Ok(Lines(vec![line]))
    }
}

impl Timer {
    pub fn new(action: TimedAction) -> Self {
        let start = Instant::now();
        Self {
            start,
            finished: false,
            action,
            num_dots: Cell::new(1),
            last_tick: start,
            color: if action.show_progress() {
                Color::Blue
            } else {
                Color::Cyan
            },
        }
    }

    pub fn next_iter(&mut self) {
        self.action.next_iter();
        *self = Self::new(self.action);
    }

    pub fn finalize(&mut self) -> anyhow::Result<Lines> {
        self.last_tick = self.start;
        self.num_dots.set(3);
        self.color = Color::Blue;

        self.draw_unchecked(Dimensions::default(), DrawMode::Normal)
    }
}

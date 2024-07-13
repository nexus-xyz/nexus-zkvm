use std::{
    cell::{Cell, RefCell},
    time::Instant,
};

use superconsole::{
    style::{Color, Stylize},
    Component, Dimensions, DrawMode, Line, Lines, Span,
};

use super::FmtDuration;
use crate::action::Action;

pub struct Timer<'a> {
    pub start: Instant,
    pub(super) action: &'a RefCell<Action>,

    num_dots: Cell<usize>,
    last_tick: Instant,
    color: Color,
}

impl Component for Timer<'_> {
    fn draw_unchecked(&self, _: Dimensions, _: DrawMode) -> anyhow::Result<Lines> {
        let action = self.action.borrow();
        if action.is_finished() {
            return Ok(Lines::new());
        }
        let elapsed: FmtDuration = self.last_tick.elapsed().into();
        let action = self.action.borrow();

        let heading_span = Span::new_styled(action.step_header.to_owned().bold().with(self.color))?;
        let mut trailing = (action.step_trailing)(action.iter);
        if !trailing.is_empty() {
            trailing.insert(0, ' ');
        }
        let trailing_span = Span::new_unstyled(trailing)?;

        // dots
        let num_dots = self.num_dots.get();
        let dots = Span::new_unstyled(format!(
            " {dot:.>num_dots$}{empty:>num_spaces$}",
            dot = '.',
            num_dots = num_dots,
            empty = "",
            num_spaces = 4 - num_dots,
        ))?;
        self.num_dots.set(((num_dots + 1) % 4).max(1));

        let elapsed_span = Span::new_styled(elapsed.to_string().bold())?;

        let line = Line::from_iter([heading_span, trailing_span, dots, elapsed_span]);
        Ok(Lines(vec![line]))
    }
}

impl<'a> Timer<'a> {
    pub fn new(action: &'a RefCell<Action>) -> Self {
        let start = Instant::now();
        Self {
            start,
            action,
            num_dots: Cell::new(1),
            last_tick: start,
            color: if action.borrow().show_progress() {
                Color::Blue
            } else {
                Color::Cyan
            },
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.action);
    }

    pub fn finalize(&mut self) -> anyhow::Result<Lines> {
        self.last_tick = self.start;
        self.num_dots.set(3);
        self.color = Color::Blue;

        let mut lines = self.draw_unchecked(Dimensions::default(), DrawMode::Normal)?;
        lines.pad_lines_left(2);

        Ok(lines)
    }
}

use std::{cell::RefCell, time::Duration};

use superconsole::{style::Stylize, Component, Dimensions, DrawMode, Line, Lines, Span};

use crate::action::Action;

const WIDTH: usize = "=======>                  ".len() - 1;

/// A loading bar component that displays progress for long-running operations.
///
/// This component renders a visual progress bar with percentage completion,
/// iteration counts, and optional headers. It automatically switches between
/// loading and completion states based on the action's progress.
pub struct LoadingBar<'a> {
    pub time_spent: Duration,

    action: &'a RefCell<Action>,
}

impl Component for LoadingBar<'_> {
    fn draw_unchecked(&self, _: Dimensions, _: DrawMode) -> anyhow::Result<Lines> {
        let action = self.action.borrow();

        let res = if !action.is_finished() {
            if !action.show_progress() {
                return Ok(Lines::new());
            }
            let iteration = action.iter;
            let total = action.iter_num;

            let heading_span = Span::new_styled(
                action
                    .loading_bar_header
                    .unwrap_or_default()
                    .to_owned()
                    .cyan()
                    .bold(),
            )?;

            let percentage = iteration as f64 / total as f64;
            let amount = (percentage * WIDTH as f64).ceil() as usize;

            let loading_bar = format!(
                " [{test:=>bar_amt$}{empty:padding_amt$}] {}/{}: ...",
                iteration,
                total,
                test = ">",
                empty = "",
                bar_amt = amount,
                padding_amt = WIDTH - amount,
            );
            let loading = Span::new_unstyled(loading_bar)?;
            Line::from_iter([heading_span, loading])
        } else {
            let elapsed = self.time_spent;

            let heading_span = Span::new_styled(action.completion_header.to_owned().blue().bold())?;
            let completion_span = Span::new_unstyled((action.completion_trailing)(elapsed.into()))?;

            Line::from_iter([heading_span, Span::padding(1), completion_span])
        };

        Ok(Lines(vec![res]))
    }
}

impl<'a> LoadingBar<'a> {
    /// Creates a new loading bar component for the given action.
    ///
    /// The loading bar will track the progress of the provided action and
    /// render appropriate visual feedback based on the action's state.
    pub fn new(action: &'a RefCell<Action>) -> Self {
        Self {
            action,
            time_spent: Duration::ZERO,
        }
    }
}

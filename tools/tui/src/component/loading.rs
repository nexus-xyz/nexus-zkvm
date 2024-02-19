use std::time::Duration;

use superconsole::{style::Stylize, Component, Dimensions, DrawMode, Line, Lines, Span};

use super::format_duration;
use crate::action::TimedAction;

const WIDTH: usize = "=======>                  ".len() - 1;

pub struct LoadingBar {
    pub time_spent: Duration,

    pub(super) finished: bool,
    pub(super) action: TimedAction,
}

impl Component for LoadingBar {
    fn draw_unchecked(&self, _: Dimensions, _: DrawMode) -> anyhow::Result<Lines> {
        let action = &self.action;

        let res = if !self.finished {
            if !self.action.show_progress() {
                return Ok(Lines::new());
            }
            let (iteration, total) = self.action.num_iters();

            let heading_span = Span::new_styled(action.loading_header().to_owned().cyan().bold())?;

            let percentage = iteration as f64 / total as f64;
            let amount = (percentage * WIDTH as f64).ceil() as usize;

            let loading_bar = format!(
                "[{test:=>bar_amt$}{empty:padding_amt$}] {}/{}: ...",
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
            let elapsed_str = format_duration(elapsed);

            let heading_span =
                Span::new_styled(action.completion_header().to_owned().blue().bold())?;
            let completion_span = Span::new_unstyled(action.completion_trailing(&elapsed_str))?;

            Line::from_iter([heading_span, completion_span])
        };

        Ok(Lines(vec![res]))
    }
}

impl LoadingBar {
    pub fn new(action: TimedAction) -> Self {
        Self {
            action,
            finished: false,
            time_spent: Duration::ZERO,
        }
    }
}

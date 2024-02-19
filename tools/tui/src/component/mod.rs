use superconsole::{Component, Dimensions, DrawMode, Lines};

use crate::action::TimedAction;

mod loading;
mod timer;

pub fn format_duration(elapsed: std::time::Duration) -> String {
    if elapsed.as_secs() == 0 {
        format!("{}ms", elapsed.as_millis())
    } else {
        let secs = elapsed.as_secs_f32();
        format!("{:.1}s", secs)
    }
}

pub struct Compositor {
    pub timer: timer::Timer,
    pub loading_bar: loading::LoadingBar,
}

impl Component for Compositor {
    fn draw_unchecked(&self, dimensions: Dimensions, mode: DrawMode) -> anyhow::Result<Lines> {
        let mut lines = self.timer.draw_unchecked(dimensions, mode)?;
        lines
            .0
            .extend(self.loading_bar.draw_unchecked(dimensions, mode)?.0);

        Ok(lines)
    }
}

impl Compositor {
    pub fn new(action: TimedAction) -> Self {
        Self {
            timer: timer::Timer::new(action),
            loading_bar: loading::LoadingBar::new(action),
        }
    }

    pub fn next_iter(&mut self) {
        self.loading_bar.action.next_iter();
        self.timer.next_iter();
    }

    pub fn finalize(&mut self) -> anyhow::Result<Lines> {
        self.timer.finished = true;
        self.loading_bar.finished = true;
        self.draw_unchecked(Dimensions::default(), DrawMode::Final)
    }
}

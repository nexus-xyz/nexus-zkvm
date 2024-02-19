#[derive(Copy, Clone)]
pub enum TimedAction {
    Prove { iteration: usize, total: usize },
    SetupParams,
    LoadParams,
}

impl TimedAction {
    // Returns `true` if the action requires showing the progress bar, and `false` otherwise.
    pub fn show_progress(&self) -> bool {
        match self {
            Self::Prove { .. } => true,
            Self::SetupParams | Self::LoadParams => false,
        }
    }

    // Returns the current iter number paired with the number of total steps.
    pub fn num_iters(&self) -> (usize, usize) {
        match self {
            Self::Prove { iteration, total } => (*iteration, *total),
            Self::SetupParams | Self::LoadParams => (0, 1),
        }
    }

    // Increments iteration number.
    pub fn next_iter(&mut self) {
        match self {
            Self::Prove { iteration, total } => {
                let next_iter = *iteration + 1;
                assert!(next_iter <= *total);

                *iteration = next_iter
            }
            Self::SetupParams | Self::LoadParams => {}
        }
    }

    pub const fn step_header(&self) -> &'static str {
        match self {
            Self::Prove { .. } => "  Computing",
            Self::LoadParams => "  Loading",
            Self::SetupParams => "  Setting up",
        }
    }

    pub fn step_trailing(&self) -> String {
        match self {
            Self::Prove { iteration, .. } => format!(" step {iteration} "),
            Self::SetupParams | Self::LoadParams => " public parameters ".to_owned(),
        }
    }

    pub fn loading_header(&self) -> &'static str {
        match self {
            Self::Prove { .. } => "   Proving",
            Self::SetupParams | Self::LoadParams => "",
        }
    }

    pub fn completion_header(&self) -> &'static str {
        match self {
            Self::Prove { .. } => "     Proved",
            Self::LoadParams => " Finished",
            Self::SetupParams => "    Finished",
        }
    }

    pub fn completion_trailing(&self, elapsed_str: &str) -> String {
        match self {
            Self::Prove { total, .. } => format!(" {total} step(s) in {elapsed_str}"),
            Self::SetupParams | Self::LoadParams => format!(" in {elapsed_str}"),
        }
    }
}

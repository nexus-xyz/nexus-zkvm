use super::component::FmtDuration;

pub(crate) struct Action {
    pub iter: usize,
    pub iter_num: usize,

    pub step_header: &'static str,
    pub step_trailing: Box<dyn Fn(usize) -> String + Send>,
    pub loading_bar_header: Option<&'static str>,

    pub completion_header: &'static str,
    pub completion_trailing: Box<dyn Fn(FmtDuration) -> String + Send>,
}

impl Action {
    pub(crate) fn show_progress(&self) -> bool {
        self.loading_bar_header.is_some()
    }

    pub(crate) fn next_iter(&mut self) {
        let next_iter = self.iter + 1;
        assert!(next_iter <= self.iter_num);

        self.iter = next_iter;
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.iter == self.iter_num
    }
}

impl Default for Action {
    fn default() -> Self {
        Self {
            iter: 0,
            iter_num: 1,
            step_header: "",
            step_trailing: Box::new(|_step| String::new()),
            loading_bar_header: None,
            completion_header: "Finished",
            completion_trailing: Box::new(|elapsed| format!("in {elapsed}")),
        }
    }
}

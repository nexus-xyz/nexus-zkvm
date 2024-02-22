use std::sync::mpsc;

use super::{action::Action, component::FmtDuration, thread as tui_thread};

pub struct TerminalHandle {
    thread: tui_thread::ThreadHandle,
    ctx_sender: Option<mpsc::Sender<()>>,
}

impl Default for TerminalHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalHandle {
    pub fn new() -> Self {
        Self {
            thread: tui_thread::ThreadHandle::new(),
            ctx_sender: None,
        }
    }

    pub fn context(&mut self, step_header: &'static str) -> TerminalContext<'_> {
        let _ = self.ctx_sender.take();
        TerminalContext {
            term: self,
            action: Some(Action { step_header, ..Default::default() }),
            steps_left: 1,
        }
    }
}

pub struct TerminalContext<'a> {
    term: &'a mut TerminalHandle,
    action: Option<Action>,
    steps_left: usize,
}

impl TerminalContext<'_> {
    pub fn with_loading_bar(self, loading_header: &'static str) -> Self {
        Self {
            action: self.action.map(|action| Action {
                loading_bar_header: Some(loading_header),
                ..action
            }),
            ..self
        }
    }

    pub fn num_steps(self, num_steps: usize) -> Self {
        assert!(num_steps > 0);
        Self {
            action: self
                .action
                .map(|action| Action { iter_num: num_steps, ..action }),
            steps_left: num_steps,
            ..self
        }
    }

    pub fn on_step<F>(self, on_step: F) -> Self
    where
        F: Fn(usize) -> String + Send + 'static,
    {
        Self {
            action: self.action.map(|action| Action {
                step_trailing: Box::new(on_step),
                ..action
            }),
            ..self
        }
    }

    pub fn completion_header(self, completion_header: &'static str) -> Self {
        Self {
            action: self
                .action
                .map(|action| Action { completion_header, ..action }),
            ..self
        }
    }

    pub fn completion_stats<F>(self, on_completion: F) -> Self
    where
        F: Fn(FmtDuration) -> String + Send + 'static,
    {
        Self {
            action: self.action.map(|action| Action {
                completion_trailing: Box::new(on_completion),
                ..action
            }),
            ..self
        }
    }

    pub fn display_step(&mut self) -> Guard<'_> {
        self.steps_left = self
            .steps_left
            .checked_sub(1)
            .expect("steps number overflow");
        let ctx_sender = &mut self.term.ctx_sender;

        let sender = if let Some(action) = self.action.take() {
            ctx_sender.get_or_insert_with(|| {
                let (tx, rx) = mpsc::channel();
                let _ = self.term.thread.sender().send((action, rx));
                tx
            })
        } else {
            let tx = ctx_sender.as_ref().unwrap();
            let _ = tx.send(());
            tx
        }
        .into();

        Guard { sender }
    }
}

pub struct Guard<'a> {
    sender: Option<&'a mpsc::Sender<()>>,
}

impl Guard<'_> {
    pub fn abort(mut self) {
        let _ = self.sender.take();
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if let Some(sender) = self.sender {
            let _ = sender.send(());
        }
    }
}

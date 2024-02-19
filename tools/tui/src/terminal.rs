use std::sync::mpsc;

use super::{action::TimedAction, thread as tui_thread};

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

    pub fn iter_context(&mut self, num_steps: usize) -> TerminalContext<'_> {
        let _ = self.ctx_sender.take();
        TerminalContext {
            term: self,
            action: Some(TimedAction::Prove { iteration: 0, total: num_steps }),
            steps_left: num_steps,
        }
    }

    pub fn display_setup(&mut self) -> Guard<'_> {
        self.display_action(TimedAction::SetupParams)
    }

    pub fn display_load(&mut self) -> Guard<'_> {
        self.display_action(TimedAction::LoadParams)
    }

    fn display_action(&mut self, action: TimedAction) -> Guard<'_> {
        let (tx, rx) = mpsc::channel();

        let sender = self.ctx_sender.insert(tx);
        let _ = self.thread.sender().send((action, rx));
        Guard { sender }
    }
}

pub struct TerminalContext<'a> {
    term: &'a mut TerminalHandle,
    action: Option<TimedAction>,
    steps_left: usize,
}

impl TerminalContext<'_> {
    pub fn display_next_step(&mut self) -> Guard<'_> {
        self.steps_left
            .checked_sub(1)
            .expect("step number overflow");
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
        };

        Guard { sender }
    }
}

pub struct Guard<'a> {
    sender: &'a mpsc::Sender<()>,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let _ = self.sender.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output() {
        let mut term = TerminalHandle::new();

        {
            let _guard = term.display_setup();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        {
            let _guard = term.display_load();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        let mut term_ctx = term.iter_context(5);

        for _ in 0..5 {
            let _guard = term_ctx.display_next_step();

            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        // std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

use std::mem::ManuallyDrop;
use std::time::Duration;
use std::{
    cell::RefCell,
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread::JoinHandle,
};

use superconsole::SuperConsole;

use super::{action::Action, component::Compositor};

pub(crate) type Payload = (Action, Receiver<()>);

pub(crate) struct ThreadHandle {
    sender: ManuallyDrop<SyncSender<Payload>>,
    join_handle: ManuallyDrop<JoinHandle<()>>,
}

impl ThreadHandle {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(0);

        let join_handle = std::thread::spawn(move || thread_main(receiver));
        Self {
            sender: ManuallyDrop::new(sender),
            join_handle: ManuallyDrop::new(join_handle),
        }
    }

    pub fn sender(&self) -> &SyncSender<Payload> {
        &self.sender
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        let Self { sender, join_handle } = self;
        // SAFETY: struct fields are inaccessible once `drop` returns.
        unsafe { ManuallyDrop::drop(sender) };
        let join_handle = unsafe { ManuallyDrop::take(join_handle) };

        let _ = join_handle.join();
    }
}

fn thread_main(receiver: Receiver<Payload>) {
    let Some(mut superconsole) = SuperConsole::new() else {
        return;
    };

    while let Ok((action, _receiver)) = receiver.recv() {
        let _ = handle_action(&mut superconsole, action, _receiver);
    }
}

fn handle_action(
    superconsole: &mut SuperConsole,
    action: Action,
    receiver: Receiver<()>,
) -> anyhow::Result<()> {
    const SLEEP_DURATION: Duration = Duration::from_millis(100);

    let mut total_elapsed = Duration::ZERO;
    let iter_num = action.iter_num;

    let action = RefCell::new(action);
    let mut component = Compositor::new(&action);
    for i in 0..iter_num {
        component.timer.reset();

        loop {
            superconsole.render(&component)?;

            match receiver.recv_timeout(SLEEP_DURATION) {
                Ok(_) => break,
                Err(RecvTimeoutError::Disconnected) => anyhow::bail!("sender dropped"),
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
        total_elapsed += component.timer.start.elapsed();
        let step_line = component.timer.finalize()?;

        superconsole.render(&component)?;
        superconsole.emit(step_line);

        action.borrow_mut().next_iter();

        if i + 1 < iter_num {
            // wait for the next step.
            receiver.recv()?;
        }
    }

    component.loading_bar.time_spent = total_elapsed;
    let bar_line = component.finalize()?;

    superconsole.render(&component)?;
    superconsole.emit(bar_line);

    Ok(())
}

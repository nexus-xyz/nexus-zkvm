use std::mem::ManuallyDrop;
use std::time::Duration;
use std::{
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread::JoinHandle,
};

use superconsole::SuperConsole;

use super::{action::TimedAction, component::Compositor};

pub(crate) type Payload = (TimedAction, Receiver<()>);

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
        // SAFETY: struct fields are not accessible once `drop` returns.
        let sender = unsafe { ManuallyDrop::take(sender) };
        let join_handle = unsafe { ManuallyDrop::take(join_handle) };

        // disconnect the sender and join the thread.
        drop(sender);
        let _ = join_handle.join();
    }
}

fn thread_main(receiver: Receiver<Payload>) {
    let Some(mut superconsole) = SuperConsole::new() else {
        return;
    };

    while let Ok((action, _receiver)) = receiver.recv() {
        handle_action(&mut superconsole, action, _receiver).expect("tui-thread error");
    }
}

fn handle_action(
    superconsole: &mut SuperConsole,
    action: TimedAction,
    receiver: Receiver<()>,
) -> anyhow::Result<()> {
    const SLEEP_DURATION: Duration = Duration::from_millis(100);

    let mut total_elapsed = Duration::ZERO;
    let (_, total_steps) = action.num_iters();

    let mut component = Compositor::new(action);
    for i in 0..total_steps {
        loop {
            superconsole.render(&component)?;

            match receiver.try_recv() {
                Ok(_) => break,
                Err(TryRecvError::Disconnected) => anyhow::bail!("sender dropped"),
                Err(TryRecvError::Empty) => {}
            }

            std::thread::sleep(SLEEP_DURATION);
        }
        total_elapsed += component.timer.start.elapsed();

        let step_line = component.timer.finalize()?;

        superconsole.render(&component)?;
        superconsole.emit(step_line);

        component.next_iter();
        if i + 1 < total_steps {
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

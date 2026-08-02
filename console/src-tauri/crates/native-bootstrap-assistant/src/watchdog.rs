use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use your_cloud_bootstrap_protocol::MAX_ASSISTANT_REMAINING_MILLIS;

use crate::EXIT_WATCHDOG_EXPIRED;

const CONTROLLED_CLEANUP_GRACE: Duration = Duration::from_secs(1);

enum WatchdogCommand {
    Tighten(Instant),
    Cancel,
}

pub(crate) struct Watchdog {
    sender: Sender<WatchdogCommand>,
    worker: Option<JoinHandle<()>>,
    expired: Arc<AtomicBool>,
}

impl Watchdog {
    pub(crate) fn start_at(session_started_at: Instant) -> Result<Self, ()> {
        let (sender, receiver) = mpsc::channel();
        let deadline = session_started_at
            .checked_add(Duration::from_millis(MAX_ASSISTANT_REMAINING_MILLIS))
            .ok_or(())?;
        let expired = Arc::new(AtomicBool::new(false));
        let worker_expired = Arc::clone(&expired);
        let worker = thread::Builder::new()
            .name("bootstrap-watchdog".into())
            .spawn(move || run(receiver, deadline, worker_expired))
            .map_err(|_| ())?;
        Ok(Self {
            sender,
            worker: Some(worker),
            expired,
        })
    }

    pub(crate) fn tighten_to(&self, deadline: Instant) -> Result<(), ()> {
        self.sender
            .send(WatchdogCommand::Tighten(deadline))
            .map_err(|_| ())
    }

    pub(crate) fn expiration_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.expired)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.sender.send(WatchdogCommand::Cancel);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run(receiver: Receiver<WatchdogCommand>, mut deadline: Instant, expired: Arc<AtomicBool>) {
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            expire_then_force_after_grace(&receiver, &expired);
            return;
        };
        match receiver.recv_timeout(remaining) {
            Ok(WatchdogCommand::Tighten(candidate)) => {
                deadline = earlier_deadline(deadline, candidate);
            }
            Ok(WatchdogCommand::Cancel) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {
                expire_then_force_after_grace(&receiver, &expired);
                return;
            }
        }
    }
}

fn expire_then_force_after_grace(receiver: &Receiver<WatchdogCommand>, expired: &AtomicBool) {
    expired.store(true, Ordering::SeqCst);
    let grace_deadline = Instant::now() + CONTROLLED_CLEANUP_GRACE;
    loop {
        let Some(remaining) = grace_deadline.checked_duration_since(Instant::now()) else {
            std::process::exit(EXIT_WATCHDOG_EXPIRED.into());
        };
        match receiver.recv_timeout(remaining) {
            Ok(WatchdogCommand::Cancel) | Err(RecvTimeoutError::Disconnected) => {
                return;
            }
            Ok(WatchdogCommand::Tighten(_)) => {}
            Err(RecvTimeoutError::Timeout) => {
                std::process::exit(EXIT_WATCHDOG_EXPIRED.into());
            }
        }
    }
}

fn earlier_deadline(current: Instant, candidate: Instant) -> Instant {
    current.min(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tightening_never_extends_a_deadline() {
        let now = Instant::now();
        let current = now + Duration::from_secs(10);
        assert_eq!(
            earlier_deadline(current, now + Duration::from_secs(5)),
            now + Duration::from_secs(5)
        );
        assert_eq!(
            earlier_deadline(current, now + Duration::from_secs(20)),
            current
        );
    }

    #[test]
    fn initial_deadline_includes_work_done_before_the_watchdog_starts() {
        let session_started_at = Instant::now();
        let after_attestation = session_started_at + Duration::from_millis(75);
        let deadline = session_started_at + Duration::from_millis(MAX_ASSISTANT_REMAINING_MILLIS);

        assert_eq!(
            deadline.duration_since(after_attestation),
            Duration::from_millis(MAX_ASSISTANT_REMAINING_MILLIS - 75)
        );
    }
}

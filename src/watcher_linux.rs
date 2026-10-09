//! Linux stub for the macOS FSEvents watcher.
//!
//! Step A of the Linux port: provides the same public interface as
//! `fsevents.rs` but emits no events. The index is built once by `walk.rs`
//! and searches work; live updates are not yet implemented (see Step B/C
//! in the port plan: polling, then inotify).

use std::sync::mpsc::Sender;

pub const MUST_SCAN_SUBDIRS: u32 = 0x1;
pub const USER_DROPPED: u32 = 0x2;
pub const KERNEL_DROPPED: u32 = 0x4;
pub const HISTORY_DONE: u32 = 0x10;

pub struct Event {
    pub path: Vec<u8>,
    pub flags: u32,
    pub id: u64,
}

pub struct Stream {
    _tx: Sender<Vec<Event>>,
}

pub fn watch(_since: u64, _latency: f64, tx: Sender<Vec<Event>>) -> Stream {
    // No-op: immediately signal HISTORY_DONE so the engine knows the
    // initial state is complete and there is no history to replay.
    let _ = tx.send(vec![Event { path: Vec::new(), flags: HISTORY_DONE, id: 0 }]);
    Stream { _tx: tx }
}

pub fn FSEventsGetCurrentEventId() -> u64 {
    0
}

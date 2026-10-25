//! Test doubles: a controllable spawn handle and a recording SDK port.
//! Shared by every `bg` module's unit tests.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde_json::Value;

use crate::glock;
use crate::handle::{Exit, ExitState, Handle};
use crate::port::{CustomMessage, SendOptions, SdkPort};

/// A handle whose death the test controls. First write to the exit cell wins,
/// exactly like a real spawn (an already-dead process cannot be re-killed).
pub(crate) struct MockHandle {
    pid: u32,
    killed: AtomicBool,
    state: ExitState,
}

impl MockHandle {
    /// Already at its terminal state.
    #[allow(dead_code)]
    pub(crate) fn exited(exit: Exit) -> Self {
        let state = ExitState::new();
        state.set(exit);
        MockHandle { pid: 4242, killed: AtomicBool::new(false), state }
    }

    /// Still running: `finish()` or `kill()` publishes the exit.
    pub(crate) fn running() -> Self {
        MockHandle { pid: 4243, killed: AtomicBool::new(false), state: ExitState::new() }
    }

    /// Test hook: the spawn exits on its own (no kill flag).
    pub(crate) fn finish(&self, exit: Exit) {
        self.state.set(exit);
    }

    #[allow(dead_code)]
    pub(crate) fn was_killed(&self) -> bool {
        self.killed.load(Ordering::SeqCst)
    }
}

impl Handle for MockHandle {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        self.state.set(Exit::killed(1));
    }
    fn wait(&self) -> Exit {
        self.state.wait()
    }
    fn try_wait(&self) -> Option<Exit> {
        self.state.get()
    }
}

/// Records everything the UI/notification layer asks of the SDK.
#[derive(Default)]
pub(crate) struct MockPort {
    pub(crate) sent: Mutex<Vec<(String, String)>>, // (custom_type, content)
    pub(crate) statuses: Mutex<Vec<(String, String)>>,
    pub(crate) widgets: Mutex<Vec<(String, Option<Value>)>>,
    pub(crate) fail_send: AtomicBool,
}

impl MockPort {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn send_count(&self) -> usize {
        glock(&self.sent).len()
    }
    pub(crate) fn contents(&self) -> Vec<String> {
        glock(&self.sent).iter().map(|(_, c)| c.clone()).collect()
    }
    pub(crate) fn set_fail_send(&self, v: bool) {
        self.fail_send.store(v, Ordering::SeqCst);
    }
}

impl SdkPort for MockPort {
    fn set_status(&self, key: &str, value: &str) {
        glock(&self.statuses).push((key.to_string(), value.to_string()));
    }
    fn set_widget(
        &self,
        key: &str,
        content: Option<Value>,
        _options: Option<Value>,
    ) -> Result<(), String> {
        glock(&self.widgets).push((key.to_string(), content));
        Ok(())
    }
    fn send_custom_message(&self, msg: CustomMessage, _opts: SendOptions) -> Result<(), String> {
        if self.fail_send.load(Ordering::SeqCst) {
            return Err("send failed".to_string());
        }
        glock(&self.sent).push((msg.custom_type, msg.content));
        Ok(())
    }
}

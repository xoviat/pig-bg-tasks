//! The PiG SDK seam — the slice of `sdk.Context` `bg` actually uses
//! (Go: `SetStatus`, `SetWidget`, `SendCustomMessage` + retained-context
//! send options). Implemented by the ext layer; mocked in tests.
//!
//! Retained-context parity (SDK D19): the registry stores this behind
//! `Option<Arc<dyn SdkPort>>` and re-renders/never-retries exactly like the
//! Go zero-value check — no notifier means notifications are lost, not queued.

use serde_json::Value;

/// Out-of-band steered message (Go `sdk.CustomMessage`).
#[derive(Debug, Clone)]
pub struct CustomMessage {
    pub custom_type: String,
    pub content: String,
    pub display: bool,
    pub details: Value,
}

/// Go `sdk.SendMessageOptions`.
#[derive(Debug, Clone)]
pub struct SendOptions {
    pub trigger_turn: bool,
    pub deliver_as: String,
}

impl SendOptions {
    /// Parity defaults used by `SendTaskNotification`: deliverAs=steer,
    /// triggerTurn=true.
    pub fn steer() -> Self {
        SendOptions { trigger_turn: true, deliver_as: "steer".to_string() }
    }
}

/// Narrow port of the retained PiG context (Go `sdk.Context` subset).
pub trait SdkPort: Send + Sync {
    /// Status-bar pill (`ctx.SetStatus`); empty value clears the key.
    fn set_status(&self, key: &str, value: &str);
    /// Editor widget (`ctx.SetWidget`); `content: None` clears the key.
    fn set_widget(
        &self,
        key: &str,
        content: Option<Value>,
        options: Option<Value>,
    ) -> Result<(), String>;
    /// Out-of-band message (`ctx.SendCustomMessage`).
    fn send_custom_message(&self, msg: CustomMessage, opts: SendOptions) -> Result<(), String>;
}

//! The SDK adapter: implements the extension's [`crate::bg::SdkPort`] over a
//! retained pig [`Context`] (SDK D19 — `Context: Clone` verified in E7).
//!
//! Every tool call installs a fresh port (`set_notifier` on each call, Go
//! parity), so the newest session drives notifications; `bg`'s watcher
//! threads then reach the host through `Arc<dyn SdkPort>` clones.

use std::sync::Arc;

use crate::bg::port::{CustomMessage, SendOptions, SdkPort};
use pig_sdk::{Context, SendMessageOptions};
use serde_json::Value;

pub struct CtxPort {
    pub ctx: Context,
}

// Compile-time shape guarantees for the retained-context port: the port
// crosses watcher threads (status pill from completion threads, messages
// after the handler returned) — the port itself is only ever held in an
// `Arc`, so it needs Send + Sync; the retained `Context` needs Clone.
fn _assert_ctx_bounds<T: Send + Sync + Clone>() {}
fn _asserts() {
    _assert_ctx_bounds::<Context>();
    fn _sync<T: Send + Sync>() {}
    _sync::<CtxPort>();
}

impl SdkPort for CtxPort {
    fn set_status(&self, key: &str, value: &str) {
        self.ctx.set_status(key, value);
    }

    /// Show: installs static rows with Go's options (placement
    /// `belowEditor`); clear: removes the key (renderer `None` clears — SDK
    /// contract). Go's `SetWidget(key, content, options)` maps onto the
    /// renderer form because it is push-based (no host round-trip mid-run)
    /// and carries options.
    fn set_widget(
        &self,
        key: &str,
        content: Option<Value>,
        options: Option<Value>,
    ) -> Result<(), String> {
        match content {
            Some(Value::Array(items)) => {
                let lines: Vec<String> = items
                    .iter()
                    .map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))
                    .collect();
                self.ctx
                    .set_widget_renderer(
                        key,
                        Some(move |_width: u32| lines.clone()),
                        options,
                    )
                    .map_err(|e| e.to_string())
            }
            _ => {
                let clear: Option<fn(u32) -> Vec<String>> = None;
                self.ctx.set_widget_renderer(key, clear, None).map_err(|e| e.to_string())
            }
        }
    }

    fn send_custom_message(&self, msg: CustomMessage, opts: SendOptions) -> Result<(), String> {
        let details = if msg.details.is_null() { None } else { Some(msg.details) };
        self.ctx
            .send_custom_message(
                &pig_sdk::CustomMessage {
                    custom_type: msg.custom_type,
                    content: Value::String(msg.content),
                    display: msg.display,
                    details,
                },
                &SendMessageOptions {
                    trigger_turn: Some(opts.trigger_turn),
                    deliver_as: Some(opts.deliver_as),
                },
            )
            .map_err(|e| e.to_string())
    }
}

/// The port for this call's retained context.
pub fn port_for(ctx: &Context) -> Arc<dyn SdkPort> {
    Arc::new(CtxPort { ctx: ctx.clone() })
}

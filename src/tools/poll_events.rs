use schemars::JsonSchema;
use serde::Deserialize;

/// Input for polling multiple event types simultaneously.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PollEventsInput {
    /// Listen for incoming job requests (default: true).
    #[schemars(description = "Listen for incoming job requests (default: true)")]
    pub listen_jobs: Option<bool>,

    /// NIP-90 job kind offsets to listen for (default: [100]).
    #[schemars(description = "Job kind offsets to listen for (default: [100])")]
    pub kind_offsets: Option<Vec<u16>>,

    /// Listen for private messages (default: true).
    #[schemars(description = "Listen for incoming private messages (default: true)")]
    pub listen_messages: Option<bool>,

    /// Payment request strings to monitor for settlement (checked every 5s).
    #[schemars(
        description = "Payment request strings to check periodically for settlement"
    )]
    pub pending_payments: Option<Vec<String>>,

    /// How long to wait in seconds (default: 60, max: 600).
    #[schemars(description = "Timeout in seconds (default: 60)")]
    pub timeout_secs: Option<u64>,
}

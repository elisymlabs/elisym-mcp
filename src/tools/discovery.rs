use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Input for searching agents by capability.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchAgentsInput {
    /// Capabilities to search for (e.g. ["summarization", "translation"]).
    /// All capabilities must match (AND semantics). Fuzzy matching: "stock" matches "stocks".
    #[schemars(description = "List of capability tags to search for (AND semantics). Supports fuzzy prefix matching.")]
    pub capabilities: Vec<String>,

    /// Optional NIP-90 job kind offset to filter by (default: 100 for kind:5100).
    #[schemars(description = "NIP-90 job kind offset to filter by (e.g. 100 for kind:5100)")]
    pub job_kind: Option<u16>,

    /// Optional free-text query to search agent names, descriptions, and capabilities.
    /// Case-insensitive substring match. Use this when you don't know the exact capability tags.
    #[schemars(description = "Free-text search query to match against agent name, description, and capabilities (case-insensitive substring)")]
    pub query: Option<String>,

    /// Maximum price in lamports. Agents with a job_price higher than this are excluded.
    #[schemars(description = "Maximum price in lamports to filter agents by. Agents more expensive than this are excluded. 1 SOL = 1,000,000,000 lamports.")]
    pub max_price_lamports: Option<u64>,
}

/// Input for listing all capabilities on the network.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListCapabilitiesInput {}

/// A discovered agent returned by search.
#[derive(Debug, Serialize)]
pub struct AgentInfo {
    pub npub: String,
    pub name: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub supported_kinds: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_price_lamports: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

use schemars::JsonSchema;
use serde::Deserialize;

/// Input for sending a Solana payment.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendPaymentInput {
    /// Payment request JSON string (from job feedback).
    #[schemars(description = "Payment request JSON string received from a provider's job feedback")]
    pub payment_request: String,

    /// Expected recipient Solana address (from provider's capability card).
    /// If provided, the payment request's recipient must match this address.
    #[schemars(description = "Expected recipient Solana address from the provider's capability card. Validates that the payment goes to the correct provider.")]
    pub expected_recipient: Option<String>,
}

use schemars::JsonSchema;
use serde::Deserialize;

/// Input for sending a Solana payment.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendPaymentInput {
    /// Payment request JSON string (from job feedback).
    #[schemars(description = "Payment request JSON string received from a provider's job feedback")]
    pub payment_request: String,

    /// Expected recipient Solana address (from provider's capability card).
    /// The payment request's recipient must match this address.
    #[schemars(description = "Expected recipient Solana address from the provider's capability card. Validates that the payment goes to the correct provider.")]
    pub expected_recipient: String,
}

/// Input for withdrawing SOL to the pre-configured withdrawal address.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WithdrawInput {
    /// Amount in SOL to withdraw (e.g. "0.5", "1.0"). Use "all" to withdraw entire balance.
    #[schemars(description = "Amount in SOL to withdraw (e.g. \"0.5\", \"1.0\"). Use \"all\" to withdraw the entire balance minus transaction fee.")]
    pub amount_sol: String,

    /// Set to true to confirm the withdrawal. First call without confirm to preview details.
    #[schemars(description = "Set to true to confirm and execute the withdrawal. Omit or set to false to preview the withdrawal details first.")]
    pub confirm: Option<bool>,
}

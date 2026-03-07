mod crypto;
mod install;
mod server;
mod tools;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use elisym_core::{
    AgentNodeBuilder, SolanaNetwork, SolanaPaymentConfig, SolanaPaymentProvider,
};
use rmcp::{ServiceExt, transport::stdio};
use serde::Deserialize;
use tracing_subscriber::{self, EnvFilter};

use server::ElisymServer;

/// elisym MCP server — AI agent discovery, marketplace, and payments via Nostr.
#[derive(Parser)]
#[command(name = "elisym-mcp", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Start HTTP transport instead of stdio (requires transport-http feature).
    #[arg(long)]
    http: bool,

    /// Host to bind HTTP server to (default: 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port for HTTP server (default: 8080).
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Bearer token for HTTP transport authentication.
    /// Can also be set via ELISYM_HTTP_TOKEN env var.
    #[arg(long)]
    http_token: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install elisym-mcp into MCP client configurations.
    Install {
        /// Target a specific client (claude-desktop, cursor, windsurf).
        #[arg(long)]
        client: Option<String>,

        /// Bind to an existing elisym agent (reads ~/.elisym/agents/<name>/config.toml).
        #[arg(long)]
        agent: Option<String>,

        /// Password to decrypt encrypted agent configs.
        #[arg(long)]
        password: Option<String>,

        /// Bearer token for HTTP transport authentication.
        #[arg(long)]
        http_token: Option<String>,

        /// Set additional env vars (KEY=VALUE, can be repeated).
        #[arg(long = "env", value_name = "KEY=VALUE")]
        extra_env: Vec<String>,

        /// List detected MCP clients and their status.
        #[arg(long)]
        list: bool,
    },

    /// Remove elisym-mcp from MCP client configurations.
    Uninstall {
        /// Target a specific client.
        #[arg(long)]
        client: Option<String>,
    },
}

/// Minimal subset of elisym-client's AgentConfig — just what we need.
#[derive(Deserialize)]
struct AgentConfig {
    name: String,
    description: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    payment: Option<PaymentSection>,
    #[serde(default)]
    encryption: Option<crypto::EncryptionSection>,
}

#[derive(Deserialize)]
struct PaymentSection {
    #[serde(default = "default_chain")]
    chain: String,
    #[serde(default = "default_network")]
    network: String,
    #[serde(default)]
    rpc_url: Option<String>,
    #[serde(default)]
    solana_secret_key: String,
}

fn default_chain() -> String {
    "solana".into()
}
fn default_network() -> String {
    "devnet".into()
}

fn load_agent_config(name: &str) -> Result<AgentConfig> {
    // Reject path traversal attempts (e.g. "../" or "/")
    anyhow::ensure!(
        !name.is_empty()
            && !name.contains('/')
            && !name.contains('\\')
            && name != "."
            && name != "..",
        "Invalid agent name: '{name}'"
    );
    let home = dirs::home_dir().context("Cannot find home directory")?;
    let path = home
        .join(".elisym")
        .join("agents")
        .join(name)
        .join("config.toml");

    // Warn if config file is readable by others (contains secret keys)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mode = meta.mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{mode:04o}"),
                    "Agent config file has insecure permissions (contains secret keys). \
                     Consider: chmod 600 {}",
                    path.display()
                );
            }
        }
    }

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Agent '{}' not found at {}", name, path.display()))?;
    let mut config: AgentConfig =
        toml::from_str(&contents).with_context(|| format!("Invalid config for agent '{}'", name))?;

    // Decrypt secrets if the config is encrypted
    if let Some(ref enc) = config.encryption {
        let password = std::env::var("ELISYM_AGENT_PASSWORD").with_context(|| {
            format!(
                "Agent '{}' has encrypted secrets. Set ELISYM_AGENT_PASSWORD env var to decrypt.",
                name
            )
        })?;
        let bundle = crypto::decrypt_secrets(enc, &password)
            .with_context(|| format!("Failed to decrypt secrets for agent '{}'", name))?;
        config.secret_key = bundle.nostr_secret_key;
        if let Some(ref mut payment) = config.payment {
            payment.solana_secret_key = bundle.solana_secret_key;
        }
        tracing::info!("Decrypted agent secrets");
    }

    Ok(config)
}

fn build_solana_provider(payment: &PaymentSection) -> Option<SolanaPaymentProvider> {
    if payment.chain != "solana" || payment.solana_secret_key.is_empty() {
        return None;
    }

    let network = match payment.network.as_str() {
        "mainnet" => SolanaNetwork::Mainnet,
        "testnet" => SolanaNetwork::Testnet,
        "devnet" => SolanaNetwork::Devnet,
        custom => SolanaNetwork::Custom(custom.to_string()),
    };

    let config = SolanaPaymentConfig {
        network,
        rpc_url: payment.rpc_url.clone(),
    };

    match SolanaPaymentProvider::from_secret_key(config, &payment.solana_secret_key) {
        Ok(provider) => {
            tracing::info!(address = %provider.address(), "Solana wallet configured");
            Some(provider)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize Solana wallet: {e}");
            None
        }
    }
}

fn list_agents() -> Vec<String> {
    let Some(home) = dirs::home_dir() else {
        return vec![];
    };
    let root = home.join(".elisym").join("agents");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return vec![];
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        if entry.path().join("config.toml").exists() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    names
}

#[cfg(feature = "transport-http")]
async fn start_http_server(
    agent: elisym_core::AgentNode,
    host: &str,
    port: u16,
    http_token: Option<String>,
) -> Result<()> {
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    };

    let agent = Arc::new(agent);
    let job_events = Arc::new(Mutex::new(HashMap::new()));

    let ct = tokio_util::sync::CancellationToken::new();
    let config = StreamableHttpServerConfig {
        stateful_mode: true,
        cancellation_token: ct.clone(),
        ..Default::default()
    };

    let agent_clone = Arc::clone(&agent);
    let job_events_clone = Arc::clone(&job_events);

    let service: StreamableHttpService<ElisymServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(ElisymServer::from_shared(
                Arc::clone(&agent_clone),
                Arc::clone(&job_events_clone),
            )),
            Default::default(),
            config,
        );

    let mut router = axum::Router::new().nest_service("/mcp", service);

    // Add bearer token auth middleware if configured
    if let Some(token) = http_token {
        use axum::http::StatusCode;

        let expected = format!("Bearer {token}");
        router = router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let expected = expected.clone();
                async move {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    // Note: not constant-time, but network jitter makes timing
                    // attacks impractical for a local/internal HTTP transport token.
                    if auth != expected {
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                    Ok(next.run(req).await)
                }
            },
        ));
        tracing::info!("HTTP bearer token authentication enabled");
    } else if host != "127.0.0.1" && host != "localhost" {
        tracing::warn!(
            "HTTP transport exposed on {host} without authentication. \
             Consider using --http-token for security."
        );
    }

    let bind_addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Cannot bind to {bind_addr}"))?;

    tracing::info!(address = %bind_addr, endpoint = "/mcp", "HTTP transport started");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutting down HTTP server");
            ct.cancel();
        })
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Install {
            client,
            agent,
            password,
            http_token: install_http_token,
            extra_env,
            list,
        }) => {
            if list {
                install::run_list();
            } else {
                let mut env = Vec::new();
                if let Some(ref pw) = password {
                    env.push(("ELISYM_AGENT_PASSWORD".to_string(), pw.clone()));
                }
                if let Some(ref tok) = install_http_token {
                    env.push(("ELISYM_HTTP_TOKEN".to_string(), tok.clone()));
                }
                for kv in &extra_env {
                    if let Some((k, v)) = kv.split_once('=') {
                        env.push((k.to_string(), v.to_string()));
                    } else {
                        anyhow::bail!("Invalid --env format: '{kv}'. Expected KEY=VALUE.");
                    }
                }
                install::run_install(client.as_deref(), agent.as_deref(), &env)?;
            }
            return Ok(());
        }
        Some(Commands::Uninstall { client }) => {
            install::run_uninstall(client.as_deref())?;
            return Ok(());
        }
        None => {}
    }

    // MCP server mode (default — no subcommand)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting elisym MCP server");

    let builder = if let Ok(agent_name) = std::env::var("ELISYM_AGENT") {
        let config = load_agent_config(&agent_name)?;
        tracing::info!(agent = %agent_name, "Loading agent from ~/.elisym/agents/");

        let mut b = AgentNodeBuilder::new(&config.name, &config.description)
            .capabilities(config.capabilities)
            .secret_key(&config.secret_key);

        if !config.relays.is_empty() {
            b = b.relays(config.relays);
        }

        if let Some(ref payment) = config.payment {
            if let Some(provider) = build_solana_provider(payment) {
                b = b.solana_payment_provider(provider);
            }
        }

        b
    } else {
        let agent_name =
            std::env::var("ELISYM_AGENT_NAME").unwrap_or_else(|_| "mcp-agent".into());
        let agent_desc = std::env::var("ELISYM_AGENT_DESCRIPTION")
            .unwrap_or_else(|_| "elisym MCP server agent".into());

        let mut b = AgentNodeBuilder::new(&agent_name, &agent_desc)
            .capabilities(vec!["mcp-gateway".into()]);

        if let Ok(key) = std::env::var("ELISYM_NOSTR_SECRET") {
            b = b.secret_key(key);
        } else {
            let agents = list_agents();
            if !agents.is_empty() {
                tracing::info!(
                    "Tip: set ELISYM_AGENT to reuse an existing agent identity. Available: {}",
                    agents.join(", ")
                );
            }
        }

        if let Ok(relays) = std::env::var("ELISYM_RELAYS") {
            let relay_list: Vec<String> =
                relays.split(',').map(|s| s.trim().to_string()).collect();
            if !relay_list.is_empty() {
                b = b.relays(relay_list);
            }
        }
        b
    };

    let agent = builder.build().await?;
    tracing::info!(
        npub = %agent.identity.npub(),
        payments = agent.payments.is_some(),
        "Agent node started"
    );

    if cli.http {
        #[cfg(feature = "transport-http")]
        {
            let http_token = cli
                .http_token
                .or_else(|| std::env::var("ELISYM_HTTP_TOKEN").ok());
            start_http_server(agent, &cli.host, cli.port, http_token).await?;
        }
        #[cfg(not(feature = "transport-http"))]
        {
            anyhow::bail!(
                "HTTP transport not available. Rebuild with: cargo build --features transport-http"
            );
        }
    } else {
        let server = ElisymServer::new(agent);
        let service = server
            .serve(stdio())
            .await
            .inspect_err(|e| tracing::error!("Failed to start MCP service: {e}"))?;

        service.waiting().await?;
    }

    tracing::info!("elisym MCP server stopped");
    Ok(())
}

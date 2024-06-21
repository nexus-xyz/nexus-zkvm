use nexus_api::config::{network::rpc::RpcConfig, Config};

use tracing::{level_filters::LevelFilter, Level};
use tracing_subscriber::{
    filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

#[tokio::main]
async fn main() {
    setup_logger();

    let config = RpcConfig::from_env().unwrap_or_default();
    nexus_rpc_server::run(config).await;
}

fn setup_logger() {
    let filter = filter::Targets::new()
        .with_target("jsonrpsee", Level::TRACE)
        .with_target("nexus-rpc", Level::TRACE)
        .with_target("r1cs", LevelFilter::OFF)
        .with_default(Level::WARN);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                .compact(),
        )
        .with(filter)
        .init()
}

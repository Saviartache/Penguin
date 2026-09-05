//! Bounded readiness checks for synchronous service-management commands.

use std::time::Duration;

use anyhow::{Context, Result};

/// Waits up to 15 seconds for a real IPC greeting, not just a running process.
///
/// Service-management callers run elevated; Unix IPC therefore probes the
/// system endpoint rather than a user's foreground daemon.
pub fn wait_until_ready() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not create readiness runtime")?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            while !penguin_ipc::client::answers_service().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("service did not answer IPC within 15 seconds; check the daemon log")
    })
}

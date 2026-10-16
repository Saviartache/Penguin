//! Ограниченное по времени ожидание готовности службы.

use std::time::Duration;

use anyhow::{Context, Result};

/// Ждёт до 15 с ответа по IPC (на Unix — системной конечной точки).
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

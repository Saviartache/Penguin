//! Ограниченное по времени ожидание готовности службы.

use std::time::Duration;

use anyhow::{Context, Result};

/// Сколько ждать ответа. launchd откладывает запуск задания после выгрузки прежнего (до 10 с
/// `ExitTimeOut` и столько же `ThrottleInterval`): за 15 с служба поднималась уже после отказа,
/// и пароль спрашивали второй раз.
const READY_WAIT: Duration = Duration::from_secs(30);

/// Ждёт ответа по IPC (на Unix — системной конечной точки).
pub fn wait_until_ready() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not create readiness runtime")?;
    runtime.block_on(async {
        tokio::time::timeout(READY_WAIT, async {
            while !penguin_ipc::client::answers_service().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .with_context(|| {
            format!(
                "service did not answer IPC within {} seconds; check the daemon log",
                READY_WAIT.as_secs()
            )
        })
    })
}

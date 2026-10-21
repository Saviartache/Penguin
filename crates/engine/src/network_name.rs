//! NLA регистрирует сеть позже появления виртуального адаптера.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

pub(crate) fn spawn(
    index: u32,
    base: String,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..30 {
            if cancel.is_cancelled() {
                return;
            }
            let name = base.clone();
            let result = tokio::task::spawn_blocking(move || {
                penguin_platform::network_name::rename(index, &name)
            })
            .await;
            match result {
                Ok(Ok(true)) => return,
                Ok(Ok(false)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "не удалось назначить имя сети");
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, "задача назначения имени сети прервана");
                    return;
                }
            }
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
        tracing::warn!(index, "NLA не зарегистрировала сеть за 30 секунд");
    })
}

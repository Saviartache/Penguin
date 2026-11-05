//! Свой i2pd для профилей `i2p`: поднимается до направления, гаснет с тоннелем.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use penguin_config::schema::profile::Profile;
use penguin_core::address::SocketAddress;
use penguin_i2pd::{I2pdError, Progress, Sidecar};
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::probe::{self, PROBE_TARGET, ProbeResult};

use crate::events::{Event, EventBus, LogLevel};

/// Сколько ждать первого потока: туннели до outproxy строятся десятками секунд.
const WARM_UP: Duration = Duration::from_secs(120);
const WARM_UP_ATTEMPT: Duration = Duration::from_secs(30);
const WARM_UP_PAUSE: Duration = Duration::from_secs(2);

/// Ходит ли профиль через i2pd.
pub(crate) fn needs_i2pd(profile: &Profile) -> bool {
    profile.outbound.protocol == penguin_i2p::PROTOCOL
}

/// Ждёт первого потока через outproxy: порт i2pd открыт раньше, чем готовы туннели,
/// и без этого «подключено» горело бы при молчащем трафике.
pub(crate) async fn warm_up(outbound: &dyn Outbound, events: &EventBus) {
    let Ok(target) = PROBE_TARGET.parse::<SocketAddress>() else {
        return;
    };
    events.emit(Event::Progress {
        message: "I2P: строится путь до outproxy".to_owned(),
    });
    let deadline = tokio::time::Instant::now() + WARM_UP;
    while tokio::time::Instant::now() < deadline {
        match probe::probe(outbound, &target, WARM_UP_ATTEMPT).await {
            ProbeResult::Alive(rtt) => {
                events.emit(Event::log(
                    LogLevel::Info,
                    format!("I2P: путь готов, задержка {} мс", rtt.millis),
                ));
                return;
            }
            ProbeResult::Timeout => {}
            ProbeResult::Rejected(message) => {
                tracing::debug!(%message, "I2P: путь ещё не готов");
                tokio::time::sleep(WARM_UP_PAUSE).await;
            }
        }
    }
    events.emit(Event::log(
        LogLevel::Warning,
        format!(
            "I2P: outproxy не ответил за {} с — трафик пойдёт, когда достроятся туннели",
            WARM_UP.as_secs()
        ),
    ));
}

/// i2pd службы; каталог задаёт она же ([`crate::Engine::use_i2pd`]).
#[derive(Debug, Default)]
pub(crate) struct I2pd(OnceLock<Sidecar>);

impl I2pd {
    /// Каталог i2pd; повторный вызов ничего не меняет.
    pub(crate) fn set_home(&self, home: PathBuf) {
        let _ = self.0.set(Sidecar::new(home));
    }

    /// Запускает i2pd, если профилю он нужен.
    pub(crate) async fn start_for(
        &self,
        profile: &Profile,
        direct: Arc<dyn Outbound>,
        events: &EventBus,
    ) -> Result<(), ProtocolError> {
        if !needs_i2pd(profile) {
            return Ok(());
        }
        let sidecar = self.sidecar().map_err(to_protocol)?;
        let report = |step: Progress| {
            let message = step.message();
            if step.is_warning() {
                events.emit(Event::log(LogLevel::Warning, message));
            } else {
                events.emit(Event::Progress { message });
            }
        };
        sidecar.start(direct, &report).await.map_err(to_protocol)
    }

    /// Останавливает i2pd, если он запущен.
    pub(crate) async fn stop(&self) {
        if let Some(sidecar) = self.0.get() {
            sidecar.stop().await;
        }
    }

    /// Ставит присланный файл i2pd.
    pub(crate) fn install(&self, bytes: &[u8]) -> Result<(), I2pdError> {
        self.sidecar()?.install(bytes)
    }

    fn sidecar(&self) -> Result<&Sidecar, I2pdError> {
        self.0.get().ok_or(I2pdError::NotInstalled)
    }
}

/// Без файла и с чужой суммой повторять бессмысленно; остальное — временное.
fn to_protocol(err: I2pdError) -> ProtocolError {
    match err {
        I2pdError::UnsupportedTarget
        | I2pdError::NotInstalled
        | I2pdError::ChecksumMismatch { .. }
        | I2pdError::NoAccount(_) => ProtocolError::InvalidConfig(err.to_string()),
        _ => ProtocolError::Connect(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_binary_is_not_retried_and_a_slow_start_is() {
        assert!(!to_protocol(I2pdError::NotInstalled).is_retryable());
        assert!(to_protocol(I2pdError::NotReady(90, PathBuf::new())).is_retryable());
    }
}

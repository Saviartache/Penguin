//! Профили: список, добавление, проверка задержки.

use std::sync::Arc;
use std::time::Duration;

use penguin_core::address::SocketAddress;
use penguin_core::id::{OutboundId, ProfileId};
use penguin_engine::Engine;
use penguin_ipc::schema::{ProbeResult, Response};
use penguin_proto::probe;

/// Отдаёт настройки.
pub fn get_config(engine: &Arc<Engine>) -> Response {
    Response::Config(Box::new((*engine.config()).clone()))
}

/// Принимает настройки: пишет на диск и применяет.
///
/// Порядок: проверка, запись, применение. Непроверенное нельзя применять
/// частично, а применённое без записи пропадёт после перезапуска.
pub fn set_config(
    engine: &Arc<Engine>,
    store: &penguin_config::ConfigStore,
    config: penguin_config::RootConfig,
) -> Response {
    if let Err(err) = penguin_config::validate::validate(&config) {
        return Response::error(err, true);
    }

    if let Err(err) = store.save(&config) {
        // Не записалось — не применяем
        tracing::error!(%err, "настройки не записаны");
        return Response::error(err, true);
    }

    // Журнал ведёт служба, а не движок
    crate::logging::set_level(config.app.log_level);

    match engine.reload(config) {
        Ok(()) => Response::Ok,
        Err(err) => {
            let needs_user_action = err.needs_user_action();
            Response::error(err, needs_user_action)
        }
    }
}

/// Сколько ждать ответа при проверке.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Сколько всего на один профиль: рукопожатие и замер.
const PROBE_DEADLINE: Duration = Duration::from_secs(10);

const NO_ANSWER: &str = "сервер не ответил";

/// Проверяет задержку до профилей.
///
/// Через сам протокол, а не `ping`: ICMP может ходить, пока QUIC режется.
pub async fn probe_profiles(engine: &Arc<Engine>, profile: Option<ProfileId>) -> Response {
    let config = engine.config();
    let profiles: Vec<_> = match &profile {
        Some(id) => config.profile(id).into_iter().collect(),
        None => config.profiles.iter().collect(),
    };

    if profiles.is_empty() {
        return Response::error("нет профилей для проверки", true);
    }

    let mut results = Vec::with_capacity(profiles.len());
    for profile in profiles {
        results.push(probe_one(engine, profile).await);
    }
    Response::Probes { results }
}

/// Проверяет один профиль.
async fn probe_one(
    engine: &Arc<Engine>,
    profile: &penguin_config::schema::profile::Profile,
) -> ProbeResult {
    let name = profile.id.to_string();

    // Сначала без сети: ошибка настроек видна мгновенно
    if let Err(err) = engine.outbounds().validate(profile) {
        return failed(name, err.to_string());
    }

    let id = OutboundId::from(profile.id.clone());
    let was_pooled = engine.outbounds().get(&id).is_some();

    let outcome = within(PROBE_DEADLINE, measure(engine, profile)).await;

    // Направление, поднятое ради замера, не копится в пуле
    if !was_pooled {
        engine.outbounds().close(&id).await;
    }

    match outcome {
        Ok(millis) => ProbeResult {
            profile: name,
            rtt_millis: Some(millis),
            error: None,
        },
        Err(message) => failed(name, message),
    }
}

fn failed(profile: String, message: String) -> ProbeResult {
    ProbeResult {
        profile,
        rtt_millis: None,
        error: Some(message),
    }
}

/// Не даёт зависшему подключению держать очередь.
async fn within(
    deadline: Duration,
    work: impl Future<Output = Result<u32, String>>,
) -> Result<u32, String> {
    tokio::time::timeout(deadline, work)
        .await
        .unwrap_or_else(|_| Err(NO_ANSWER.to_owned()))
}

/// Подключается (если надо) и меряет задержку.
async fn measure(
    engine: &Arc<Engine>,
    profile: &penguin_config::schema::profile::Profile,
) -> Result<u32, String> {
    let outbound = engine
        .outbounds()
        .get_or_connect(profile)
        .await
        .map_err(|err| err.to_string())?;

    let target: SocketAddress = probe::PROBE_TARGET
        .parse()
        .unwrap_or_else(|_| SocketAddress::domain("cp.cloudflare.com", 80));

    match probe::probe(outbound.as_ref(), &target, PROBE_TIMEOUT).await {
        probe::ProbeResult::Alive(rtt) => Ok(rtt.millis),
        probe::ProbeResult::Timeout => Err(NO_ANSWER.to_owned()),
        probe::ProbeResult::Rejected(message) => Err(message),
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::RootConfig;

    use super::*;

    fn engine() -> Arc<Engine> {
        Engine::new(RootConfig::default()).expect("движок собирается")
    }

    /// Настоящее хранилище во временном каталоге.
    fn store(tag: &str) -> penguin_config::ConfigStore {
        let dir =
            std::env::temp_dir().join(format!("penguin-handler-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        penguin_config::ConfigStore::new(penguin_config::Paths::rooted(dir))
    }

    #[test]
    fn config_comes_back_whole() {
        let Response::Config(config) = get_config(&engine()) else {
            panic!("не тот ответ")
        };
        assert_eq!(config.version, penguin_config::SCHEMA_VERSION);
    }

    #[test]
    fn broken_config_is_refused_before_applying() {
        let engine = engine();
        let mut config = RootConfig::default();
        config.network.tun.mtu = 9000;

        let store = store("broken");
        assert!(set_config(&engine, &store, config).is_error());
        assert!(
            !store.paths().config_file().exists(),
            "негодные настройки всё-таки записались"
        );
    }

    #[test]
    fn good_config_is_accepted() {
        let store = store("good");
        assert!(!set_config(&engine(), &store, RootConfig::default()).is_error());
    }

    #[test]
    fn accepted_settings_reach_the_disk() {
        let store = store("saved");
        let mut config = RootConfig::default();
        config.network.kill_switch = false;

        assert!(!set_config(&engine(), &store, config).is_error());

        let back = store.load().expect("записанное читается");
        assert!(!back.network.kill_switch, "правка не дошла до файла");

        let _ = std::fs::remove_dir_all(store.paths().config_dir());
    }

    #[tokio::test]
    async fn probing_without_profiles_says_so() {
        assert!(probe_profiles(&engine(), None).await.is_error());
    }

    #[tokio::test]
    async fn a_hung_connection_gives_up_at_the_deadline() {
        let outcome = within(Duration::from_millis(20), std::future::pending()).await;
        assert_eq!(outcome, Err(NO_ANSWER.to_owned()));
    }

    #[tokio::test]
    async fn work_within_the_deadline_keeps_its_result() {
        let outcome = within(Duration::from_secs(1), async { Ok(7) }).await;
        assert_eq!(outcome, Ok(7));
    }

    #[test]
    fn probe_target_parses() {
        assert!(probe::PROBE_TARGET.parse::<SocketAddress>().is_ok());
    }
}

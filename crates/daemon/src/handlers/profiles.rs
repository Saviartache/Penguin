//! Профили: список, добавление, проверка задержки.

use std::sync::Arc;
use std::time::Duration;

use penguin_core::address::SocketAddress;
use penguin_core::id::ProfileId;
use penguin_engine::Engine;
use penguin_ipc::schema::{ProbeResult, Response};
use penguin_proto::probe;

/// Отдаёт настройки.
pub fn get_config(engine: &Arc<Engine>) -> Response {
    Response::Config(Box::new((*engine.config()).clone()))
}

/// Принимает настройки: пишет на диск и применяет.
///
/// Порядок именно такой, и он важен дважды.
///
/// **Проверка до всего.** Применить половину правил хуже, чем не применить ни
/// одного: трафик пошёл бы не туда, а пользователь считал бы, что настройки в
/// силе.
///
/// **Запись до применения.** Настройки, применённые, но не записанные, живут
/// до перезапуска службы — и «Сохранить» в окне перестаёт что-либо сохранять.
/// Заметить это можно только через неделю, когда служба перезапустится сама.
pub fn set_config(
    engine: &Arc<Engine>,
    store: &penguin_config::ConfigStore,
    config: penguin_config::RootConfig,
) -> Response {
    if let Err(err) = penguin_config::validate::validate(&config) {
        return Response::error(err, true);
    }

    if let Err(err) = store.save(&config) {
        // Не записалось — не применяем. Иначе окно показывало бы одно, файл
        // содержал бы другое, а после перезапуска вернулось бы третье.
        tracing::error!(%err, "настройки не записаны");
        return Response::error(err, true);
    }

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

/// Проверяет задержку до профилей.
///
/// Через сам протокол, а не `ping`: ICMP до сервера может ходить прекрасно,
/// пока QUIC на нужном порту режется. Проверка должна мерить то, чем потом
/// пойдёт трафик.
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

    // Проверка настроек идёт первой и без сети: неверная конфигурация
    // выясняется мгновенно, а неудачное подключение — за секунды.
    if let Err(err) = engine.outbounds().validate(profile) {
        return ProbeResult {
            profile: name,
            rtt_millis: None,
            error: Some(err.to_string()),
        };
    }

    let outbound = match engine.outbounds().get_or_connect(profile).await {
        Ok(outbound) => outbound,
        Err(err) => {
            return ProbeResult {
                profile: name,
                rtt_millis: None,
                error: Some(err.to_string()),
            };
        }
    };

    let target: SocketAddress = probe::PROBE_TARGET
        .parse()
        .unwrap_or_else(|_| SocketAddress::domain("cp.cloudflare.com", 80));

    match probe::probe(outbound.as_ref(), &target, PROBE_TIMEOUT).await {
        probe::ProbeResult::Alive(rtt) => ProbeResult {
            profile: name,
            rtt_millis: Some(rtt.millis),
            error: None,
        },
        probe::ProbeResult::Timeout => ProbeResult {
            profile: name,
            rtt_millis: None,
            error: Some("сервер не ответил".to_owned()),
        },
        probe::ProbeResult::Rejected(message) => ProbeResult {
            profile: name,
            rtt_millis: None,
            error: Some(message),
        },
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::RootConfig;

    use super::*;

    fn engine() -> Arc<Engine> {
        Engine::new(RootConfig::default()).expect("движок собирается")
    }

    /// Хранилище в отдельном временном каталоге.
    ///
    /// Настоящее, а не заглушка: половина смысла `set_config` в том, что
    /// настройки доходят до диска, и проверить это можно только диском.
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
        // Применить половину правил хуже, чем не применить ни одного.
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
        // Настройки, применённые, но не записанные, живут до перезапуска
        // службы — и «Сохранить» в окне перестаёт что-либо сохранять.
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

    #[test]
    fn probe_target_parses() {
        // Адрес проверки зашит в контракте протокола; опечатка в нём
        // сломала бы измерение задержки у всех профилей сразу.
        assert!(probe::PROBE_TARGET.parse::<SocketAddress>().is_ok());
    }
}

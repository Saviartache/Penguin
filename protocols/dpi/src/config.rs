//! Настройки режима: только план обхода, больше здесь ничего нет.

use penguin_transport::desync::{Desync, DesyncConfig, Strategy};
use penguin_transport::error::{TransportError, TransportResult};
use serde::{Deserialize, Serialize};

/// Стратегия нового профиля.
///
/// Разрез посреди имени узла: самое безобидное из действенного — лишних
/// пакетов не появляется вовсе, меняется только граница сегментов.
const DEFAULT_STRATEGY: Strategy = Strategy::Multisplit;

/// Настройки режима DPI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DpiConfig {
    /// План обхода. Раздел общий с остальными протоколами.
    pub desync: DesyncConfig,
}

impl Default for DpiConfig {
    fn default() -> Self {
        Self {
            desync: DesyncConfig {
                strategy: DEFAULT_STRATEGY.name().to_owned(),
                ..DesyncConfig::default()
            },
        }
    }
}

impl DpiConfig {
    /// Проверяет настройки и собирает план.
    ///
    /// Отвергается больше, чем у обычного протокола, и по одной причине: на
    /// том конце здесь не наш сервер, а сайт, который о нас не знает
    /// (см. документ крейта).
    pub fn plan(&self) -> TransportResult<Desync> {
        let plan = self.desync.compile()?;
        match plan.strategy() {
            Strategy::None => Err(TransportError::config(
                "режим DPI без обхода — это обычное прямое соединение: выберите multisplit или disorder",
            )),
            Strategy::Fake | Strategy::FakedSplit => Err(TransportError::config(format!(
                "стратегия `{}` шлёт ложное приветствие, а принял бы его сам сайт и оборвал соединение: в режиме DPI бывают multisplit и disorder",
                plan.strategy().name()
            ))),
            _ => Ok(plan),
        }
    }

    /// Проверяет настройки, ничего не собирая.
    pub fn validate(&self) -> TransportResult<()> {
        self.plan().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(strategy: &str) -> DpiConfig {
        DpiConfig {
            desync: DesyncConfig {
                strategy: strategy.to_owned(),
                ..DesyncConfig::default()
            },
        }
    }

    #[test]
    fn a_new_profile_already_bypasses_something() {
        // Умолчание «ничего не делать» превратило бы режим в прямое
        // соединение с лишним именем в списке протоколов.
        let plan = DpiConfig::default().plan().expect("настройки верны");
        assert_eq!(plan.strategy(), DEFAULT_STRATEGY);
    }

    #[test]
    fn the_strategies_that_need_a_decoy_are_refused_by_name() {
        // Молча превратить их в «ничего не делать» значило бы показать
        // настроенный обход там, где обхода нет.
        for strategy in ["fake", "fakedsplit"] {
            let err = config(strategy)
                .plan()
                .expect_err("ложную посылку тут послать некому");
            assert!(err.to_string().contains(strategy), "{strategy}");
        }
    }

    #[test]
    fn a_mode_without_a_bypass_is_refused() {
        assert!(config("none").plan().is_err());
    }

    #[test]
    fn both_working_strategies_compile() {
        for strategy in ["multisplit", "disorder"] {
            config(strategy).plan().expect("настройки верны");
        }
    }

    #[test]
    fn an_unknown_strategy_is_reported_by_the_transport() {
        assert!(config("multi-split").plan().is_err());
    }

    #[test]
    fn the_settings_section_is_the_usual_one() {
        // Раздел тот же, что у `pingwin`: человек, знающий один, читает и
        // второй.
        let config: DpiConfig = serde_json::from_value(serde_json::json!({
            "desync": { "strategy": "disorder", "split_pos": ["midsld"], "delay_ms": 2 }
        }))
        .expect("разбирается");
        let plan = config.plan().expect("настройки верны");
        assert_eq!(plan.strategy(), Strategy::Disorder);
        assert_eq!(plan.delay(), std::time::Duration::from_millis(2));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // Опечатка в имени поля — это профиль, который выглядит настроенным.
        assert!(
            serde_json::from_value::<DpiConfig>(serde_json::json!({ "server": "example.com:443" }))
                .is_err()
        );
    }
}

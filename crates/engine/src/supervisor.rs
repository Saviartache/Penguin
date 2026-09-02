//! Переподключение с задержкой, проверка живости, деградация к прямому
//! выходу.
//!
//! Соединение рвётся: сеть моргнула, ноутбук проснулся, провайдер сбросил
//! сессию. Клиент обязан подняться сам — но не любой ценой.
//!
//! ```text
//!   обрыв ──► пауза 1 с ──► попытка ──► обрыв ──► пауза 2 с ──► …
//!                                                   до 30 с
//! ```
//!
//! Задержка удваивается: сеть, которой нет, не появится оттого, что её
//! спрашивают чаще, а сервер, который отказывает, от настойчивости не
//! подобреет. Потолок нужен, чтобы после долгого сна ноутбука клиент поднялся
//! за секунды, а не за минуты.
//!
//! И главное — повторяется не всё. Неверный пароль повторять бессмысленно, и
//! попытка номер сорок с тем же паролем ничем не отличается от первой.

use std::time::Duration;

use penguin_core::time::backoff;
use penguin_proto::error::ProtocolError;

/// Наименьшая пауза.
pub const MIN_DELAY: Duration = Duration::from_secs(1);

/// Наибольшая пауза.
///
/// Тридцать секунд: дольше означает, что проснувшийся ноутбук полминуты сидит
/// без тоннеля, хотя сеть уже есть.
pub const MAX_DELAY: Duration = Duration::from_secs(30);

/// Сколько попыток до сдачи.
///
/// `None` — бесконечно. Так и надо для восстановимых ошибок: клиент,
/// переставший пытаться, хуже клиента, который пытается медленно.
pub const MAX_ATTEMPTS: Option<u32> = None;

/// Что делать после неудачи.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Подождать и попробовать снова.
    Retry {
        /// Сколько ждать.
        delay: Duration,
        /// Какая это будет попытка.
        attempt: u32,
    },
    /// Сдаться: сама по себе такая ошибка не пройдёт.
    GiveUp {
        /// Что сказать пользователю.
        reason: String,
    },
}

/// Решает, повторять ли попытку.
///
/// Свободная функция без состояния: всё, что нужно для решения, — ошибка и
/// номер попытки. Отдельно проверяется тестами, не поднимая соединения.
pub fn decide(error: &ProtocolError, attempt: u32) -> Decision {
    if !error.is_retryable() {
        // Неверный пароль, неразбираемая конфигурация, неподдерживаемая
        // возможность — попытка номер сорок ничем не отличается от первой.
        return Decision::GiveUp {
            reason: error.to_string(),
        };
    }

    if let Some(limit) = MAX_ATTEMPTS
        && attempt >= limit
    {
        return Decision::GiveUp {
            reason: format!("не удалось подключиться за {limit} попыток: {error}"),
        };
    }

    Decision::Retry {
        delay: backoff(attempt, MIN_DELAY, MAX_DELAY),
        attempt: attempt + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_errors_are_retried_with_growing_delay() {
        let error = ProtocolError::Disconnected("сеть пропала".to_owned());

        let Decision::Retry { delay, attempt } = decide(&error, 0) else {
            panic!("обрыв сети обязан повторяться");
        };
        assert_eq!(delay, MIN_DELAY);
        assert_eq!(attempt, 1);

        let Decision::Retry { delay, .. } = decide(&error, 3) else {
            panic!("обрыв сети обязан повторяться");
        };
        assert!(delay > MIN_DELAY, "задержка не растёт");
    }

    #[test]
    fn delay_is_capped() {
        // Проснувшийся ноутбук не должен полминуты сидеть без тоннеля.
        let error = ProtocolError::Connect("нет маршрута".to_owned());
        let Decision::Retry { delay, .. } = decide(&error, 100) else {
            panic!("обязано повторяться");
        };
        assert_eq!(delay, MAX_DELAY);
    }

    #[test]
    fn wrong_password_is_not_retried() {
        // Попытка номер сорок с тем же паролем ничем не отличается от первой.
        let Decision::GiveUp { reason } = decide(&ProtocolError::AuthRejected, 0) else {
            panic!("неверный пароль повторять нельзя");
        };
        assert!(
            reason.contains("аутентификацию"),
            "причина невнятна: {reason}"
        );
    }

    #[test]
    fn broken_config_is_not_retried() {
        let error = ProtocolError::InvalidConfig("не задан пароль".to_owned());
        assert!(matches!(decide(&error, 0), Decision::GiveUp { .. }));
    }

    #[test]
    fn unsupported_feature_is_not_retried() {
        assert!(matches!(
            decide(&ProtocolError::Unsupported("UDP"), 0),
            Decision::GiveUp { .. }
        ));
    }

    #[test]
    fn retries_are_endless_for_recoverable_errors() {
        // Клиент, переставший пытаться, хуже клиента, который пытается
        // медленно: пользователь вернулся к столу и ждёт работающего тоннеля.
        let error = ProtocolError::Disconnected("сеть пропала".to_owned());
        for attempt in [0u32, 10, 100, 10_000] {
            assert!(
                matches!(decide(&error, attempt), Decision::Retry { .. }),
                "сдались на попытке {attempt}"
            );
        }
    }

    #[test]
    fn huge_attempt_number_does_not_overflow() {
        let error = ProtocolError::Connect("нет сети".to_owned());
        let Decision::Retry { delay, attempt } = decide(&error, u32::MAX - 1) else {
            panic!("обязано повторяться");
        };
        assert_eq!(delay, MAX_DELAY);
        assert_eq!(attempt, u32::MAX);
    }
}

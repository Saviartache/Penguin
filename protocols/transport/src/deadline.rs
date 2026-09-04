//! Срок на рукопожатие.
//!
//! Прокси, принявший соединение и замолчавший, держит поток приложения
//! вечно. Пока протоколов было четыре, это выглядело мелочью; с двадцатью
//! шестью у каждого своё рукопожатие, и каждое умеет зависнуть.
//!
//! Срок ставится на **всё, что происходит до первого байта приложения**:
//! приветствие, проверку подлинности, рукопожатие TLS, ответ на `CONNECT`.
//! На сам обмен данными срок не ставится — соединение, по которому молчат
//! обе стороны, это не ошибка, а открытая вкладка.
//!
//! Отдельная обёртка, а не голый [`tokio::time::timeout`], ради ответа:
//! `Io(TimedOut)` выше по стеку неотличим от «сервер закрыл соединение», а
//! [`TransportError::Timeout`] говорит, **что именно** не уложилось, и
//! попадает в повторяемые ошибки — молчащий сервер лечится повторной
//! попыткой.

use std::future::Future;
use std::time::Duration;

use crate::error::TransportError;

/// Сколько ждать рукопожатия, если протокол не сказал иначе.
///
/// Десять секунд — это заметно больше любого разумного обмена парой пакетов
/// даже на плохой линии и заметно меньше того, что человек готов ждать,
/// глядя на «Подключение».
pub const DEFAULT: Duration = Duration::from_secs(10);

/// Выполняет рукопожатие с ограничением по времени.
///
/// `what` — что именно делалось; оно попадает в текст ошибки, поэтому пишется
/// так, как читается в строке: «рукопожатие TLS не уложилось в срок».
///
/// Ошибка возвращается **в языке зовущего**, а не в языке транспорта: у
/// каждого протокола своё перечисление, и превращать всё, что через него
/// прошло, в `TransportError` значило бы терять `AuthRejected` ровно там, где
/// от него зависит, повторит ли `supervisor` попытку. Отсюда требование
/// `E: From<TransportError>` — один вариант в перечислении протокола, и срок
/// говорит на его языке.
pub async fn within<T, E>(
    limit: Duration,
    what: &'static str,
    work: impl Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    E: From<TransportError>,
{
    match tokio::time::timeout(limit, work).await {
        Ok(done) => done,
        Err(_elapsed) => Err(E::from(TransportError::Timeout(what))),
    }
}

/// То же самое со сроком по умолчанию.
pub async fn handshake<T, E>(
    what: &'static str,
    work: impl Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    E: From<TransportError>,
{
    within(DEFAULT, what, work).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn work_that_finishes_in_time_passes_through() {
        let value = within(DEFAULT, "проверка", async {
            Ok::<_, TransportError>(7)
        })
        .await
        .expect("успело");
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn a_silent_server_gives_up_with_a_name() {
        // Текст ошибки называет шаг: «не уложилось в срок» без указания, что
        // именно, не отвечает на вопрос, куда смотреть.
        let err = within(Duration::from_millis(1), "рукопожатие TLS", async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<(), TransportError>(())
        })
        .await
        .expect_err("не успело");

        assert!(matches!(err, TransportError::Timeout("рукопожатие TLS")));
    }

    #[tokio::test]
    async fn a_real_failure_is_not_disguised_as_a_timeout() {
        // Ошибка, случившаяся вовремя, обязана дойти как есть: иначе
        // «неверный пароль» превратится в «повторяем бесконечно».
        let err = within(DEFAULT, "проверка", async {
            Err::<(), _>(TransportError::malformed("не то"))
        })
        .await
        .expect_err("ошибка");

        assert!(matches!(err, TransportError::Malformed(_)));
    }
}

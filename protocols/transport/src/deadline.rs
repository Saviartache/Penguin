//! Срок на рукопожатие.
//!
//! Срок на всё до первого байта приложения (приветствие, TLS, `CONNECT`); на обмен данными срока нет.
//! [`TransportError::Timeout`] называет шаг и повторяем, в отличие от `Io(TimedOut)`.

use std::future::Future;
use std::time::Duration;

use crate::error::TransportError;

/// Срок рукопожатия по умолчанию.
pub const DEFAULT: Duration = Duration::from_secs(10);

/// Выполняет рукопожатие с ограничением по времени; `what` попадает в текст ошибки.
/// Ошибка в типе зовущего (`E: From<TransportError>`), чтобы не терять `AuthRejected`.
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
        let err = within(DEFAULT, "проверка", async {
            Err::<(), _>(TransportError::malformed("не то"))
        })
        .await
        .expect_err("ошибка");

        assert!(matches!(err, TransportError::Malformed(_)));
    }
}

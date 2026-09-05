//! Ответ сервера: один байт, а при отказе ещё код и текст.
//!
//! ```text
//!  0x00  тоннель открыт, дальше идут данные
//!  0x02  отказ: [код][длина текста][текст]
//! ```
//!
//! Ответ приходит **не сразу**: сервер шлёт его, когда соединится с адресом
//! назначения. Поэтому ждать его перед отправкой данных нельзя — это стоило
//! бы лишнего оборота до сервера на каждое соединение. Он снимается при
//! первом чтении, и тогда же отказ становится ошибкой.
//!
//! У канала датаграмм тот же ответ означает «готов принимать», и там его
//! читают сразу: посылать датаграммы в неоткрытый канал незачем.

use crate::error::{SnellError, SnellResult};

/// Тоннель открыт.
pub const TUNNEL: u8 = 0x00;

/// Ответ на проверку живости. Мы её не шлём, но получить обязаны разобрать.
pub const PONG: u8 = 0x01;

/// Отказ.
pub const ERROR: u8 = 0x02;

/// Что ответил сервер.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Тоннель открыт, дальше данные.
    Tunnel,
    /// Ответ на проверку живости.
    Pong,
    /// Отказ с объяснением.
    Refused {
        /// Код, который назвал сервер.
        code: u8,
        /// Текст, который он приложил.
        message: String,
    },
}

/// Читает ответ с начала среза.
///
/// Возвращает ответ и число съеденных байт: за ответом сразу идут данные, и
/// звать длину заново пришлось бы тем же разбором.
///
/// `Ok(None)` — байт пока не хватает. Это не ошибка: ответ мог прийти не
/// целиком, и отличать «неполно» от «сломано» обязан тот, кто читает.
pub fn decode(bytes: &[u8]) -> SnellResult<Option<(Reply, usize)>> {
    let Some((&command, rest)) = bytes.split_first() else {
        return Ok(None);
    };

    match command {
        TUNNEL => Ok(Some((Reply::Tunnel, 1))),
        PONG => Ok(Some((Reply::Pong, 1))),
        ERROR => {
            let (Some(&code), Some(&len)) = (rest.first(), rest.get(1)) else {
                return Ok(None);
            };
            let len = usize::from(len);
            let Some(text) = rest.get(2..2 + len) else {
                return Ok(None);
            };
            Ok(Some((
                Reply::Refused {
                    code,
                    message: String::from_utf8_lossy(text).into_owned(),
                },
                1 + 2 + len,
            )))
        }
        other => Err(SnellError::malformed(format!(
            "сервер ответил {other:#04x}: так отвечает не Snell или не эта его версия"
        ))),
    }
}

impl Reply {
    /// Превращает отказ в ошибку, а остальное — в успех.
    pub fn into_result(self) -> SnellResult<()> {
        match self {
            Self::Tunnel | Self::Pong => Ok(()),
            Self::Refused { code, message } => Err(SnellError::Refused { code, message }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_tunnel_is_one_byte() {
        let (reply, used) = decode(&[TUNNEL, b'd', b'a'])
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(reply, Reply::Tunnel);
        assert_eq!(used, 1, "съедены данные за ответом");
    }

    #[test]
    fn a_refusal_carries_its_reason() {
        let mut wire = vec![ERROR, 7, 5];
        wire.extend_from_slice(b"no dns");
        let (reply, used) = decode(&wire).expect("разбирается").expect("целиком");

        assert_eq!(used, 3 + 5, "съедено не то, что объявлено длиной");
        assert_eq!(
            reply,
            Reply::Refused {
                code: 7,
                message: "no dn".to_owned()
            }
        );
    }

    #[test]
    fn a_refusal_becomes_an_error_and_keeps_the_text() {
        let reply = Reply::Refused {
            code: 3,
            message: "connection refused".to_owned(),
        };
        let err = reply.into_result().expect_err("это отказ");
        assert!(err.to_string().contains("connection refused"), "{err}");
        assert!(err.to_string().contains("код 3"), "{err}");
    }

    #[test]
    fn a_half_read_reply_is_not_an_error() {
        // Ответ мог прийти не целиком: путать «неполно» и «сломано» значит
        // рвать живое соединение.
        let mut wire = vec![ERROR, 1, 4];
        wire.extend_from_slice(b"abcd");
        for cut in 0..wire.len() {
            assert!(
                decode(&wire[..cut]).expect("не сломано").is_none(),
                "обрезанный до {cut} байт ответ разобрался целиком"
            );
        }
    }

    #[test]
    fn an_answer_nobody_speaks_is_reported() {
        // Чаще всего это неверная версия: сервер расшифровал наш заголовок
        // другим шифром и ответил чем попало.
        let err = decode(&[0x42]).expect_err("не тот ответ");
        assert!(err.to_string().contains("не эта его версия"), "{err}");
    }

    #[test]
    fn a_refusal_without_a_message_is_still_a_refusal() {
        let (reply, used) = decode(&[ERROR, 9, 0])
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(used, 3);
        assert_eq!(
            reply,
            Reply::Refused {
                code: 9,
                message: String::new()
            }
        );
    }
}

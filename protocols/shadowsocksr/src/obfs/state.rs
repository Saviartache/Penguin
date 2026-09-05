//! Состояние надстройки `obfs` на одно соединение и выбор между вариантами.

use bytes::BytesMut;

use crate::error::ShadowsocksrResult;
use crate::obfs::http_simple::HttpSimpleState;
use crate::obfs::method::ObfsMethod;

/// Обёртка над шифротекстом на время одного соединения.
///
/// Живёт на внешней стороне кадра: видит уже зашифрованные байты и ничего не
/// знает ни про пароль, ни про адрес назначения — только про то, как это
/// должно выглядеть снаружи.
pub(crate) enum ObfsState {
    Plain,
    HttpSimple(HttpSimpleState),
}

impl ObfsState {
    /// Заводит состояние для одного соединения.
    ///
    /// `head_size` — IV шифра плюс точная длина закодированного адреса
    /// назначения; используется только надстройками, которым важно, сколько
    /// байт в начале потока выглядит «содержательно» (сейчас — `http_simple`).
    pub(crate) fn new(
        method: ObfsMethod,
        host: String,
        port: u16,
        param: Option<String>,
        head_size: usize,
    ) -> Self {
        match method {
            ObfsMethod::Plain => Self::Plain,
            ObfsMethod::HttpSimple => {
                Self::HttpSimple(HttpSimpleState::new(host, port, param, head_size))
            }
        }
    }

    /// Оборачивает исходящий шифротекст перед отправкой в сокет.
    pub(crate) fn client_encode(&mut self, buf: &[u8]) -> Vec<u8> {
        match self {
            Self::Plain => buf.to_vec(),
            Self::HttpSimple(state) => state.client_encode(buf),
        }
    }

    /// Снимает обёртку с байтов, только что пришедших из сокета.
    ///
    /// `incoming` очищается: то, что не удалось разобрать целиком (например,
    /// заголовки ответа `http_simple`, ещё не дочитанные до конца), остаётся
    /// в собственном буфере надстройки, а не теряется и не блокирует чтение.
    pub(crate) fn client_decode(&mut self, incoming: &mut BytesMut) -> ShadowsocksrResult<Vec<u8>> {
        match self {
            Self::Plain => Ok(std::mem::take(incoming).to_vec()),
            Self::HttpSimple(state) => state.client_decode(incoming),
        }
    }

    /// Остались ли непрочитанные до конца заголовки ответа.
    ///
    /// У `plain` заголовков нет вовсе, поэтому оборвать здесь нечего.
    pub(crate) fn has_pending_data(&self) -> bool {
        match self {
            Self::Plain => false,
            Self::HttpSimple(state) => state.has_pending_header(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_passes_bytes_through_untouched() {
        let mut state = ObfsState::new(ObfsMethod::Plain, "example.com".into(), 8388, None, 0);
        assert_eq!(state.client_encode(b"hello"), b"hello");

        let mut incoming = BytesMut::from(&b"world"[..]);
        assert_eq!(state.client_decode(&mut incoming).unwrap(), b"world");
        assert!(
            incoming.is_empty(),
            "прочитанное должно быть снято с буфера"
        );
    }

    #[test]
    fn http_simple_is_selected_by_method() {
        let mut state = ObfsState::new(ObfsMethod::HttpSimple, "example.com".into(), 8388, None, 0);
        let out = state.client_encode(b"x");
        assert!(
            out.starts_with(b"GET /"),
            "{}",
            String::from_utf8_lossy(&out)
        );
    }
}

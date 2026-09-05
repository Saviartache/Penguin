//! Состояние надстройки `protocol` на одно соединение и выбор между
//! вариантами.

use crate::error::ShadowsocksrResult;
use crate::protocol::auth_aes128::{AuthAes128State, HashKind};
use crate::protocol::client_id::AuthHeader;
use crate::protocol::method::ProtocolMethod;

/// Кадрирование поверх потокового шифра на время одного соединения.
///
/// Живёт на внутренней стороне кадра: получает открытый текст ещё до шифра
/// (`client_pre_encrypt`) и отдаёт его туда же после расшифровки
/// (`client_post_decrypt`). Про адрес сервера или пароль не знает — только
/// главный ключ и IV этого соединения, переданные при постройке.
pub(crate) enum ProtocolState {
    /// Без надстройки: открытый текст и есть кадр, как у обычного
    /// Shadowsocks.
    Origin,
    AuthAes128(AuthAes128State),
}

impl ProtocolState {
    /// Заводит состояние для одного соединения.
    pub(crate) fn new(method: ProtocolMethod, user_key: Vec<u8>, cipher_iv: Vec<u8>) -> Self {
        match method {
            ProtocolMethod::Origin => Self::Origin,
            ProtocolMethod::AuthAes128Md5 => {
                Self::AuthAes128(AuthAes128State::new(HashKind::Md5, user_key, cipher_iv))
            }
            ProtocolMethod::AuthAes128Sha1 => {
                Self::AuthAes128(AuthAes128State::new(HashKind::Sha1, user_key, cipher_iv))
            }
        }
    }

    /// Оборачивает открытый текст перед тем, как его зашифрует [`crate::crypto`].
    ///
    /// `head_size` и `header` нужны только `auth_*`: первый — сколько байт
    /// уйдёт в разовый заголовок соединения, второй — сам заголовок
    /// (метка времени, `client_id`, `connection_id`). `header` обязателен
    /// при первом вызове на соединении и игнорируется в остальных.
    pub(crate) fn client_pre_encrypt(
        &mut self,
        buf: &[u8],
        head_size: usize,
        header: Option<AuthHeader>,
    ) -> ShadowsocksrResult<Vec<u8>> {
        match self {
            Self::Origin => Ok(buf.to_vec()),
            Self::AuthAes128(state) => state.client_pre_encrypt(buf, head_size, header),
        }
    }

    /// Снимает кадрирование с только что расшифрованных байт ответа.
    pub(crate) fn client_post_decrypt(&mut self, incoming: &[u8]) -> ShadowsocksrResult<Vec<u8>> {
        match self {
            Self::Origin => Ok(incoming.to_vec()),
            Self::AuthAes128(state) => state.client_post_decrypt(incoming),
        }
    }

    /// Нужен ли этому варианту заголовок `auth_data` на новое соединение.
    pub(crate) fn needs_auth_header(&self) -> bool {
        matches!(self, Self::AuthAes128(_))
    }

    /// Остался ли в буфере кусок кадра, не дождавшийся продолжения.
    ///
    /// У `origin` кадрирования нет вовсе, поэтому оборвать здесь нечего.
    pub(crate) fn has_pending_data(&self) -> bool {
        match self {
            Self::Origin => false,
            Self::AuthAes128(state) => state.has_pending_frame(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_passes_bytes_through_untouched() {
        let mut state = ProtocolState::new(ProtocolMethod::Origin, b"key".to_vec(), vec![1u8; 16]);
        assert_eq!(
            state.client_pre_encrypt(b"hello", 0, None).unwrap(),
            b"hello"
        );
        assert_eq!(state.client_post_decrypt(b"world").unwrap(), b"world");
        assert!(!state.needs_auth_header());
    }

    #[test]
    fn auth_aes128_is_selected_by_method_and_wants_a_header() {
        for method in [
            ProtocolMethod::AuthAes128Md5,
            ProtocolMethod::AuthAes128Sha1,
        ] {
            let state = ProtocolState::new(method, b"key".to_vec(), vec![1u8; 16]);
            assert!(state.needs_auth_header());
        }
    }
}

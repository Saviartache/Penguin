//! Общий на всё направление счётчик соединений для надстроек `auth_*`.
//!
//! Сервер у `auth_aes128_*` копит по каждому `client_id` окно из недавних
//! `connection_id` и отвергает повтор — это защита от повторного
//! воспроизведения записанного пакета (см. `client_queue`/`obfs_auth_mu_data`
//! в `shadowsocks/obfsplugin/auth.py` эталона). Значит, если на каждое новое
//! TCP-соединение через наш выход заводить свежий случайный `client_id`,
//! сервер довольно быстро решит, что это уже 65-й одновременный клиент
//! (лимит по умолчанию — 64), и начнёт отвечать так, будто протокол не
//! совпал. Поэтому `client_id` — один на весь выход и живёт, пока жив выход,
//! а меняется только `connection_id`, растущий с каждым новым соединением.

use rand::RngCore;
use std::sync::Mutex;

/// Метка времени в формате протокола: секунды с эпохи, младшие 32 бита.
fn utc_now_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Данные одного заголовка `auth_data`: метка времени, id клиента, id
/// соединения — ровно то, что уходит в первый пакет каждого соединения.
pub(crate) struct AuthHeader {
    pub utc_time: u32,
    pub client_id: [u8; 4],
    pub connection_id: u32,
}

struct Inner {
    client_id: Option<[u8; 4]>,
    connection_id: u32,
}

/// Общее состояние на весь выход. Клонируется дёшево — внутри `Arc`.
pub(crate) struct ClientIdState(Mutex<Inner>);

impl ClientIdState {
    /// Заводит состояние. `client_id` появится при первом обращении.
    pub(crate) fn new() -> Self {
        Self(Mutex::new(Inner {
            client_id: None,
            connection_id: 0,
        }))
    }

    /// Следующий заголовок `auth_data` для нового соединения.
    ///
    /// Заводит `client_id` при первом вызове; если счётчик соединений зашёл
    /// слишком далеко (`> 0xFF000000`, как у эталона), заводит и его, и новый
    /// `client_id` заново — это тот же самый защитный порог, что у сервера.
    pub(crate) fn next(&self) -> AuthHeader {
        let mut inner = self.0.lock().unwrap_or_else(|poison| poison.into_inner());

        if inner.connection_id > 0xFF00_0000 {
            inner.client_id = None;
        }
        if inner.client_id.is_none() {
            let mut id = [0u8; 4];
            rand::thread_rng().fill_bytes(&mut id);
            inner.client_id = Some(id);
            inner.connection_id = rand::thread_rng().next_u32() & 0x00FF_FFFF;
        }
        let client_id = inner.client_id.unwrap_or_default();
        inner.connection_id += 1;

        AuthHeader {
            utc_time: utc_now_u32(),
            client_id,
            connection_id: inner.connection_id,
        }
    }
}

impl Default for ClientIdState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_id_stays_the_same_across_connections() {
        // Иначе сервер увидит поток «новых» клиентов вместо одного выхода с
        // растущим счётчиком соединений и рано или поздно откажет в приёме.
        let state = ClientIdState::new();
        let first = state.next();
        let second = state.next();
        assert_eq!(first.client_id, second.client_id);
        assert_eq!(second.connection_id, first.connection_id + 1);
    }

    #[test]
    fn different_outbounds_get_different_client_ids() {
        let a = ClientIdState::new().next();
        let b = ClientIdState::new().next();
        assert_ne!(a.client_id, b.client_id);
    }
}

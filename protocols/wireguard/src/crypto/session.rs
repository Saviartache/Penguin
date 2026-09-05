//! Установленный сеанс: ключи данных, счётчик отправки, окно приёма.
//!
//! Рукопожатие (`crate::crypto::handshake`) заканчивается здесь: у него была
//! своя жизнь на время обмена двумя сообщениями, у сеанса — своя, на все
//! пакеты данных, пока не пришла пора обновиться.

use std::time::{Duration, Instant};

use crate::crypto::constants::{
    KEY_LEN, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
};
use crate::crypto::handshake::SessionKeys;
use crate::crypto::primitives::{aead_open, aead_seal};
use crate::crypto::replay::ReplayWindow;
use crate::error::{WireguardError, WireguardResult};

/// Сеанс данных поверх завершённого рукопожатия.
///
/// Живёт до [`REJECT_AFTER_TIME`] или [`REJECT_AFTER_MESSAGES`] пакетов,
/// смотря что раньше, — после этого шифрование и расшифровка отказывают, а не
/// молча продолжают на просроченных ключах.
pub struct Session {
    send_key: [u8; KEY_LEN],
    recv_key: [u8; KEY_LEN],
    /// Наш индекс — сервер вставляет его в заголовок пакетов к нам.
    pub local_index: u32,
    /// Индекс сервера — мы вставляем его в заголовок пакетов к нему.
    pub remote_index: u32,
    tx_counter: u64,
    replay: ReplayWindow,
    established_at: Instant,
}

impl Session {
    /// Заводит сеанс сразу после успешного рукопожатия.
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            local_index: keys.local_index,
            remote_index: keys.remote_index,
            tx_counter: 0,
            replay: ReplayWindow::new(),
            established_at: Instant::now(),
        }
    }

    /// Шифрует пакет для отправки. Возвращает счётчик (он же нонс) и
    /// шифротекст с меткой.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> WireguardResult<(u64, Vec<u8>)> {
        if self.tx_counter >= REJECT_AFTER_MESSAGES {
            return Err(WireguardError::SessionExpired(
                self.established_at.elapsed(),
            ));
        }
        let counter = self.tx_counter;
        self.tx_counter += 1;
        Ok((counter, aead_seal(&self.send_key, counter, plaintext, &[])))
    }

    /// Расшифровывает пакет, пришедший с этим счётчиком, и проверяет его по
    /// окну защиты от повторов.
    ///
    /// Порядок важен: окно смотрит на счётчик только после того, как метка
    /// подлинности AEAD сошлась, — иначе поддельный пакет с угаданным
    /// счётчиком мог бы стереть из окна место настоящего (см.
    /// `crate::crypto::replay`).
    pub fn decrypt(&mut self, counter: u64, ciphertext: &[u8]) -> WireguardResult<Vec<u8>> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(WireguardError::SessionExpired(
                self.established_at.elapsed(),
            ));
        }
        let plaintext = aead_open(&self.recv_key, counter, ciphertext, &[])?;
        if !self.replay.accept(counter) {
            return Err(WireguardError::malformed(
                "счётчик пакета уже был принят: повтор",
            ));
        }
        Ok(plaintext)
    }

    /// Сеанс исчерпал срок или счётчик — держать его дальше нельзя ни в
    /// какую сторону.
    pub fn is_expired(&self) -> bool {
        self.established_at.elapsed() >= REJECT_AFTER_TIME * 3
            || self.tx_counter >= REJECT_AFTER_MESSAGES
    }

    /// Пора начинать новое рукопожатие: либо истекло время, либо разменяно
    /// слишком много сообщений, чтобы ждать штатного срока.
    ///
    /// Источник условия по времени — `RekeyAfterTime` в
    /// `wireguard-go/device/constants.go`: инициатор обновляет рукопожатие
    /// не дожидаясь конца сеанса, чтобы стороны разошлись без перерыва в
    /// трафике.
    pub fn needs_rekey(&self) -> bool {
        self.established_at.elapsed() >= REKEY_AFTER_TIME || self.tx_counter >= REKEY_AFTER_MESSAGES
    }

    /// Сколько сеанс уже живёт.
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }

    /// Выставляет счётчик отправки напрямую, в обход реального шифрования.
    ///
    /// Только для тестов предела: прогнать `encrypt` два в шестьдесят раз
    /// подряд, чтобы дойти до настоящего предела, — не тест, а зависание.
    #[cfg(test)]
    fn set_tx_counter_for_test(&mut self, counter: u64) {
        self.tx_counter = counter;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::new(SessionKeys {
            send_key: [1u8; KEY_LEN],
            recv_key: [1u8; KEY_LEN],
            local_index: 1,
            remote_index: 2,
        })
    }

    #[test]
    fn a_fresh_session_does_not_need_a_rekey_yet() {
        assert!(!session().needs_rekey());
        assert!(!session().is_expired());
    }

    #[test]
    fn encrypted_data_round_trips_through_decrypt() {
        let mut sender = session();
        let mut receiver = Session::new(SessionKeys {
            // Симметричный сеанс для теста: получатель расшифровывает тем
            // же ключом, которым отправитель шифровал — в жизни это два
            // разных ключа сеанса, но здесь важна только пара `encrypt`/`decrypt`.
            send_key: [1u8; KEY_LEN],
            recv_key: [1u8; KEY_LEN],
            local_index: 2,
            remote_index: 1,
        });

        let (counter, ciphertext) = sender.encrypt(b"hello, tunnel").expect("шифруется");
        let plaintext = receiver
            .decrypt(counter, &ciphertext)
            .expect("расшифровывается");
        assert_eq!(plaintext, b"hello, tunnel");
    }

    #[test]
    fn counters_climb_by_one_per_packet() {
        let mut sender = session();
        let (first, _) = sender.encrypt(b"a").expect("шифруется");
        let (second, _) = sender.encrypt(b"b").expect("шифруется");
        assert_eq!(second, first + 1);
    }

    #[test]
    fn a_replayed_counter_is_refused_on_the_receiving_side() {
        let mut sender = session();
        let mut receiver = Session::new(SessionKeys {
            send_key: [1u8; KEY_LEN],
            recv_key: [1u8; KEY_LEN],
            local_index: 2,
            remote_index: 1,
        });

        let (counter, ciphertext) = sender.encrypt(b"data").expect("шифруется");
        receiver
            .decrypt(counter, &ciphertext)
            .expect("проходит первый раз");
        assert!(receiver.decrypt(counter, &ciphertext).is_err());
    }

    #[test]
    fn a_session_at_the_message_ceiling_refuses_to_encrypt_further() {
        // Прогнать `encrypt` 2^64 раз, чтобы дойти сюда по-настоящему, —
        // не тест, а зависание; счётчик выставляется напрямую.
        let mut session = session();
        session.set_tx_counter_for_test(REJECT_AFTER_MESSAGES);
        assert!(session.encrypt("один пакет лишний".as_bytes()).is_err());
    }

    #[test]
    fn a_session_past_the_soft_rekey_threshold_asks_for_a_new_handshake() {
        let mut session = session();
        assert!(!session.needs_rekey());
        session.set_tx_counter_for_test(REKEY_AFTER_MESSAGES);
        assert!(session.needs_rekey());
    }
}

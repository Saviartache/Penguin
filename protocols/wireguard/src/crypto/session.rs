//! Установленный сеанс: ключи данных, счётчик отправки, окно приёма.

use std::time::{Duration, Instant};

use crate::crypto::constants::{
    KEY_LEN, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
    TRANSPORT_HEADER_LEN,
};
use crate::crypto::handshake::SessionKeys;
use crate::crypto::primitives::{aead_open_in_place, aead_seal_in_place};
use crate::crypto::replay::ReplayWindow;
use crate::error::{WireguardError, WireguardResult};
use crate::frame::transport::{self, TransportHeader};

/// Сеанс данных; после [`REJECT_AFTER_TIME`] или [`REJECT_AFTER_MESSAGES`] отказывает.
pub struct Session {
    send_key: [u8; KEY_LEN],
    recv_key: [u8; KEY_LEN],
    /// Наш индекс: сервер ставит его в заголовок пакетов к нам.
    pub local_index: u32,
    /// Индекс сервера: ставится в заголовок пакетов к нему.
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

    /// Собирает в `out` пакет данных: заголовок, шифротекст и метка. Буфер переиспользуется.
    pub fn seal_packet(
        &mut self,
        reserved: [u8; 3],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> WireguardResult<()> {
        if self.tx_counter >= REJECT_AFTER_MESSAGES {
            return Err(WireguardError::SessionExpired(self.age()));
        }
        let counter = self.tx_counter;
        self.tx_counter += 1;

        let header = TransportHeader {
            receiver_index: self.remote_index,
            counter,
        };
        out.clear();
        out.extend_from_slice(&transport::encode_header(&header, reserved));
        out.extend_from_slice(plaintext);
        let tag = aead_seal_in_place(
            &self.send_key,
            counter,
            &mut out[TRANSPORT_HEADER_LEN..],
            &[],
        )?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Расшифровывает пакет данных на месте и возвращает открытый текст.
    ///
    /// Окно повторов смотрит на счётчик только после проверки метки.
    pub fn open_packet<'a>(&mut self, datagram: &'a mut [u8]) -> WireguardResult<&'a mut [u8]> {
        let (header, _) = transport::split(datagram)?;
        if header.receiver_index != self.local_index {
            return Err(WireguardError::malformed("чужой индекс получателя"));
        }
        if header.counter >= REJECT_AFTER_MESSAGES {
            return Err(WireguardError::SessionExpired(self.age()));
        }
        let plaintext = aead_open_in_place(
            &self.recv_key,
            header.counter,
            &mut datagram[TRANSPORT_HEADER_LEN..],
            &[],
        )?;
        if !self.replay.accept(header.counter) {
            return Err(WireguardError::malformed(
                "счётчик пакета уже был принят: повтор",
            ));
        }
        Ok(plaintext)
    }

    /// Сеанс исчерпал срок или счётчик.
    pub fn is_expired(&self) -> bool {
        self.established_at.elapsed() >= REJECT_AFTER_TIME * 3
            || self.tx_counter >= REJECT_AFTER_MESSAGES
    }

    /// Пора начинать новое рукопожатие (`RekeyAfterTime` в `wireguard-go/device/constants.go`).
    pub fn needs_rekey(&self) -> bool {
        self.established_at.elapsed() >= REKEY_AFTER_TIME || self.tx_counter >= REKEY_AFTER_MESSAGES
    }

    /// Когда сеанс истечёт по времени.
    pub fn expires_at(&self) -> Instant {
        self.established_at + REJECT_AFTER_TIME * 3
    }

    /// Когда сеанс начнёт просить обновления по времени.
    pub fn rekey_at(&self) -> Instant {
        self.established_at + REKEY_AFTER_TIME
    }

    /// Сколько сеанс уже живёт.
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }

    /// Выставляет счётчик отправки: дойти до предела настоящими пакетами нельзя.
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

    fn peer() -> Session {
        Session::new(SessionKeys {
            send_key: [1u8; KEY_LEN],
            recv_key: [1u8; KEY_LEN],
            local_index: 2,
            remote_index: 1,
        })
    }

    fn seal(session: &mut Session, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        session
            .seal_packet([0; 3], plaintext, &mut out)
            .expect("шифруется");
        out
    }

    #[test]
    fn a_fresh_session_does_not_need_a_rekey_yet() {
        assert!(!session().needs_rekey());
        assert!(!session().is_expired());
    }

    #[test]
    fn sealed_data_round_trips_through_open() {
        let mut packet = seal(&mut session(), b"hello, tunnel");
        let plaintext = peer().open_packet(&mut packet).expect("расшифровывается");
        assert_eq!(plaintext, b"hello, tunnel");
    }

    #[test]
    fn counters_climb_by_one_per_packet() {
        let mut sender = session();
        let first = transport::split(&seal(&mut sender, b"a"))
            .expect("разбирается")
            .0;
        let second = transport::split(&seal(&mut sender, b"b"))
            .expect("разбирается")
            .0;
        assert_eq!(second.counter, first.counter + 1);
    }

    #[test]
    fn a_replayed_packet_is_refused_on_the_receiving_side() {
        let packet = seal(&mut session(), b"data");
        let mut receiver = peer();
        receiver
            .open_packet(&mut packet.clone())
            .expect("проходит первый раз");
        assert!(receiver.open_packet(&mut packet.clone()).is_err());
    }

    #[test]
    fn a_packet_for_another_index_is_refused() {
        let mut packet = seal(&mut session(), b"data");
        assert!(session().open_packet(&mut packet).is_err());
    }

    #[test]
    fn a_session_at_the_message_ceiling_refuses_to_seal_further() {
        let mut session = session();
        session.set_tx_counter_for_test(REJECT_AFTER_MESSAGES);
        assert!(session.seal_packet([0; 3], b"x", &mut Vec::new()).is_err());
    }

    #[test]
    fn a_session_past_the_soft_rekey_threshold_asks_for_a_new_handshake() {
        let mut session = session();
        assert!(!session.needs_rekey());
        session.set_tx_counter_for_test(REKEY_AFTER_MESSAGES);
        assert!(session.needs_rekey());
    }
}

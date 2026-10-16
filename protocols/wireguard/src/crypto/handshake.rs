//! Рукопожатие Noise IK (`psk2`), роль инициатора: клиент всегда инициатор.
//!
//! Перевод `CreateMessageInitiation` и `ConsumeMessageResponse` из
//! `device/noise-protocol.go` (`wireguard-go`); номера шагов в коде - порядок
//! перемешивания `hash`/`chaining_key`, ошибка в котором не видна иначе как сверкой с эталоном.

use penguin_proto::random;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::constants::{
    CONSTRUCTION, IDENTIFIER, INITIATION_MESSAGE_LEN, KEY_LEN, LABEL_MAC1,
};
use crate::crypto::primitives::{aead_open, aead_seal, hash, kdf1, kdf2, kdf3, mac};
use crate::crypto::tai64n::Tai64N;
use crate::error::{WireguardError, WireguardResult};
use crate::frame::{initiation, response};

/// Долгоживущие ключи и предвычисленное из них.
pub struct StaticKeys {
    private: StaticSecret,
    public: [u8; KEY_LEN],
    server_public: [u8; KEY_LEN],
    /// Нули, если в настройках не задан (штатно для `wg(8)`).
    preshared: [u8; KEY_LEN],
    /// `DH(Spriv_свой, Spub_сервера)`.
    precomputed_ss: [u8; KEY_LEN],
    /// Ключ `mac1` для сообщений к серверу.
    mac1_key_send: [u8; KEY_LEN],
    /// Ключ `mac1` для сообщений от сервера к нам.
    mac1_key_receive: [u8; KEY_LEN],
}

impl StaticKeys {
    /// Готовит долгоживущие ключи из сырых 32 байт.
    pub fn new(
        private_key: [u8; KEY_LEN],
        server_public_key: [u8; KEY_LEN],
        preshared: [u8; KEY_LEN],
    ) -> Self {
        let private = StaticSecret::from(private_key);
        let public = PublicKey::from(&private);
        let server_public = PublicKey::from(server_public_key);
        let precomputed_ss = *private.diffie_hellman(&server_public).as_bytes();
        let mac1_key_send = hash(&[LABEL_MAC1, server_public.as_bytes()]);
        let mac1_key_receive = hash(&[LABEL_MAC1, public.as_bytes()]);

        Self {
            private,
            public: *public.as_bytes(),
            server_public: *server_public.as_bytes(),
            preshared,
            precomputed_ss,
            mac1_key_send,
            mac1_key_receive,
        }
    }

    /// Собственный статический открытый ключ.
    pub fn public(&self) -> [u8; KEY_LEN] {
        self.public
    }
}

/// Состояние между сообщениями 1 и 2; одноразовое, на каждую попытку новое.
pub struct PendingHandshake {
    local_index: u32,
    ephemeral_private: StaticSecret,
    chaining_key: [u8; KEY_LEN],
    hash: [u8; KEY_LEN],
}

impl PendingHandshake {
    /// Индекс, под которым сервер адресует нам ответ.
    pub fn local_index(&self) -> u32 {
        self.local_index
    }
}

/// Ключи установленного сеанса.
pub struct SessionKeys {
    /// Ключ пакетов к серверу.
    pub send_key: [u8; KEY_LEN],
    /// Ключ пакетов от сервера.
    pub recv_key: [u8; KEY_LEN],
    /// Наш индекс: сервер ставит его в заголовок пакетов к нам.
    pub local_index: u32,
    /// Индекс сервера: ставится в заголовок пакетов к нему.
    pub remote_index: u32,
}

fn random_index() -> u32 {
    u32::from_ne_bytes(random::array())
}

fn random_secret() -> StaticSecret {
    StaticSecret::from(random::array::<KEY_LEN>())
}

/// Строит сообщение 1 (инициация) и состояние для разбора ответа.
pub fn create_initiation(
    keys: &StaticKeys,
    reserved: [u8; 3],
) -> ([u8; INITIATION_MESSAGE_LEN], PendingHandshake) {
    // Шаги 1-2.
    let mut chaining_key = hash(&[CONSTRUCTION]);
    let mut transcript = hash(&[&chaining_key, IDENTIFIER]);
    transcript = hash(&[&transcript, &keys.server_public]);

    // Шаг 3.
    let ephemeral_private = random_secret();
    let ephemeral_public = *PublicKey::from(&ephemeral_private).as_bytes();
    chaining_key = kdf1(&chaining_key, &ephemeral_public);
    transcript = hash(&[&transcript, &ephemeral_public]);

    // Шаг 4.
    let ss = *ephemeral_private
        .diffie_hellman(&PublicKey::from(keys.server_public))
        .as_bytes();
    let (chaining_key_2, key) = kdf2(&chaining_key, &ss);
    chaining_key = chaining_key_2;

    // Шаг 5.
    let static_ciphertext = to_array(&aead_seal(&key, 0, &keys.public, &transcript));
    transcript = hash(&[&transcript, &static_ciphertext]);

    // Шаг 6.
    let (chaining_key_3, key) = kdf2(&chaining_key, &keys.precomputed_ss);
    chaining_key = chaining_key_3;

    // Шаг 7.
    let timestamp = Tai64N::now().to_bytes();
    let timestamp_ciphertext = to_array(&aead_seal(&key, 0, &timestamp, &transcript));
    transcript = hash(&[&transcript, &timestamp_ciphertext]);

    let local_index = random_index();
    let fields = initiation::InitiationFields {
        sender_index: local_index,
        ephemeral_public,
        static_ciphertext,
        timestamp_ciphertext,
    };
    let mut message = initiation::encode(&fields, reserved);

    // Шаг 8: `mac1` вне транскрипта, `mac2` - ноль (cookie не запрашивается).
    let mac1 = mac(&keys.mac1_key_send, initiation::mac1_covered(&message));
    initiation::set_mac1(&mut message, mac1);

    (
        message,
        PendingHandshake {
            local_index,
            ephemeral_private,
            chaining_key,
            hash: transcript,
        },
    )
}

/// Разбирает сообщение 2 и завершает рукопожатие.
pub fn consume_response(
    keys: &StaticKeys,
    pending: PendingHandshake,
    message: &[u8],
) -> WireguardResult<SessionKeys> {
    let fields = response::parse(message)?;

    if fields.receiver_index != pending.local_index {
        return Err(WireguardError::malformed(
            "ответ адресован не этому рукопожатию",
        ));
    }

    // Ранний отсев подделки до дорогих DH.
    let expected_mac1 = mac(&keys.mac1_key_receive, response::mac1_covered(message));
    if expected_mac1 != message[60..76] {
        return Err(WireguardError::malformed("mac1 ответа не сошёлся"));
    }

    let PendingHandshake {
        local_index,
        ephemeral_private,
        mut chaining_key,
        hash: mut transcript,
    } = pending;

    // Шаг 9.
    transcript = hash(&[&transcript, &fields.ephemeral_public]);
    chaining_key = kdf1(&chaining_key, &fields.ephemeral_public);

    // Шаг 10.
    let ss_ee = *ephemeral_private
        .diffie_hellman(&PublicKey::from(fields.ephemeral_public))
        .as_bytes();
    chaining_key = kdf1(&chaining_key, &ss_ee);

    // Шаг 11.
    let ss_se = *keys
        .private
        .diffie_hellman(&PublicKey::from(fields.ephemeral_public))
        .as_bytes();
    chaining_key = kdf1(&chaining_key, &ss_se);

    // Шаг 12.
    let (chaining_key_final, tau, key) = kdf3(&chaining_key, &keys.preshared);
    chaining_key = chaining_key_final;
    transcript = hash(&[&transcript, &tau]);

    // Шаг 13: на этом шаге сервер шифрует пустую строку.
    let opened = aead_open(&key, 0, &fields.empty_ciphertext, &transcript)?;
    if !opened.is_empty() {
        return Err(WireguardError::malformed(
            "второе сообщение несёт данные там, где протокол ждёт пустую строку",
        ));
    }

    // Шаг 14: у инициатора `send, recv = KDF2(ck, "")` (`BeginSymmetricSession`).
    let (send_key, recv_key) = kdf2(&chaining_key, &[]);

    Ok(SessionKeys {
        send_key,
        recv_key,
        local_index,
        remote_index: fields.sender_index,
    })
}

/// Длина источника равна `N` по построению.
fn to_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (StaticSecret, PublicKey) {
        let secret = random_secret();
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    fn key_pairs() -> (StaticKeys, StaticKeys) {
        let (client_priv, client_pub) = keypair();
        let (server_priv, server_pub) = keypair();
        let client = StaticKeys::new(
            client_priv.to_bytes(),
            *server_pub.as_bytes(),
            [0u8; KEY_LEN],
        );
        let server = StaticKeys::new(
            server_priv.to_bytes(),
            *client_pub.as_bytes(),
            [0u8; KEY_LEN],
        );
        (client, server)
    }

    /// Круговой тест ловит опечатку в паре, но не неверно понятый формат: для
    /// этого есть векторы в `crate::crypto::primitives` и тесты `crate::frame`.
    #[test]
    fn a_full_handshake_between_two_instances_of_this_crate_agrees_on_keys() {
        let (client_keys, server_keys) = key_pairs();

        let (message1, pending) = create_initiation(&client_keys, [0, 0, 0]);
        let (message2, server_local_index) =
            server_side_response(&server_keys, &message1).expect("сервер отвечает");

        let session_keys =
            consume_response(&client_keys, pending, &message2).expect("рукопожатие сходится");

        assert_eq!(session_keys.remote_index, server_local_index);
        assert_ne!(session_keys.send_key, session_keys.recv_key);
    }

    #[test]
    fn a_response_addressed_to_a_different_handshake_is_refused() {
        let (client_keys, server_keys) = key_pairs();

        let (message1, pending) = create_initiation(&client_keys, [0, 0, 0]);
        let (mut message2, _) = server_side_response(&server_keys, &message1).expect("отвечает");
        message2[8..12].copy_from_slice(&(pending.local_index().wrapping_add(1)).to_le_bytes());

        assert!(consume_response(&client_keys, pending, &message2).is_err());
    }

    #[test]
    fn a_response_with_a_tampered_mac1_is_refused() {
        let (client_keys, server_keys) = key_pairs();

        let (message1, pending) = create_initiation(&client_keys, [0, 0, 0]);
        let (mut message2, _) = server_side_response(&server_keys, &message1).expect("отвечает");
        message2[60] ^= 0xFF;

        assert!(consume_response(&client_keys, pending, &message2).is_err());
    }

    /// Роль ответчика по формулам спецификации, только для теста; возвращает
    /// сообщение 2 и объявленный сервером индекс.
    fn server_side_response(
        keys: &StaticKeys,
        message1: &[u8],
    ) -> WireguardResult<([u8; crate::crypto::constants::RESPONSE_MESSAGE_LEN], u32)> {
        use crate::crypto::constants::RESPONSE_MESSAGE_LEN;

        let fields = initiation::parse(message1)?;

        let mut chaining_key = hash(&[CONSTRUCTION]);
        let mut transcript = hash(&[&chaining_key, IDENTIFIER]);
        transcript = hash(&[&transcript, &keys.public]);
        chaining_key = kdf1(&chaining_key, &fields.ephemeral_public);
        transcript = hash(&[&transcript, &fields.ephemeral_public]);

        let ss = *keys
            .private
            .diffie_hellman(&PublicKey::from(fields.ephemeral_public))
            .as_bytes();
        let (chaining_key_2, key) = kdf2(&chaining_key, &ss);
        chaining_key = chaining_key_2;

        let initiator_static = aead_open(&key, 0, &fields.static_ciphertext, &transcript)?;
        transcript = hash(&[&transcript, &fields.static_ciphertext]);

        let (chaining_key_3, key) = kdf2(&chaining_key, &keys.precomputed_ss);
        chaining_key = chaining_key_3;
        let _timestamp = aead_open(&key, 0, &fields.timestamp_ciphertext, &transcript)?;
        transcript = hash(&[&transcript, &fields.timestamp_ciphertext]);

        let local_index = random_index();
        let ephemeral_private = random_secret();
        let ephemeral_public = *PublicKey::from(&ephemeral_private).as_bytes();
        transcript = hash(&[&transcript, &ephemeral_public]);
        chaining_key = kdf1(&chaining_key, &ephemeral_public);

        let ss_ee = *ephemeral_private
            .diffie_hellman(&PublicKey::from(fields.ephemeral_public))
            .as_bytes();
        chaining_key = kdf1(&chaining_key, &ss_ee);

        let mut initiator_static_pub = [0u8; KEY_LEN];
        initiator_static_pub.copy_from_slice(&initiator_static);
        let ss_se = *ephemeral_private
            .diffie_hellman(&PublicKey::from(initiator_static_pub))
            .as_bytes();
        chaining_key = kdf1(&chaining_key, &ss_se);

        let (_chaining_key, tau, key) = kdf3(&chaining_key, &keys.preshared);
        transcript = hash(&[&transcript, &tau]);

        let empty_ciphertext_vec = aead_seal(&key, 0, &[], &transcript);
        let mut empty_ciphertext = [0u8; 16];
        empty_ciphertext.copy_from_slice(&empty_ciphertext_vec);

        let response_fields = response::ResponseFields {
            sender_index: local_index,
            receiver_index: fields.sender_index,
            ephemeral_public,
            empty_ciphertext,
        };
        let mut out = [0u8; RESPONSE_MESSAGE_LEN];
        out[0] = crate::crypto::constants::MESSAGE_RESPONSE;
        out[4..8].copy_from_slice(&response_fields.sender_index.to_le_bytes());
        out[8..12].copy_from_slice(&response_fields.receiver_index.to_le_bytes());
        out[12..44].copy_from_slice(&response_fields.ephemeral_public);
        out[44..60].copy_from_slice(&response_fields.empty_ciphertext);
        let mac1 = mac(&keys.mac1_key_send, &out[..60]);
        out[60..76].copy_from_slice(&mac1);

        Ok((out, local_index))
    }
}

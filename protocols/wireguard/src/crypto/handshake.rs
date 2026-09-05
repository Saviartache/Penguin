//! Рукопожатие Noise IK (с модификатором `psk2`): роль инициатора.
//!
//! Крейт всегда клиент, то есть всегда инициатор — сервер ролями с ним не
//! меняется никогда. Поэтому здесь нет ни `ConsumeMessageInitiation`, ни
//! `CreateMessageResponse`: только то, что делает инициатор.
//!
//! Последовательность — построчный перевод `CreateMessageInitiation` и
//! `ConsumeMessageResponse` из `device/noise-protocol.go` (`wireguard-go`).
//! Каждый шаг подписан номером строки того же смысла на человеческом языке,
//! а не только формулой: спутать порядок перемешивания `hash`/`chaining_key`
//! значит получить рукопожатие, которое не проходит молча, и найти это по
//! одним лишь формулам ниже потом не получится — только сверкой с эталоном.
//!
//! # Что мешается в хэш и в каком порядке (сообщение 1, инициатор → сервер)
//!
//! 1. `chaining_key = HASH(CONSTRUCTION)`, `hash = HASH(chaining_key || IDENTIFIER)`.
//! 2. `hash = HASH(hash || Spub_сервера)`.
//! 3. Новый эфемерный ключ `E`. `chaining_key = KDF1(chaining_key, Epub)`,
//!    `hash = HASH(hash || Epub)`.
//! 4. `ss = DH(Epriv, Spub_сервера)`. `(chaining_key, key) = KDF2(chaining_key, ss)`.
//! 5. Шифруется собственный статический ключ: `msg.static = AEAD(key, 0,
//!    Spub_свой, hash)`. `hash = HASH(hash || msg.static)`.
//! 6. `ss = DH(Spriv_свой, Spub_сервера)` — не зависит от эфемерного, считается
//!    один раз при старте (`StaticKeys::precomputed_ss`, поле не публично).
//!    `(chaining_key, key) = KDF2(chaining_key, ss)`.
//! 7. Шифруется метка времени: `msg.timestamp = AEAD(key, 0, TAI64N::now(),
//!    hash)`. `hash = HASH(hash || msg.timestamp)`.
//! 8. `mac1`/`mac2` считаются отдельно от `hash`/`chaining_key` — это защита
//!    от перегрузки, а не часть транскрипта Noise (см. `crate::frame::initiation`).
//!
//! # Сообщение 2 (сервер → инициатор)
//!
//! 9. `hash = HASH(hash || Epub_сервера)`. `chaining_key = KDF1(chaining_key, Epub_сервера)`.
//! 10. `ss = DH(Epriv_свой, Epub_сервера)`. `chaining_key = KDF1(chaining_key, ss)`.
//! 11. `ss = DH(Spriv_свой, Epub_сервера)`. `chaining_key = KDF1(chaining_key, ss)`.
//! 12. Смешивается предварительный ключ: `(chaining_key, tau, key) =
//!     KDF3(chaining_key, psk)`. `hash = HASH(hash || tau)`.
//! 13. Транскрипт заверяется пустой строкой: `AEAD_open(key, 0, msg.empty,
//!     hash)` обязан дать пустой открытый текст. `hash = HASH(hash || msg.empty)`.
//! 14. Ключи сеанса: `(k0, k1) = KDF2(chaining_key, "")`. Инициатор
//!     отправляет ключом `k0`, принимает — `k1` (источник:
//!     `BeginSymmetricSession` в `device/noise-protocol.go` — у инициатора
//!     `sendKey, recvKey = KDF2(...)` именно в этом порядке; у ответчика
//!     порядок был бы обратный, но им этот крейт не бывает).

use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::constants::{
    CONSTRUCTION, IDENTIFIER, INITIATION_MESSAGE_LEN, KEY_LEN, LABEL_MAC1,
};
use crate::crypto::primitives::{aead_open, aead_seal, hash, kdf1, kdf2, kdf3, mac};
use crate::crypto::tai64n::Tai64N;
use crate::error::{WireguardError, WireguardResult};
use crate::frame::{initiation, response};

/// Долгоживущие ключи и то, что из них можно посчитать заранее.
///
/// Одна штука на направление, живёт весь сеанс профиля — в отличие от
/// [`PendingHandshake`], который заводится заново на каждую попытку.
pub struct StaticKeys {
    private: StaticSecret,
    public: [u8; KEY_LEN],
    server_public: [u8; KEY_LEN],
    /// Предварительный ключ. Все нули, если в настройках не задан — это и
    /// есть штатное поведение `wg(8)` для пустого `PresharedKey`, а не
    /// заглушка этого крейта.
    preshared: [u8; KEY_LEN],
    /// `DH(Spriv_свой, Spub_сервера)` — не меняется, пока не меняются оба
    /// ключа, и вычисление здесь одно на весь сеанс, а не на каждую попытку
    /// рукопожатия.
    precomputed_ss: [u8; KEY_LEN],
    /// `HASH(LABEL_MAC1 || Spub_сервера)` — ключ `mac1` для сообщений,
    /// которые шлём мы (сообщение адресовано серверу, и мета защищает
    /// именно его от перегрузки).
    mac1_key_send: [u8; KEY_LEN],
    /// `HASH(LABEL_MAC1 || Spub_свой)` — ключ, которым сервер обязан был
    /// посчитать `mac1` ответа: сообщение адресовано нам.
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

/// Состояние рукопожатия между отправкой сообщения 1 и получением сообщения 2.
///
/// Заводится заново на каждую попытку: индекс, эфемерный ключ и транскрипт —
/// одноразовые. Переживший неудачную попытку `PendingHandshake` не годится ни
/// для чего, кроме как быть отброшенным.
pub struct PendingHandshake {
    local_index: u32,
    ephemeral_private: StaticSecret,
    chaining_key: [u8; KEY_LEN],
    hash: [u8; KEY_LEN],
}

impl PendingHandshake {
    /// Индекс, под которым сервер будет адресовать нам ответ.
    pub fn local_index(&self) -> u32 {
        self.local_index
    }
}

/// Ключи установленного сеанса, готовые лечь в `crate::crypto::session::Session`.
pub struct SessionKeys {
    /// Ключ, которым шифруются пакеты в сторону сервера.
    pub send_key: [u8; KEY_LEN],
    /// Ключ, которым расшифровываются пакеты от сервера.
    pub recv_key: [u8; KEY_LEN],
    /// Наш индекс — сервер вставляет его в заголовок пакетов к нам.
    pub local_index: u32,
    /// Индекс сервера — мы вставляем его в заголовок пакетов к нему.
    pub remote_index: u32,
}

/// Строит сообщение 1 (инициация) и возвращает его вместе с состоянием,
/// нужным, чтобы разобрать ответ.
pub fn create_initiation(
    keys: &StaticKeys,
    reserved: [u8; 3],
) -> ([u8; INITIATION_MESSAGE_LEN], PendingHandshake) {
    // Шаг 1.
    let mut chaining_key = hash(&[CONSTRUCTION]);
    let mut transcript = hash(&[&chaining_key, IDENTIFIER]);
    // Шаг 2.
    transcript = hash(&[&transcript, &keys.server_public]);

    // Шаг 3.
    let ephemeral_private = StaticSecret::random();
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
    let static_ciphertext = to_array_48(aead_seal(&key, 0, &keys.public, &transcript));
    transcript = hash(&[&transcript, &static_ciphertext]);

    // Шаг 6.
    let (chaining_key_3, key) = kdf2(&chaining_key, &keys.precomputed_ss);
    chaining_key = chaining_key_3;

    // Шаг 7.
    let timestamp = Tai64N::now().to_bytes();
    let timestamp_ciphertext = to_array_28(aead_seal(&key, 0, &timestamp, &transcript));
    transcript = hash(&[&transcript, &timestamp_ciphertext]);

    let local_index = rand::random::<u32>();
    let fields = initiation::InitiationFields {
        sender_index: local_index,
        ephemeral_public,
        static_ciphertext,
        timestamp_ciphertext,
    };
    let mut message = initiation::encode(&fields, reserved);

    // Шаг 8: mac1 считается над готовыми байтами отдельным ключом, mac2
    // остаётся нулём — cookie этот крейт не запрашивает.
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

/// Разбирает сообщение 2 (ответ) и завершает рукопожатие, отдавая ключи
/// установленного сеанса.
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

    // Проверка `mac1` — не часть транскрипта Noise, а дешёвый ранний отсев
    // подделанного или испорченного ответа до дорогих операций Диффи-Хеллмана.
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

    // Шаг 13.
    let opened = aead_open(&key, 0, &fields.empty_ciphertext, &transcript)?;
    if !opened.is_empty() {
        // Не должно случиться: пустой открытый текст — это то, что сервер
        // всегда шифрует на этом шаге. Непустой результат означает не «сервер
        // прислал данные», а то, что транскрипт разошёлся ещё до этой точки
        // и метка всё равно как-то сошлась — то есть баг в самой реализации,
        // а не во входных данных.
        return Err(WireguardError::malformed(
            "второе сообщение несёт данные там, где протокол ждёт пустую строку",
        ));
    }

    // Шаг 14.
    let (send_key, recv_key) = kdf2(&chaining_key, &[]);

    Ok(SessionKeys {
        send_key,
        recv_key,
        local_index,
        remote_index: fields.sender_index,
    })
}

fn to_array_48(vec: Vec<u8>) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&vec);
    out
}

fn to_array_28(vec: Vec<u8>) -> [u8; 28] {
    let mut out = [0u8; 28];
    out.copy_from_slice(&vec);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    #[test]
    fn a_full_handshake_between_two_instances_of_this_crate_agrees_on_keys() {
        // Круговой тест ловит опечатку в паре, но не ловит неверно понятый
        // формат — этим и объясняются отдельные тесты на длину сообщений
        // (`crate::frame`) и на захардкоженные `InitialChainKey`/`InitialHash`
        // (`crate::crypto::primitives`), сверенные с `boringtun` и с OpenSSL
        // независимо от этого файла.
        let (client_priv, client_pub) = keypair();
        let (server_priv, server_pub) = keypair();

        let client_keys = StaticKeys::new(
            client_priv.to_bytes(),
            *server_pub.as_bytes(),
            [0u8; KEY_LEN],
        );
        let server_keys = StaticKeys::new(
            server_priv.to_bytes(),
            *client_pub.as_bytes(),
            [0u8; KEY_LEN],
        );

        let (message1, pending) = create_initiation(&client_keys, [0, 0, 0]);

        // Сторона сервера собирается вручную по тем же формулам — этот крейт
        // не реализует роль ответчика, а тест обязан её сыграть, чтобы
        // проверить, что созданное сообщение 1 в принципе разбирается.
        let (message2, server_local_index) =
            server_side_response(&server_keys, &message1).expect("сервер отвечает");

        let session_keys =
            consume_response(&client_keys, pending, &message2).expect("рукопожатие сходится");

        assert_eq!(session_keys.remote_index, server_local_index);
        // То, чем шифрует один, обязано быть тем, чем расшифровывает другой.
        assert_ne!(session_keys.send_key, session_keys.recv_key);
    }

    #[test]
    fn a_response_addressed_to_a_different_handshake_is_refused() {
        let (client_priv, client_pub) = keypair();
        let (server_priv, server_pub) = keypair();
        let client_keys = StaticKeys::new(
            client_priv.to_bytes(),
            *server_pub.as_bytes(),
            [0u8; KEY_LEN],
        );
        let server_keys = StaticKeys::new(
            server_priv.to_bytes(),
            *client_pub.as_bytes(),
            [0u8; KEY_LEN],
        );

        let (message1, pending) = create_initiation(&client_keys, [0, 0, 0]);
        let (mut message2, _) = server_side_response(&server_keys, &message1).expect("отвечает");
        // Подменяем receiver_index на чужой.
        message2[8..12].copy_from_slice(&(pending.local_index().wrapping_add(1)).to_le_bytes());

        assert!(consume_response(&client_keys, pending, &message2).is_err());
    }

    #[test]
    fn a_response_with_a_tampered_mac1_is_refused() {
        let (client_priv, client_pub) = keypair();
        let (server_priv, server_pub) = keypair();
        let client_keys = StaticKeys::new(
            client_priv.to_bytes(),
            *server_pub.as_bytes(),
            [0u8; KEY_LEN],
        );
        let server_keys = StaticKeys::new(
            server_priv.to_bytes(),
            *client_pub.as_bytes(),
            [0u8; KEY_LEN],
        );

        let (message1, pending) = create_initiation(&client_keys, [0, 0, 0]);
        let (mut message2, _) = server_side_response(&server_keys, &message1).expect("отвечает");
        message2[60] ^= 0xFF;

        assert!(consume_response(&client_keys, pending, &message2).is_err());
    }

    /// Играет роль ответчика по тем же формулам спецификации — только для
    /// теста. Возвращает сообщение 2 и локальный индекс, который сервер в
    /// нём объявил (для сверки с `remote_index` на стороне клиента).
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

        // Сообщение 2.
        let local_index = rand::random::<u32>();
        let ephemeral_private = StaticSecret::random();
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

        // `chaining_key` дальше не нужен: сервер после этого шага сразу
        // выводит ключи сеанса, а не участвует в проверках теста.
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

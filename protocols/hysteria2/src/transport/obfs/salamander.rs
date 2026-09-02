//! Salamander: соль плюс BLAKE2b-256 и XOR.
//!
//! ```text
//! ┌──────────┬──────────────────────────────┐
//! │ соль 8 Б │ пакет QUIC ⊕ ключ            │
//! └──────────┴──────────────────────────────┘
//!   ключ = BLAKE2b-256(пароль ‖ соль)
//! ```
//!
//! Соль новая на каждый пакет, поэтому один и тот же байт заголовка QUIC
//! каждый раз шифруется в разное — иначе постоянный префикс выдавал бы и
//! протокол, и сам факт обфускации.
//!
//! Это не шифрование и не претендует им быть: содержимое уже зашифровано
//! самим QUIC. Задача слоя ровно одна — убрать узнаваемый вид с проводов.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rand::RngCore;

use super::Obfuscator;

/// Длина соли.
const SALT_LEN: usize = 8;

/// Длина ключа, он же период XOR.
const KEY_LEN: usize = 32;

type Blake2b256 = Blake2b<U32>;

/// Обфускатор Salamander.
pub struct Salamander {
    password: Vec<u8>,
}

impl Salamander {
    /// Создаёт обфускатор с общим с сервером ключом.
    pub fn new(password: impl AsRef<[u8]>) -> Self {
        Self {
            password: password.as_ref().to_vec(),
        }
    }

    /// Ключ для конкретной соли.
    fn key(&self, salt: &[u8]) -> [u8; KEY_LEN] {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.password);
        hasher.update(salt);
        hasher.finalize().into()
    }
}

// Пароль не должен утечь в журнал через отладочный вывод сокета.
impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Salamander")
            .field("password", &"<скрыт>")
            .finish()
    }
}

impl Obfuscator for Salamander {
    fn overhead(&self) -> usize {
        SALT_LEN
    }

    fn obfuscate(&self, input: &[u8], output: &mut [u8]) -> Option<usize> {
        let total = input.len().checked_add(SALT_LEN)?;
        if output.len() < total {
            return None;
        }

        let (salt, body) = output[..total].split_at_mut(SALT_LEN);
        rand::thread_rng().fill_bytes(salt);
        let key = self.key(salt);

        for (index, byte) in input.iter().enumerate() {
            body[index] = byte ^ key[index % KEY_LEN];
        }
        Some(total)
    }

    fn deobfuscate(&self, buf: &mut [u8]) -> Option<usize> {
        let len = buf.len().checked_sub(SALT_LEN).filter(|len| *len > 0)?;

        // Соль копируется, потому что дальше буфер переписывается с начала —
        // и она оказалась бы затёрта на первом же байте.
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[..SALT_LEN]);
        let key = self.key(&salt);

        // Сдвиг влево: читаем с `SALT_LEN`, пишем с нуля. Источник всегда
        // впереди приёмника, поэтому перекрытие безопасно.
        for index in 0..len {
            buf[index] = buf[index + SALT_LEN] ^ key[index % KEY_LEN];
        }
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obfuscator() -> Salamander {
        Salamander::new("cry_me_a_r1ver")
    }

    #[test]
    fn round_trips() {
        let obfs = obfuscator();
        let packet = b"\xc0\x00\x00\x00\x01QUIC initial packet contents";

        let mut wire = vec![0u8; packet.len() + obfs.overhead()];
        let written = obfs.obfuscate(packet, &mut wire).expect("обфусцируется");
        assert_eq!(written, packet.len() + SALT_LEN);

        let recovered = obfs.deobfuscate(&mut wire[..written]).expect("снимается");
        assert_eq!(&wire[..recovered], packet);
    }

    #[test]
    fn same_packet_looks_different_every_time() {
        // Постоянная соль сделала бы префикс QUIC узнаваемым — ровно то, от
        // чего слой и защищает.
        let obfs = obfuscator();
        let packet = b"the same bytes each time";
        let mut first = vec![0u8; packet.len() + SALT_LEN];
        let mut second = vec![0u8; packet.len() + SALT_LEN];
        obfs.obfuscate(packet, &mut first).expect("обфусцируется");
        obfs.obfuscate(packet, &mut second).expect("обфусцируется");
        assert_ne!(first, second);
    }

    #[test]
    fn wrong_password_yields_garbage_not_panic() {
        let sender = obfuscator();
        let receiver = Salamander::new("другой пароль");
        let packet = b"secret payload";

        let mut wire = vec![0u8; packet.len() + SALT_LEN];
        let written = sender.obfuscate(packet, &mut wire).expect("обфусцируется");
        let len = receiver
            .deobfuscate(&mut wire[..written])
            .expect("длина известна");
        // Мусор, но не паника: чужой пакет на открытом порту — обычное дело.
        assert_ne!(&wire[..len], packet);
    }

    #[test]
    fn rejects_short_input() {
        let obfs = obfuscator();
        // Короче соли — разбирать нечего.
        let mut too_short = [0u8; SALT_LEN];
        assert_eq!(obfs.deobfuscate(&mut too_short), None);
        let mut empty: [u8; 0] = [];
        assert_eq!(obfs.deobfuscate(&mut empty), None);
    }

    #[test]
    fn rejects_undersized_output() {
        let obfs = obfuscator();
        let mut tight = [0u8; 4];
        assert_eq!(obfs.obfuscate(b"12345678", &mut tight), None);
    }

    #[test]
    fn key_matches_reference_construction() {
        // Ключ обязан считаться как BLAKE2b-256(пароль ‖ соль): сервер
        // считает его именно так, и любое расхождение здесь означает, что
        // соединение не поднимется вообще.
        let obfs = obfuscator();
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let mut expected = Blake2b256::new();
        expected.update(b"cry_me_a_r1ver");
        expected.update(salt);
        let expected: [u8; KEY_LEN] = expected.finalize().into();

        assert_eq!(obfs.key(&salt), expected);
    }

    #[test]
    fn xor_repeats_key_every_32_bytes() {
        // Период XOR — длина ключа; на пакете длиннее 32 байт это заметно.
        let obfs = obfuscator();
        let packet = vec![0u8; 96];
        let mut wire = vec![0u8; packet.len() + SALT_LEN];
        obfs.obfuscate(&packet, &mut wire).expect("обфусцируется");

        let body = &wire[SALT_LEN..];
        assert_eq!(body[..KEY_LEN], body[KEY_LEN..KEY_LEN * 2]);
        assert_eq!(body[..KEY_LEN], body[KEY_LEN * 2..KEY_LEN * 3]);
    }
}

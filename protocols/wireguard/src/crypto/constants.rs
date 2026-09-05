//! Числа и строки, которые нельзя подобрать заново — только списать.
//!
//! Каждая константа здесь — часть договора с сервером, а не выбор реализации.
//! Разойтись с сервером хоть на байт в строке конструкции значит получить
//! другой `chaining key`, а с ним — рукопожатие, которое не заходит и не
//! говорит, почему. Источники указаны при каждой группе; независимая сверка —
//! в тестах `crate::crypto::primitives` (константы `INITIAL_CHAIN_KEY` и
//! `INITIAL_CHAIN_HASH` там проверены сравнением с захардкоженными байтами из
//! `boringtun` и отдельно — с байтами, посчитанными через BLAKE2s-256 из
//! OpenSSL напрямую, без единой строчки этого крейта).

use std::time::Duration;

/// Имя конструкции Noise. Входит в `chaining key` первым.
///
/// Источник: `wireguard.com/protocol/`, раздел «Cryptokey Routine»; байт в
/// байт совпадает с `NoiseConstruction` в `wireguard-go`
/// (`device/noise-helpers.go`) и с одноимённой константой в `boringtun`
/// (`boringtun/src/noise/handshake.rs`, через `INITIAL_CHAIN_KEY`).
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Имя протокола. Смешивается в хэш рукопожатия следом за конструкцией.
///
/// Источник тот же, что у [`CONSTRUCTION`]: `WGIdentifier` в `wireguard-go`.
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// Метка ключа для `mac1`: восемь байт, дефисы — не разделитель, а набивка
/// до восьми байт ровно, как и `LABEL_COOKIE` ниже.
///
/// Источник: `WGLabelMAC1` в `device/noise-helpers.go` (`wireguard-go`),
/// `LABEL_MAC1` в `boringtun/src/noise/handshake.rs` — совпадает в обеих
/// независимых реализациях.
pub const LABEL_MAC1: &[u8] = b"mac1----";

/// Метка ключа для расшифровки cookie-ответа сервера.
///
/// Источник: `WGLabelCookie` в `device/noise-helpers.go`. Крейт cookie-ответы
/// не разбирает (см. документ `crate::outbound`), но метка входит в список
/// сверенных строк по требованию плана.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// Тип сообщения — рукопожатие, инициатор → ответчик.
pub const MESSAGE_INITIATION: u8 = 1;
/// Тип сообщения — рукопожатие, ответчик → инициатор.
pub const MESSAGE_RESPONSE: u8 = 2;
/// Тип сообщения — cookie-ответ сервера под нагрузкой.
///
/// Крейт такие сообщения не строит и не разбирает: cookie — это защита
/// сервера от перегрузки поддельными рукопожатиями, а не часть переговоров о
/// ключе. Отсутствие поддержки означает, что клиент не проходит рукопожатие,
/// пока сервер под настолько сильной нагрузкой, что включил её, — деградация,
/// а не потеря связи молча.
pub const MESSAGE_COOKIE_REPLY: u8 = 3;
/// Тип сообщения — пакет с данными.
pub const MESSAGE_TRANSPORT_DATA: u8 = 4;

/// Длина открытого/приватного ключа X25519 и общего секрета.
pub const KEY_LEN: usize = 32;
/// Длина метки подлинности ChaCha20-Poly1305.
pub const AEAD_TAG_LEN: usize = 16;
/// Длина `mac1`/`mac2` — керированный BLAKE2s, усечённый до 128 бит.
pub const MAC_LEN: usize = 16;
/// Длина метки времени TAI64N в байтах поля `encrypted_timestamp` до шифрования.
pub const TIMESTAMP_LEN: usize = 12;

/// Точный размер сообщения рукопожатия «инициатор → ответчик» на проводе.
///
/// `4 (тип+резерв) + 4 (индекс) + 32 (эфемерный) + 48 (статический+метка) +
/// 28 (метка времени+метка) + 16 (mac1) + 16 (mac2)`. Источник:
/// `MessageInitiationSize` в `device/noise-protocol.go`.
pub const INITIATION_MESSAGE_LEN: usize = 148;

/// Точный размер сообщения рукопожатия «ответчик → инициатор» на проводе.
///
/// `4 (тип+резерв) + 4 (индекс отправителя) + 4 (индекс получателя) +
/// 32 (эфемерный) + 16 (пустой текст+метка) + 16 (mac1) + 16 (mac2)`.
/// Источник: `MessageResponseSize` в `device/noise-protocol.go`.
pub const RESPONSE_MESSAGE_LEN: usize = 92;

/// Размер заголовка пакета с данными, перед шифротекстом.
///
/// `4 (тип+резерв) + 4 (индекс получателя) + 8 (счётчик)`. Источник:
/// `MessageTransportHeaderSize` в `device/noise-protocol.go`.
pub const TRANSPORT_HEADER_LEN: usize = 16;

/// Наибольший пакет, который направление берёт целиком, когда путь снаружи
/// держит обычные 1500.
///
/// 1500 - 80: заголовок IP (берётся с запасом на IPv6 — 40 байт, а не 20 у
/// IPv4, потому что адрес сервера неизвестен заранее) + UDP (8) + заголовок
/// пакета данных WireGuard (16) + метка Poly1305 (16). Соврать здесь — значит
/// объявить приложению MSS, который не проходит через настоящий путь, и
/// получить страницу, которая грузится наполовину. Число из
/// `crates/proto/src/packet.rs`, документ `PacketInterface::mtu`.
pub const DEFAULT_MTU: u16 = 1420;

/// Через сколько сообщений с начала сеанса инициатор обязан обновить
/// рукопожатие, не дожидаясь [`REKEY_AFTER_TIME`].
///
/// Источник: `RekeyAfterMessages` в `wireguard-go/device/constants.go`,
/// `1 << 60`. С запасом ниже настоящего предела счётчика — исчерпать его при
/// разумной скорости передачи нельзя, но традиция протокола обновлять ключ
/// заведомо раньше, чем достижение предела станет вопросом сравнения чисел.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Счётчик, после которого пакет с этим сеансом принимать нельзя ни в какую
/// сторону: сеанс мёртв, и продолжать значило бы рисковать переиспользованием
/// нонса.
///
/// Источник: `RejectAfterMessages` в `wireguard-go/device/constants.go`,
/// `(1 << 64) - (1 << 13) - 1`. Запас в `2^13` — на пакеты, ушедшие в сеть до
/// того, как отправитель узнал, что пора остановиться. Записано как
/// `u64::MAX - (1 << 13)`, потому что `u64::MAX == (1 << 64) - 1`, и вычесть
/// из него ещё единицу, как выглядело бы при наивном переносе формулы,
/// значило бы посчитать на единицу меньше, чем в источнике, — эта ошибка была
/// в черновике этого файла и исправлена при сверке.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

// Оба свойства верны для любых значений входных чисел, а не только для
// сегодняшних — поэтому это утверждение уровня типов, а не тест, и `clippy`
// прав, требуя его в `const`-блок, а не в `assert!` времени выполнения.
const _: () = assert!(REKEY_AFTER_MESSAGES < REJECT_AFTER_MESSAGES);
const _: () = assert!(REJECT_AFTER_MESSAGES < u64::MAX);

/// Сколько инициатор ждёт до планового обновления рукопожатия, если сеанс
/// живёт и по нему идут данные.
///
/// Источник: `RekeyAfterTime` в `wireguard-go/device/constants.go`, 120 с.
/// Совпадает с `boringtun` (`boringtun/src/noise/timers.rs`, `REKEY_AFTER_TIME`)
/// — сверено по обеим независимым реализациям.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Сколько сеанс живёт с момента установления, после чего его данные больше
/// не шифруются и не расшифровываются: пора либо обновиться, либо считать
/// тоннель мёртвым.
///
/// Источник: `RejectAfterTime`, 180 с. Тот же порядок, что у `boringtun`.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Сколько ждать ответа на инициацию, прежде чем послать её снова.
///
/// Источник: `RekeyTimeout`, 5 с.
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);

/// Случайный сдвиг к [`REKEY_TIMEOUT`], чтобы повторные инициации от разных
/// клиентов после общего сбоя не пришли одной волной.
///
/// Источник: `RekeyTimeoutJitterMaxMs`, 334 мс — фактический интервал розыгрыша
/// `[0, 334)` мс.
pub const REKEY_TIMEOUT_JITTER_MAX_MS: u64 = 334;

/// Сколько инициатор пытается провести рукопожатие заново, прежде чем
/// признать сервер недостижимым.
///
/// Источник: `RekeyAttemptTime`, 90 с.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);

/// Сколько можно молчать (не отправлять пакет), получая данные, прежде чем
/// послать пустой пакет-подтверждение (keepalive уровня протокола, отдельно
/// от настраиваемого `PersistentKeepalive`, см. `crate::config`).
///
/// Источник: `KeepaliveTimeout`, 10 с.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Значение `PersistentKeepalive`, которое `wg(8)` называет разумным для
/// интерфейса за NAT: реже сервер забывает отображение адреса, чаще — трафик
/// без нужды. Используется как значение по умолчанию в [`crate::config`].
///
/// Источник: `wireguard-tools`, `man 8 wg`, описание `PersistentKeepalive`.
pub const DEFAULT_KEEPALIVE_SECS: u32 = 25;

/// Наибольшее допустимое значение интервала `PersistentKeepalive`.
///
/// Источник: `man 8 wg` — «between 1 and 65535 inclusive».
pub const MAX_KEEPALIVE_SECS: u32 = 65535;

/// Ширина окна защиты от повторов, в пакетах.
///
/// Число не входит в договор с сервером — это исключительно локальная
/// политика приёмника, и сервер про неё ничего не знает и знать не должен
/// (в отличие от всего выше). Взято равным `boringtun`
/// (`boringtun/src/noise/session.rs`, `N_WORDS * WORD_SIZE = 16 * 64`, то
/// есть 1024 бита): реализация оттуда широко используется и проверена live
/// на практике. У `wireguard-go`/модуля ядра окно шире (8128 бит,
/// `COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS` в `messages.h`) — это тоже
/// годный выбор, но здесь взят более простой и вдвое меньший по памяти
/// вариант; на интероперабельность выбор ширины окна не влияет никак.
pub const REPLAY_WINDOW_BITS: u64 = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_construction_string_is_the_exact_length_it_claims() {
        // Опечатка на байт здесь — это другой `chaining key`, и разойдётся
        // он молча: рукопожатие просто не сойдётся ни с одним сервером.
        assert_eq!(CONSTRUCTION.len(), 37);
        assert_eq!(IDENTIFIER.len(), 34);
        assert_eq!(LABEL_MAC1.len(), 8);
        assert_eq!(LABEL_COOKIE.len(), 8);
    }

    #[test]
    fn message_type_bytes_match_the_wire_format() {
        assert_eq!(MESSAGE_INITIATION, 1);
        assert_eq!(MESSAGE_RESPONSE, 2);
        assert_eq!(MESSAGE_COOKIE_REPLY, 3);
        assert_eq!(MESSAGE_TRANSPORT_DATA, 4);
    }

    #[test]
    fn message_sizes_add_up_field_by_field() {
        assert_eq!(4 + 4 + 32 + 48 + 28 + 16 + 16, INITIATION_MESSAGE_LEN);
        assert_eq!(4 + 4 + 4 + 32 + 16 + 16 + 16, RESPONSE_MESSAGE_LEN);
        assert_eq!(4 + 4 + 8, TRANSPORT_HEADER_LEN);
    }

    #[test]
    fn the_message_counter_limit_matches_the_reference_formula() {
        // `(1 << 64) - (1 << 13) - 1` из `wireguard-go`, посчитанное в `u128`,
        // чтобы формула на проверке не совпала с формулой в коде случайно —
        // через то же самое переполнение, что дало ошибку в черновике.
        let reference: u128 = (1u128 << 64) - (1u128 << 13) - 1;
        assert_eq!(u128::from(REJECT_AFTER_MESSAGES), reference);
    }

    #[test]
    fn the_rekey_timeout_is_shorter_than_the_attempt_window() {
        // Иначе повторной инициации просто не будет места: окно попыток
        // закроется раньше первого повтора.
        assert!(REKEY_TIMEOUT < REKEY_ATTEMPT_TIME);
    }

    #[test]
    fn the_mtu_leaves_the_headroom_the_packet_contract_documents() {
        assert_eq!(1500 - DEFAULT_MTU, 80);
    }
}

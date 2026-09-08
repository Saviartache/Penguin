//! Ключевое расписание: из двух согласований Диффи-Хеллмана и пароля — в
//! ключи записей.
//!
//! ```text
//!            ┌─ X25519(эфемерный клиента, постоянный сервера)  ── опознание
//!  секреты ──┤
//!            └─ X25519(эфемерный клиента, эфемерный сервера)   ── прямая секретность
//!
//!  prk    = HKDF-Extract(соль = SHA-256(приветствия), ss_s ‖ ss_e ‖ пароль)
//!  c2s    = HKDF-Expand(prk, "pingwin1 c2s", 32)
//!  s2c    = HKDF-Expand(prk, "pingwin1 s2c", 32)
//!  pad    = HKDF-Expand(prk, "pingwin1 pad", 64)
//! ```
//!
//! # Что даёт каждая часть
//!
//! **`ss_s`** — общий секрет с постоянным ключом сервера. Его может посчитать
//! только тот, у кого есть закрытая половина этого ключа, то есть сам сервер.
//! Отсюда две вещи сразу: сервер опознан (подставной не расшифрует ни байта)
//! и клиент опознан (постороннему нечего положить в `SessionID`, чтобы это
//! прошло проверку). Пассивный наблюдатель не отличит первую посылку от
//! случайных байт внутри обычного `ClientHello`.
//!
//! **`ss_e`** — общий секрет двух эфемерных ключей. Он и только он даёт
//! прямую секретность: записанный сегодня разговор не расшифровывается
//! завтра, даже если постоянный ключ сервера утёк.
//!
//! **Пароль** — то, что отличает пользователей одного сервера друг от друга.
//! Без него все пользователи с одним ключом сервера читали бы разговоры друг
//! друга, зная только открытый ключ.
//!
//! **Соль — стенограмма.** В неё входят обе посылки целиком, вместе с
//! отпечатком браузера, `SessionID` и всеми расширениями. Правка любого байта
//! по дороге даёт другие ключи, и первая же запись не расшифруется.
//!
//! # Про 0-RTT
//!
//! Ключ ранних данных выводится без `ss_e` — эфемерного ключа сервера клиент
//! ещё не видел. Значит, прямой секретности у ранних данных нет, и это
//! свойство любого 0-RTT, а не недосмотр. Повтор ранних данных при этом
//! невозможен: [`crate::wire::replay`] помнит эфемерные ключи окна, а
//! отметка времени закрывает всё, что старше него.

use ring::digest;
use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{PingwinError, PingwinResult};

/// Длина ключа записи и любого выведенного секрета.
pub const KEY_LEN: usize = 32;

/// Длина открытого ключа X25519.
pub const PUBLIC_LEN: usize = 32;

/// Метка версии протокола во всех выводах ключей.
///
/// Меняется вместе с форматом провода: разные версии обязаны получать разные
/// ключи, иначе несовместимые стороны договорятся до половины разговора и
/// разойдутся на первом же кадре.
const LABEL: &str = "pingwin1";

/// Ключи одного соединения.
#[derive(Clone)]
pub struct SessionKeys {
    /// Ключ записей от клиента к серверу.
    pub c2s: [u8; KEY_LEN],
    /// Ключ записей от сервера к клиенту.
    pub s2c: [u8; KEY_LEN],
    /// Затравка расписания дополнения клиента.
    pub pad_c2s: [u8; KEY_LEN],
    /// Затравка расписания дополнения сервера.
    pub pad_s2c: [u8; KEY_LEN],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ключи в журнал не попадают — ни целиком, ни первыми байтами
        // (`AGENTS.md` §5.2).
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

/// Постоянная пара ключей сервера.
///
/// Закрытая половина живёт в файле настроек сервера, открытая — в профиле
/// клиента. Тип многоразовый (`StaticSecret`) намеренно: секрет участвует в
/// согласовании на каждом соединении, а `ring::agreement` тратит ключ первым
/// же вызовом.
pub struct StaticKeyPair {
    secret: StaticSecret,
    /// Открытая половина — то, что стоит в профиле клиента.
    pub public: [u8; PUBLIC_LEN],
}

impl std::fmt::Debug for StaticKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticKeyPair")
            .field("public", &"<открытый ключ>")
            .finish_non_exhaustive()
    }
}

impl StaticKeyPair {
    /// Новая пара.
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        Self::from_secret(secret)
    }

    /// Пара из закрытой половины.
    pub fn from_bytes(secret: [u8; KEY_LEN]) -> Self {
        Self::from_secret(StaticSecret::from(secret))
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = *PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    /// Закрытая половина — только затем, чтобы её записать в файл настроек.
    pub fn secret_bytes(&self) -> [u8; KEY_LEN] {
        self.secret.to_bytes()
    }

    /// Общий секрет с эфемерным ключом клиента.
    pub fn agree(&self, peer: &[u8; PUBLIC_LEN]) -> [u8; KEY_LEN] {
        *self
            .secret
            .diffie_hellman(&PublicKey::from(*peer))
            .as_bytes()
    }
}

/// Ключ, которым закрываются данные опознания в `SessionID`.
///
/// Выводится из одного `ss_s`: на этом шаге клиент ещё не видел ответа
/// сервера, а сервер — ничего, кроме `ClientHello`.
pub fn probe_key(shared_static: &[u8; KEY_LEN]) -> PingwinResult<[u8; KEY_LEN]> {
    let prk = extract(&[], shared_static);
    expand_key(&prk, "probe")
}

/// Ключ ранних данных (0-RTT).
///
/// `hello_hash` — SHA-256 записи `ClientHello` целиком: без него один и тот же
/// пароль давал бы один и тот же ключ на всех соединениях.
pub fn zero_rtt_key(
    hello_hash: &[u8; 32],
    shared_static: &[u8; KEY_LEN],
    password: &[u8],
) -> PingwinResult<[u8; KEY_LEN]> {
    let mut ikm = Vec::with_capacity(KEY_LEN + password.len());
    ikm.extend_from_slice(shared_static);
    ikm.extend_from_slice(password);
    let prk = extract(hello_hash, &ikm);
    expand_key(&prk, "0rtt")
}

/// Ключи соединения после того, как обе стороны сказали своё.
pub fn session_keys(
    transcript: &[u8; 32],
    shared_static: &[u8; KEY_LEN],
    shared_ephemeral: &[u8; KEY_LEN],
    password: &[u8],
) -> PingwinResult<SessionKeys> {
    let mut ikm = Vec::with_capacity(2 * KEY_LEN + password.len());
    ikm.extend_from_slice(shared_static);
    ikm.extend_from_slice(shared_ephemeral);
    ikm.extend_from_slice(password);
    let prk = extract(transcript, &ikm);

    Ok(SessionKeys {
        c2s: expand_key(&prk, "c2s")?,
        s2c: expand_key(&prk, "s2c")?,
        pad_c2s: expand_key(&prk, "pad c2s")?,
        pad_s2c: expand_key(&prk, "pad s2c")?,
    })
}

/// Метка пользователя: восемь байт, по которым сервер находит его пароль.
///
/// Привязана к ключу сервера: один и тот же пароль на двух серверах даёт две
/// разные метки, и совпадение меток ничего не говорит о совпадении паролей.
/// На проводе метка всё равно едет внутри AEAD, то есть выглядит случайной.
pub fn user_tag(password: &[u8], server_public: &[u8; PUBLIC_LEN]) -> PingwinResult<[u8; 8]> {
    let prk = extract(server_public, password);
    let mut tag = [0u8; 8];
    fill(&prk, "user", &mut tag)?;
    Ok(tag)
}

/// Стенограмма: SHA-256 от записей приветствий, склеенных по порядку.
///
/// Склейка без разделителя здесь однозначна, и это не удача: обе половины —
/// записи TLS, у каждой в первых пяти байтах своя длина. Разбить одну и ту же
/// строку на две другие записи нельзя, значит и подобрать вторую пару
/// приветствий с той же стенограммой — тоже.
pub fn transcript(client_hello: &[u8], server_hello: &[u8]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(client_hello);
    context.update(server_hello);
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    out
}

/// SHA-256 одной посылки.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    out
}

fn extract(salt: &[u8], ikm: &[u8]) -> Prk {
    Salt::new(HKDF_SHA256, salt).extract(ikm)
}

fn expand_key(prk: &Prk, purpose: &str) -> PingwinResult<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    fill(prk, purpose, &mut key)?;
    Ok(key)
}

/// Длина вывода. `ring` требует её типом, а не числом.
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn fill(prk: &Prk, purpose: &str, out: &mut [u8]) -> PingwinResult<()> {
    let label = format!("{LABEL} {purpose}");
    let info = [label.as_bytes()];
    let okm = prk
        .expand(&info, Len(out.len()))
        .map_err(|_| PingwinError::malformed("ключ не выводится"))?;
    okm.fill(out)
        .map_err(|_| PingwinError::malformed("ключ не выводится"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(password: &[u8]) -> SessionKeys {
        session_keys(&[7u8; 32], &[1u8; 32], &[2u8; 32], password).expect("выводятся")
    }

    #[test]
    fn a_static_pair_agrees_with_itself_from_both_sides() {
        // Это и есть опознание сервера: клиент считает секрет открытым
        // ключом, сервер — закрытым, и они обязаны совпасть.
        let server = StaticKeyPair::generate();
        let client = StaticKeyPair::generate();

        let by_server = server.agree(&client.public);
        let by_client = client.agree(&server.public);
        assert_eq!(by_server, by_client);
    }

    #[test]
    fn a_pair_survives_the_trip_through_its_own_bytes() {
        // Так ключ и живёт: в файле настроек сервера лежат байты.
        let pair = StaticKeyPair::generate();
        let same = StaticKeyPair::from_bytes(pair.secret_bytes());
        assert_eq!(pair.public, same.public);
    }

    #[test]
    fn the_two_directions_never_share_a_key() {
        // Один ключ на оба направления означал бы повтор пары «ключ,
        // счётчик» — то есть раскрытые сообщения, а не «чуть слабее».
        let keys = keys(b"secret");
        assert_ne!(keys.c2s, keys.s2c);
        assert_ne!(keys.pad_c2s, keys.pad_s2c);
        assert_ne!(keys.c2s, keys.pad_c2s);
    }

    #[test]
    fn a_different_password_gives_different_keys() {
        // Иначе пользователи одного сервера читали бы разговоры друг друга.
        assert_ne!(keys(b"one").c2s, keys(b"two").c2s);
    }

    #[test]
    fn a_changed_transcript_gives_different_keys() {
        // Правка приветствия по дороге обязана ломать расшифровку первой же
        // записи, а не проходить незамеченной.
        let other = session_keys(&[8u8; 32], &[1u8; 32], &[2u8; 32], b"secret").expect("выводятся");
        assert_ne!(keys(b"secret").c2s, other.c2s);
    }

    #[test]
    fn the_ephemeral_secret_really_takes_part() {
        // Без него не было бы прямой секретности: записанный разговор
        // расшифровывался бы утёкшим постоянным ключом.
        let other = session_keys(&[7u8; 32], &[1u8; 32], &[3u8; 32], b"secret").expect("выводятся");
        assert_ne!(keys(b"secret").c2s, other.c2s);
    }

    #[test]
    fn the_zero_rtt_key_depends_on_the_hello_it_rides_with() {
        // Иначе один пароль давал бы один и тот же ключ ранних данных на
        // каждом соединении — и повтор перестал бы быть повтором.
        let one = zero_rtt_key(&[1u8; 32], &[9u8; 32], b"secret").expect("выводится");
        let two = zero_rtt_key(&[2u8; 32], &[9u8; 32], b"secret").expect("выводится");
        assert_ne!(one, two);
    }

    #[test]
    fn the_probe_key_is_not_any_of_the_session_keys() {
        let probe = probe_key(&[1u8; 32]).expect("выводится");
        let keys = keys(b"secret");
        assert_ne!(probe, keys.c2s);
        assert_ne!(probe, keys.s2c);
    }

    #[test]
    fn a_user_tag_is_bound_to_the_server_it_is_shown_to() {
        // Совпадение меток на двух серверах ничего не говорило бы о
        // совпадении паролей — и не должно.
        let one = user_tag(b"secret", &[1u8; 32]).expect("считается");
        let two = user_tag(b"secret", &[2u8; 32]).expect("считается");
        assert_ne!(one, two);

        let other = user_tag(b"another", &[1u8; 32]).expect("считается");
        assert_ne!(one, other);
    }

    #[test]
    fn the_transcript_notices_a_change_in_either_half() {
        // Правка любого байта любого приветствия обязана дать другие ключи —
        // на этом стоит защита рукопожатия от правки по дороге.
        let base = transcript(b"client", b"server");
        assert_ne!(base, transcript(b"cliont", b"server"));
        assert_ne!(base, transcript(b"client", b"servor"));
        assert_eq!(base, transcript(b"client", b"server"));
    }

    #[test]
    fn the_transcript_is_not_the_hash_of_one_half() {
        // Иначе `ServerHello` не участвовал бы в ключах вовсе.
        assert_ne!(transcript(b"client", b"server"), hash(b"client"));
    }

    #[test]
    fn debug_shows_no_key_material() {
        let rendered = format!("{:?}", keys(b"secret"));
        assert!(!rendered.contains("c2s"), "{rendered}");

        let pair = StaticKeyPair::generate();
        assert!(!format!("{pair:?}").contains(&format!("{:?}", pair.public)));
    }
}

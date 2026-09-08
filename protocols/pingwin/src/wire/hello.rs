//! Приветствия: данные опознания в `SessionID`, разбор `ClientHello`, сборка
//! `ServerHello`.
//!
//! ```text
//!  ClientHello (настоящий, с отпечатком браузера)
//!    key_share.x25519  ─► эфемерный ключ клиента   (лежит ровно там, где ему и место)
//!    session_id (32)   ─► AEAD(данные опознания)   (снаружи — случайные байты)
//!    server_name       ─► имя прикрытия            (то, что видит DPI)
//!
//!  ServerHello
//!    key_share.x25519  ─► эфемерный ключ сервера
//!    session_id (32)   ─► эхо клиентского, как требует TLS 1.3
//! ```
//!
//! # Почему опознание лежит в `SessionID`
//!
//! Потому что это единственное поле `ClientHello`, куда можно положить
//! тридцать два произвольных байта, не сделав сообщение непохожим на
//! браузерное. В TLS 1.3 `SessionID` — наследие совместимости: браузер кладёт
//! туда случайные байты и никогда их не проверяет. Тот же приём у Reality, и
//! по той же причине.
//!
//! Эфемерный ключ при этом **не прячется**: он лежит в `key_share`, где у
//! настоящего TLS 1.3 лежит ровно такой же ключ X25519. Прятать его было бы
//! ошибкой — сообщение без `key_share` не похоже ни на один браузер.
//!
//! # Что видит тот, кто смотрит
//!
//! Обычный `ClientHello` от Chrome (или Firefox, или Safari — отпечаток
//! выбирается в настройках) с именем прикрытия в SNI. Проверить, свой это
//! клиент или нет, можно только имея закрытый ключ сервера: без него
//! `SessionID` — тридцать два случайных байта, а они и должны быть
//! случайными.

use penguin_utls::server_hello::{self, ServerHello};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::error::{PingwinError, PingwinResult};
use crate::wire::keys::{KEY_LEN, PUBLIC_LEN};
use crate::wire::record;

/// Версия протокола в данных опознания.
pub const VERSION: u8 = 1;

/// Длина данных опознания до шифрования.
const AUTH_PLAIN_LEN: usize = 16;

/// Длина `SessionID`: данные опознания вместе с меткой подлинности.
pub const SESSION_ID_LEN: usize = AUTH_PLAIN_LEN + 16;

/// Смещение `SessionID` внутри сообщения `ClientHello`.
///
/// Четыре байта заголовка рукопожатия, два `legacy_version`, тридцать два
/// `random`, один — длина `SessionID`. То же число и по той же причине, что у
/// `penguin_utls::ClientHello::SESSION_ID_OFFSET`.
const SESSION_ID_OFFSET: usize = 39;

/// За `ClientHello` едут ранние данные.
pub const FLAG_EARLY_DATA: u8 = 0b0000_0001;

/// Разговор ведётся ChaCha20-Poly1305, а не AES-256-GCM.
pub const FLAG_CHACHA: u8 = 0b0000_0010;

/// Шифр, который выбрал клиент, — единственное, что говорит `ServerHello`
/// настоящего TLS 1.3 и что нам тоже нужно сказать.
const CIPHER_SUITE: u16 = 0x1301;

/// Группа X25519 в `key_share`.
const GROUP_X25519: u16 = 0x001d;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

/// Версия TLS, которую называет `ServerHello`.
const TLS13: u16 = 0x0304;

/// Данные опознания клиента — то, что лежит в `SessionID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth {
    /// Версия протокола.
    pub version: u8,
    /// Признаки: ранние данные, выбор шифра.
    pub flags: u8,
    /// Когда клиент собрал приветствие, секунды с начала эпохи.
    pub time: u64,
    /// Метка пользователя — по ней сервер находит пароль.
    pub user: [u8; 8],
}

impl Auth {
    /// Записывает данные опознания в шестнадцать байт.
    pub fn encode(&self) -> [u8; AUTH_PLAIN_LEN] {
        let mut out = [0u8; AUTH_PLAIN_LEN];
        out[0] = self.version;
        out[1] = self.flags;
        out[2..8].copy_from_slice(&self.time.to_be_bytes()[2..]);
        out[8..].copy_from_slice(&self.user);
        out
    }

    /// Разбирает шестнадцать байт данных опознания.
    pub fn decode(bytes: &[u8; AUTH_PLAIN_LEN]) -> Self {
        let mut time = [0u8; 8];
        time[2..].copy_from_slice(&bytes[2..8]);
        let mut user = [0u8; 8];
        user.copy_from_slice(&bytes[8..]);
        Self {
            version: bytes[0],
            flags: bytes[1],
            time: u64::from_be_bytes(time),
            user,
        }
    }

    /// За приветствием идут ранние данные.
    pub fn has_early_data(&self) -> bool {
        self.flags & FLAG_EARLY_DATA != 0
    }

    /// Разговор ведётся ChaCha20-Poly1305.
    pub fn wants_chacha(&self) -> bool {
        self.flags & FLAG_CHACHA != 0
    }
}

/// Дополнительные данные для AEAD: `ClientHello` с обнулённым `SessionID`.
///
/// Обнулять обязательно: `SessionID` — это и есть то, что шифруется, и
/// включить его в собственные дополнительные данные нельзя. Всё остальное
/// сообщение при этом заверено, то есть подставить чужой `SessionID` в свой
/// `ClientHello` не выйдет.
pub fn auth_aad(handshake: &[u8]) -> PingwinResult<Vec<u8>> {
    let end = SESSION_ID_OFFSET + SESSION_ID_LEN;
    if handshake.len() < end {
        return Err(PingwinError::malformed(
            "приветствие короче собственной головы",
        ));
    }
    let mut aad = handshake.to_vec();
    aad[SESSION_ID_OFFSET..end].fill(0);
    Ok(aad)
}

/// Закрывает данные опознания ключом, выведенным из постоянного ключа сервера.
pub fn seal_auth(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    auth: &Auth,
) -> PingwinResult<[u8; SESSION_ID_LEN]> {
    let mut buffer = auth.encode().to_vec();
    aead(key)?
        .seal_in_place_append_tag(zero_nonce(), Aad::from(aad), &mut buffer)
        .map_err(|_| PingwinError::malformed("данные опознания не зашифровались"))?;

    let mut out = [0u8; SESSION_ID_LEN];
    let sealed: &[u8; SESSION_ID_LEN] = buffer
        .first_chunk()
        .ok_or_else(|| PingwinError::malformed("данные опознания вышли не той длины"))?;
    out.copy_from_slice(sealed);
    Ok(out)
}

/// Открывает данные опознания.
///
/// `Err(Rejected)` — метка не сошлась: перед нами не наш клиент. Различить
/// «чужой клиент» и «наш, но с не тем ключом» нельзя, и не нужно — сервер в
/// обоих случаях отдаёт соединение прикрытию.
pub fn open_auth(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
) -> PingwinResult<Auth> {
    let mut buffer = session_id.to_vec();
    let plain = aead(key)?
        .open_in_place(zero_nonce(), Aad::from(aad), &mut buffer)
        .map_err(|_| PingwinError::Rejected)?;
    let plain: &[u8; AUTH_PLAIN_LEN] = plain
        .first_chunk()
        .ok_or_else(|| PingwinError::malformed("данные опознания вышли не той длины"))?;
    Ok(Auth::decode(plain))
}

/// Нонс здесь всегда нулевой, и это не упущение: ключ выведен из эфемерного
/// ключа клиента, то есть свой на каждое соединение, и второй раз под ним
/// ничего не шифруется.
fn zero_nonce() -> Nonce {
    Nonce::assume_unique_for_key([0u8; 12])
}

fn aead(key: &[u8; KEY_LEN]) -> PingwinResult<LessSafeKey> {
    let key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| PingwinError::malformed("ключ опознания не той длины"))?;
    Ok(LessSafeKey::new(key))
}

/// Что нужно серверу из `ClientHello`.
#[derive(Debug, Clone)]
pub struct ClientHelloParts {
    /// `SessionID` — данные опознания.
    pub session_id: [u8; SESSION_ID_LEN],
    /// Эфемерный ключ клиента из `key_share`.
    pub key_share: [u8; PUBLIC_LEN],
    /// Имя прикрытия из SNI, если оно есть. Только для журнала и прикрытия.
    pub server_name: Option<String>,
}

/// Разбирает сообщение `ClientHello` (без заголовка записи).
///
/// Разбор нарочно нестрогий ко всему, что нам не нужно: расширений у
/// браузерного приветствия два десятка, и требовать от них чего-либо значило
/// бы отвергать клиентов из-за чужого отпечатка.
pub fn parse_client_hello(handshake: &[u8]) -> PingwinResult<ClientHelloParts> {
    let mut reader = Reader::new(handshake);
    if reader.u8()? != 1 {
        return Err(PingwinError::malformed("это не ClientHello"));
    }
    let body_len = reader.u24()?;
    let body = reader.take(body_len)?;

    let mut reader = Reader::new(body);
    reader.take(2)?; // legacy_version
    reader.take(32)?; // random

    let session_len = usize::from(reader.u8()?);
    let session = reader.take(session_len)?;
    let session_id: [u8; SESSION_ID_LEN] = session
        .first_chunk()
        .copied()
        .filter(|_| session_len == SESSION_ID_LEN)
        .ok_or_else(|| {
            PingwinError::malformed(format!("SessionID длиной {session_len}, а нужен 32"))
        })?;

    let suites_len = reader.u16()?;
    reader.take(suites_len)?;
    let compression_len = usize::from(reader.u8()?);
    reader.take(compression_len)?;

    let extensions_len = reader.u16()?;
    let extensions = reader.take(extensions_len)?;

    let mut key_share = None;
    let mut server_name = None;
    let mut reader = Reader::new(extensions);
    while !reader.is_empty() {
        let kind = reader.u16_value()?;
        let len = reader.u16()?;
        let data = reader.take(len)?;
        match kind {
            EXT_KEY_SHARE => key_share = parse_key_share(data),
            EXT_SERVER_NAME => server_name = parse_server_name(data),
            _ => {}
        }
    }

    let key_share = key_share.ok_or_else(|| {
        PingwinError::malformed("в приветствии нет ключа X25519: это не наш клиент")
    })?;
    Ok(ClientHelloParts {
        session_id,
        key_share,
        server_name,
    })
}

/// Ищет долю X25519 среди предложенных клиентом.
///
/// Их бывает несколько (Firefox предлагает ещё и P-256) — берётся та, что
/// нужна нам, а остальные пропускаются молча.
fn parse_key_share(data: &[u8]) -> Option<[u8; PUBLIC_LEN]> {
    let mut reader = Reader::new(data);
    let list_len = reader.u16().ok()?;
    let list = reader.take(list_len).ok()?;

    let mut reader = Reader::new(list);
    while !reader.is_empty() {
        let group = reader.u16_value().ok()?;
        let len = reader.u16().ok()?;
        let share = reader.take(len).ok()?;
        if group == GROUP_X25519 && len == PUBLIC_LEN {
            return share.first_chunk().copied();
        }
    }
    None
}

fn parse_server_name(data: &[u8]) -> Option<String> {
    let mut reader = Reader::new(data);
    let list_len = reader.u16().ok()?;
    let list = reader.take(list_len).ok()?;

    let mut reader = Reader::new(list);
    while !reader.is_empty() {
        let kind = reader.u8().ok()?;
        let len = reader.u16().ok()?;
        let name = reader.take(len).ok()?;
        if kind == 0 {
            return String::from_utf8(name.to_vec()).ok();
        }
    }
    None
}

/// Собирает запись с `ServerHello`.
///
/// Всё, чего требует TLS 1.3 от ответа сервера в режиме совместимости: эхо
/// `SessionID`, шифр, `supported_versions` и `key_share`. Больше в открытом
/// виде настоящий сервер не показывает ничего — сертификат и `Finished` у
/// него уже зашифрованы.
pub fn build_server_hello(
    session_id: &[u8; SESSION_ID_LEN],
    ephemeral_public: &[u8; PUBLIC_LEN],
    random: &[u8; 32],
) -> PingwinResult<Vec<u8>> {
    let mut extensions = Vec::new();
    push_extension(
        &mut extensions,
        EXT_SUPPORTED_VERSIONS,
        &TLS13.to_be_bytes(),
    );

    let mut key_share = Vec::with_capacity(4 + PUBLIC_LEN);
    key_share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    key_share.extend_from_slice(&(PUBLIC_LEN as u16).to_be_bytes());
    key_share.extend_from_slice(ephemeral_public);
    push_extension(&mut extensions, EXT_KEY_SHARE, &key_share);

    let mut body = Vec::with_capacity(64 + extensions.len());
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(random);
    body.push(SESSION_ID_LEN as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&CIPHER_SUITE.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(2);
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut out = Vec::with_capacity(record::HEADER_LEN + handshake.len());
    out.extend_from_slice(&record::header(
        record::CONTENT_HANDSHAKE,
        record::VERSION_DATA,
        handshake.len(),
    )?);
    out.extend_from_slice(&handshake);
    Ok(out)
}

fn push_extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Достаёт эфемерный ключ сервера из записи `ServerHello`.
///
/// Разбор — чужой ([`penguin_utls::server_hello`]): он уже написан и проверен
/// на настоящих ответах, и второй такой же здесь был бы вторым ответом на
/// вопрос, что делать с расширением неизвестной длины.
pub fn server_key_share(server_hello: &[u8]) -> PingwinResult<[u8; PUBLIC_LEN]> {
    let hello: ServerHello = server_hello::parse(server_hello)?;
    let share = hello
        .key_share
        .ok_or_else(|| PingwinError::malformed("в ответе сервера нет key_share"))?;
    if share.group != GROUP_X25519 {
        return Err(PingwinError::malformed(format!(
            "сервер ответил группой {:#06x}, а не X25519",
            share.group
        )));
    }
    share
        .data
        .first_chunk()
        .copied()
        .ok_or_else(|| PingwinError::malformed("ключ сервера не тридцати двух байт"))
}

/// Сколько байт занимает запись, начало которой уже прочитано.
///
/// `None` — заголовка ещё не набралось.
pub fn record_len(bytes: &[u8]) -> PingwinResult<Option<usize>> {
    let Some(head) = bytes.first_chunk::<{ record::HEADER_LEN }>() else {
        return Ok(None);
    };
    let (_, len) = record::parse_header(head)?;
    Ok(Some(record::HEADER_LEN + len))
}

/// Чтение байтов по порядку с проверкой границ на каждом шаге.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn take(&mut self, len: usize) -> PingwinResult<&'a [u8]> {
        if self.rest.len() < len {
            return Err(PingwinError::malformed(format!(
                "приветствие обрывается: нужно {len} байт, осталось {}",
                self.rest.len()
            )));
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> PingwinResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16_value(&mut self) -> PingwinResult<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Двухбайтная длина — читается чаще всего именно как длина.
    fn u16(&mut self) -> PingwinResult<usize> {
        Ok(usize::from(self.u16_value()?))
    }

    fn u24(&mut self) -> PingwinResult<usize> {
        let bytes = self.take(3)?;
        let len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        usize::try_from(len).map_err(|_| PingwinError::malformed("длина не помещается в адрес"))
    }
}

#[cfg(test)]
mod tests {
    use penguin_core::address::Address;
    use penguin_utls::Fingerprint;

    use super::*;

    fn auth() -> Auth {
        Auth {
            version: VERSION,
            flags: FLAG_EARLY_DATA,
            time: 1_760_000_000,
            user: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    #[test]
    fn the_auth_block_is_exactly_the_session_id_minus_the_tag() {
        // Иначе оно не влезет в `SessionID`, и приветствие перестанет быть
        // похожим на браузерное.
        assert_eq!(auth().encode().len(), SESSION_ID_LEN - 16);
    }

    #[test]
    fn an_auth_block_survives_the_round_trip() {
        assert_eq!(Auth::decode(&auth().encode()), auth());
    }

    #[test]
    fn a_time_that_needs_all_six_bytes_survives() {
        // Шесть байт хватает до восьмого тысячелетия; обрезать старшие
        // значило бы получить отметку из прошлого и отказ по окну времени.
        let far = Auth {
            time: 0x0000_FFFF_FFFF_FFFF,
            ..auth()
        };
        assert_eq!(Auth::decode(&far.encode()).time, far.time);
    }

    #[test]
    fn what_is_sealed_opens_with_the_same_key_and_the_same_hello() {
        let key = [7u8; KEY_LEN];
        let aad = vec![9u8; 100];
        let sealed = seal_auth(&key, &aad, &auth()).expect("шифруется");
        assert_eq!(
            open_auth(&key, &aad, &sealed).expect("расшифровывается"),
            auth()
        );
    }

    #[test]
    fn a_stranger_gets_rejected_rather_than_misread() {
        // Ровно на этом стоит устойчивость к активной проверке: без ключа
        // сервера `SessionID` — тридцать два случайных байта.
        let sealed = seal_auth(&[7u8; KEY_LEN], &[9u8; 100], &auth()).expect("шифруется");
        assert!(matches!(
            open_auth(&[8u8; KEY_LEN], &[9u8; 100], &sealed),
            Err(PingwinError::Rejected)
        ));
    }

    #[test]
    fn the_session_id_cannot_be_moved_into_another_hello() {
        // Дополнительные данные — всё приветствие: перенос `SessionID` в
        // чужое сообщение обязан ломать метку.
        let key = [7u8; KEY_LEN];
        let sealed = seal_auth(&key, &[9u8; 100], &auth()).expect("шифруется");
        assert!(open_auth(&key, &[9u8; 99], &sealed).is_err());
    }

    #[test]
    fn the_aad_zeroes_exactly_the_session_id() {
        let handshake = vec![0xAB; 200];
        let aad = auth_aad(&handshake).expect("считается");
        assert_eq!(aad.len(), handshake.len());
        assert!(
            aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(aad[SESSION_ID_OFFSET - 1], 0xAB);
        assert_eq!(aad[SESSION_ID_OFFSET + SESSION_ID_LEN], 0xAB);
    }

    #[test]
    fn a_hello_shorter_than_its_own_head_is_refused_without_panicking() {
        assert!(auth_aad(&[0u8; 10]).is_err());
    }

    /// Настоящее приветствие с настоящим отпечатком — то, что уходит на провод.
    fn real_hello(session_id: [u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let (hello, keys) = Fingerprint::Chrome
            .build(&Address::domain("www.microsoft.com"), session_id)
            .expect("собирается");
        let public = keys
            .iter()
            .find(|key| key.public.len() == PUBLIC_LEN)
            .map(|key| {
                let mut out = [0u8; PUBLIC_LEN];
                out.copy_from_slice(&key.public);
                out
            })
            .expect("X25519 предлагает каждый отпечаток");
        (hello.handshake_bytes().to_vec(), public)
    }

    #[test]
    fn a_real_browser_hello_parses_into_what_the_server_needs() {
        // Разбор проверяется на том самом сообщении, которое уходит на
        // провод, а не на выдуманном: своя пара «собрал — разобрал»
        // согласилась бы сама с собой при любой ошибке в раскладке.
        let session_id = [0x5A; 32];
        let (handshake, public) = real_hello(session_id);

        let parts = parse_client_hello(&handshake).expect("разбирается");
        assert_eq!(parts.session_id, session_id);
        assert_eq!(parts.key_share, public);
        assert_eq!(parts.server_name.as_deref(), Some("www.microsoft.com"));
    }

    #[test]
    fn every_fingerprint_offers_a_key_the_server_can_find() {
        // Firefox предлагает ещё и P-256: взять надо X25519, а не первую
        // попавшуюся долю.
        for fingerprint in [
            Fingerprint::Chrome,
            Fingerprint::Firefox,
            Fingerprint::Safari,
        ] {
            let (hello, _) = fingerprint
                .build(&Address::domain("example.com"), [1u8; 32])
                .expect("собирается");
            parse_client_hello(hello.handshake_bytes())
                .unwrap_or_else(|err| panic!("{fingerprint:?}: {err}"));
        }
    }

    #[test]
    fn a_truncated_hello_is_an_error_not_a_panic() {
        // Приветствие приходит из сети: обрезать его может кто угодно.
        let (handshake, _) = real_hello([0; 32]);
        for len in [0, 1, 5, 39, 50, handshake.len() - 1] {
            assert!(parse_client_hello(&handshake[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn a_server_hello_carries_the_key_back() {
        let session_id = [0x11; SESSION_ID_LEN];
        let public = [0x22; PUBLIC_LEN];
        let record = build_server_hello(&session_id, &public, &[0x33; 32]).expect("собирается");

        assert_eq!(record[0], record::CONTENT_HANDSHAKE);
        assert_eq!(server_key_share(&record).expect("разбирается"), public);
    }

    #[test]
    fn the_server_hello_echoes_the_session_id_the_way_tls_requires() {
        // Настоящий клиент TLS 1.3 сверяет эхо и рвёт соединение, если оно не
        // совпало. Наш не сверяет, но выглядеть должен так же.
        let session_id = [0x11; SESSION_ID_LEN];
        let record =
            build_server_hello(&session_id, &[0x22; PUBLIC_LEN], &[0x33; 32]).expect("собирается");
        let hello = server_hello::parse(&record).expect("разбирается");
        assert_eq!(hello.session_id, session_id);
        assert_eq!(hello.supported_version, Some(TLS13));
    }

    #[test]
    fn the_length_of_a_record_is_known_from_its_header_alone() {
        let record = build_server_hello(&[0; SESSION_ID_LEN], &[0; PUBLIC_LEN], &[0; 32])
            .expect("собирается");
        assert_eq!(
            record_len(&record).expect("разбирается"),
            Some(record.len())
        );
        assert_eq!(record_len(&record[..3]).expect("разбирается"), None);
    }
}

//! Рукопожатие: одно приветствие туда, одно обратно — и разговор начался.
//!
//! ```text
//!  клиент                                          сервер
//!    │  [ложное приветствие, малый TTL]              │   ← только при обходе DPI
//!    │  ClientHello  (ключ в key_share,              │
//!    │                опознание в SessionID)         │
//!    │  ChangeCipherSpec                             │
//!    │  [одна запись ранних данных]                  │   ← 0-RTT
//!    ├──────────────────────────────────────────────►│
//!    │                                               │  проверяет опознание,
//!    │                                               │  время и повтор
//!    │◄──────────────────────────────────────────────┤
//!    │  ServerHello  (ключ в key_share)              │
//!    │  ChangeCipherSpec                             │
//!    │  записи данных                                │
//! ```
//!
//! # Сколько это стоит
//!
//! Один оборот до первого байта ответа — и ноль, если считать от первого
//! запроса: запрос уходит вместе с приветствием. Для сравнения, у любого
//! протокола поверх настоящего TLS до первого запроса проходит два оборота
//! (TCP плюс TLS), а с проверкой сертификата — иногда три.
//!
//! # Что делает сервер, не узнав клиента
//!
//! Ничего особенного — и в этом смысл. Он не отвечает отказом, не рвёт
//! соединение и не медлит: он отдаёт соединение прикрытию, то есть настоящему
//! сайту, вместе со всеми уже прочитанными байтами. Тот, кто пробует сервер
//! на прочность, видит обычный сайт — потому что перед ним и есть обычный
//! сайт.
//!
//! Отсюда же и терпимость к ложным приветствиям ([`MAX_FOREIGN_HELLOS`]):
//! ложная посылка обхода DPI не проходит опознание ровно так же, как чужое
//! приветствие, и отдельной метки, по которой сервер отличал бы её от
//! пробы, нет намеренно — такая метка искалась бы в трафике.

use std::time::{Duration, Instant};

use penguin_core::address::Address;
use penguin_transport::TransportError;
use penguin_transport::aead::{Algorithm, Cipher};
use penguin_transport::desync::Desync;
use penguin_transport::desync::write::{TtlStream, send_first_flight};
use penguin_utls::Fingerprint;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{PingwinError, PingwinResult};
use crate::wire::hello::{self, Auth, SESSION_ID_LEN};
use crate::wire::keys::{self, PUBLIC_LEN, SessionKeys, StaticKeyPair};
use crate::wire::padding::Padding;
use crate::wire::record;

/// Сколько чужих приветствий сервер прочитает, прежде чем отдать соединение
/// прикрытию.
///
/// Два — это ложная посылка обхода DPI и одна её повторная передача. Больше
/// незачем: настоящий клиент шлёт своё приветствие сразу за ложным, а тот,
/// кто пробует сервер, не пришлёт правильного никогда.
pub const MAX_FOREIGN_HELLOS: usize = 2;

/// Сколько ждать следующего приветствия после чужого.
///
/// Настоящий клиент шлёт своё сразу за ложным — одной посылкой, — и секунды
/// хватает даже с настроенной паузой между кусками. Тот, кто пробует сервер,
/// не пришлёт ничего, и держать ради него сокет до общего срока рукопожатия
/// незачем: чем раньше соединение уйдёт прикрытию, тем меньше оно отличается
/// от обычного.
const DECOY_GRACE: Duration = Duration::from_secs(1);

/// Сколько байт сервер прочитает до опознания.
///
/// Иначе тот, кто шлёт бесконечный поток записей, заставит держать его в
/// памяти целиком: прочитанное копится, чтобы уйти прикрытию.
const MAX_FOREIGN_BYTES: usize = 64 * 1024;

/// Что нужно клиенту, чтобы поздороваться.
pub struct ClientParams<'a> {
    /// Открытый ключ сервера.
    pub server_public: [u8; PUBLIC_LEN],
    /// Пароль пользователя.
    pub password: &'a [u8],
    /// Имя прикрытия — оно уходит в SNI.
    pub cover: &'a Address,
    /// Чьим приветствием притворяться.
    pub fingerprint: Fingerprint,
    /// Шифр записей.
    pub algorithm: Algorithm,
    /// План обхода DPI.
    pub desync: &'a Desync,
    /// Ранние данные: кадры, которые уедут вместе с приветствием.
    ///
    /// Пусто — 0-RTT не используется.
    pub early: &'a [u8],
}

/// Чем кончилось рукопожатие у клиента.
pub struct Established {
    /// Ключи соединения.
    pub keys: SessionKeys,
    /// Шифр записей.
    pub algorithm: Algorithm,
    /// Уехали ли ранние данные.
    pub early_sent: bool,
}

/// Здоровается с сервером и выводит ключи соединения.
pub async fn connect<S>(io: &mut S, params: &ClientParams<'_>) -> PingwinResult<Established>
where
    S: AsyncRead + TtlStream,
{
    let (mut hello_message, exchange) = build_client_hello(params)?;

    let shared_static = exchange
        .x25519_diffie_hellman(&params.server_public)
        .ok_or_else(|| PingwinError::malformed("отпечаток не предложил ключа X25519"))?;

    let early_sent = !params.early.is_empty();
    let auth = Auth {
        version: hello::VERSION,
        flags: flags(early_sent, params.algorithm),
        time: crate::wire::replay::now_seconds(),
        user: keys::user_tag(params.password, &params.server_public)?,
    };
    let aad = hello::auth_aad(hello_message.handshake_bytes())?;
    let probe = keys::probe_key(&shared_static)?;
    hello_message.patch_session_id(hello::seal_auth(&probe, &aad, &auth)?);

    let client_hello = hello_message.record_bytes();
    let mut flight = client_hello.clone();
    flight.extend_from_slice(&record::CHANGE_CIPHER_SPEC);
    if early_sent {
        let key = keys::zero_rtt_key(&keys::hash(&client_hello), &shared_static, params.password)?;
        let mut cipher = Cipher::new(params.algorithm, &key)?;
        let mut frames = params.early.to_vec();
        crate::wire::padding::pad(&mut frames, Padding::from_seed(&key).target(0));
        record::seal(&mut cipher, &frames, &mut flight)?;
    }

    let decoy = params
        .desync
        .wants_fake()
        .then(|| decoy_hello(params))
        .transpose()?;
    send_first_flight(
        io,
        params.desync,
        &flight,
        decoy.as_deref(),
        params.cover.as_domain(),
    )
    .await?;

    let server_hello = read_record(io, record::CONTENT_HANDSHAKE)
        .await
        .map_err(unrecognised)?;
    let server_public = hello::server_key_share(&server_hello).map_err(unrecognised)?;
    let shared_ephemeral = exchange
        .x25519_diffie_hellman(&server_public)
        .ok_or_else(|| PingwinError::malformed("отпечаток не предложил ключа X25519"))?;

    let transcript = keys::transcript(&client_hello, &server_hello);
    let keys = keys::session_keys(
        &transcript,
        &shared_static,
        &shared_ephemeral,
        params.password,
    )?;

    Ok(Established {
        keys,
        algorithm: params.algorithm,
        early_sent,
    })
}

/// Ответ, не похожий на наш, — это ответ прикрытия.
///
/// Сервер, не узнавший клиента, не отказывает: он молча отдаёт соединение
/// настоящему сайту, и клиент получает от него `HTTP/1.1 400` или что там
/// ответит веб-сервер. Разбирать это как «сервер ответил не по протоколу»
/// значит отправить человека искать поломку в сети — а искать надо в двух
/// полях профиля.
///
/// Обрыв и ошибки ввода-вывода при этом остаются собой: сеть, пропавшая
/// посреди рукопожатия, — не то же самое, что чужой пароль, и повторять её
/// стоит.
fn unrecognised(err: PingwinError) -> PingwinError {
    match err {
        PingwinError::Malformed(_) | PingwinError::Utls(_) => PingwinError::Rejected,
        other => other,
    }
}

fn flags(early: bool, algorithm: Algorithm) -> u8 {
    let mut flags = 0;
    if early {
        flags |= hello::FLAG_EARLY_DATA;
    }
    if algorithm == Algorithm::ChaCha20Poly1305 {
        flags |= hello::FLAG_CHACHA;
    }
    flags
}

fn build_client_hello(
    params: &ClientParams<'_>,
) -> PingwinResult<(penguin_utls::ClientHello, penguin_utls::KeyExchange)> {
    // Нулевой `SessionID` на первом шаге: данные опознания заверяют весь
    // `ClientHello` целиком, а он неизвестен, пока не собран.
    let (hello, exchanges) = params
        .fingerprint
        .build(params.cover, [0u8; SESSION_ID_LEN])?;
    let exchange = exchanges
        .into_iter()
        .find(|exchange| exchange.public.len() == PUBLIC_LEN)
        .ok_or_else(|| PingwinError::malformed("отпечаток не предложил ключа X25519"))?;
    Ok((hello, exchange))
}

/// Ложное приветствие для обхода DPI.
///
/// Тот же отпечаток и то же имя прикрытия, что у настоящего, — отличается
/// только `SessionID`, и он случайный. Для DPI это второе такое же
/// приветствие; для сервера — чужое, которое он пропустит по своему обычному
/// правилу, не зная и не спрашивая, откуда оно взялось.
fn decoy_hello(params: &ClientParams<'_>) -> PingwinResult<Vec<u8>> {
    let (hello, _) = params
        .fingerprint
        .build(params.cover, penguin_utls::random_session_id())?;
    Ok(hello.record_bytes())
}

/// Что сервер знает о клиенте после рукопожатия.
pub struct Accepted {
    /// Ключи соединения.
    pub keys: SessionKeys,
    /// Шифр записей.
    pub algorithm: Algorithm,
    /// Метка пользователя, чей пароль подошёл.
    pub user: [u8; 8],
    /// Имя прикрытия, которое назвал клиент.
    pub cover: Option<String>,
    /// Расшифрованные ранние данные, если они были.
    pub early: Option<Vec<u8>>,
}

/// Чем кончилось рукопожатие у сервера.
pub enum Outcome {
    /// Клиент опознан.
    Ours(Box<Accepted>),
    /// Клиент не опознан. Внутри — всё, что успели прочитать: эти байты
    /// уходят прикрытию, иначе оно получит запрос без начала.
    Foreign(Vec<u8>),
}

/// Правила сервера, которых крейт протокола не знает и знать не должен.
pub trait ServerPolicy: Send + Sync {
    /// Пароль пользователя по его метке. `None` — такого пользователя нет.
    fn password(&self, user: &[u8; 8]) -> Option<Vec<u8>>;

    /// Принимает эфемерный ключ клиента и отметку времени.
    ///
    /// `false` — повтор либо разъехавшиеся часы. Сервер отдаёт такое
    /// соединение прикрытию: отвечать отказом значило бы подтвердить, что
    /// здесь сервер, а не сайт.
    fn admit(&self, ephemeral: &[u8; PUBLIC_LEN], time: u64) -> bool;
}

/// Принимает соединение: читает приветствия, пока не найдёт своё.
///
/// `limit` — сколько всего отпущено на рукопожатие. Срок стоит **здесь**, а
/// не у вызывающего, ровно по одной причине: истёкший срок — это не ошибка, а
/// ещё один способ понять, что клиент чужой, и прочитанное к этому моменту
/// надо отдать прикрытию. Обёрнутый снаружи `timeout` эти байты выбрасывал
/// бы — и соединение закрывалось бы там, где обычный сайт ответил бы.
pub async fn accept<S>(
    io: &mut S,
    server: &StaticKeyPair,
    policy: &dyn ServerPolicy,
    limit: Duration,
) -> PingwinResult<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let started = Instant::now();
    let mut seen = Vec::new();
    let mut failures = 0usize;

    loop {
        // Первую запись ждём столько, сколько отпущено на всё рукопожатие.
        // После первого чужого приветствия — недолго: настоящий клиент шлёт
        // своё сразу за ложным.
        let left = limit.saturating_sub(started.elapsed());
        let wait = if failures == 0 {
            left
        } else {
            DECOY_GRACE.min(left)
        };

        let record = match tokio::time::timeout(wait, read_any_record(io, &mut seen)).await {
            Ok(read) => read,
            Err(_elapsed) => return give_up(seen),
        };

        // Обрыв на чтении — тоже «не наш клиент», а не ошибка: прочитанное
        // всё равно надо отдать прикрытию, иначе оно получит запрос без
        // начала, ответит не тем, и разница будет видна снаружи.
        let record = match record {
            Ok(Some(record)) => record,
            // Заголовок не похож на TLS вовсе: обычный `GET / HTTP/1.1` и
            // прочее, чем порт проверяют первым делом. Ждать от него тела
            // записи бессмысленно — его нет и не будет.
            Ok(None) => return Ok(Outcome::Foreign(seen)),
            Err(err) if !seen.is_empty() => {
                tracing::debug!(%err, "соединение оборвалось до опознания");
                return Ok(Outcome::Foreign(seen));
            }
            Err(err) => return Err(err),
        };
        if seen.len() > MAX_FOREIGN_BYTES {
            return Ok(Outcome::Foreign(seen));
        }

        // Не приветствие — `ChangeCipherSpec` и прочее, что шлёт и наш
        // клиент. Такие записи не считаются чужими: считать их значило бы
        // отдавать прикрытию собственного клиента.
        let Some(body) = data_of(&record, record::CONTENT_HANDSHAKE) else {
            continue;
        };

        match authenticate(server, policy, body) {
            Ok(accepted) => return finish(io, &record, accepted).await,
            Err(_) => {
                failures += 1;
                if failures > MAX_FOREIGN_HELLOS {
                    return Ok(Outcome::Foreign(seen));
                }
            }
        }
    }
}

/// Данные опознания, разобранные из чужого приветствия.
struct Authenticated {
    session_id: [u8; SESSION_ID_LEN],
    client_public: [u8; PUBLIC_LEN],
    cover: Option<String>,
    auth: Auth,
    password: Vec<u8>,
    shared_static: [u8; 32],
}

fn authenticate(
    server: &StaticKeyPair,
    policy: &dyn ServerPolicy,
    handshake: &[u8],
) -> PingwinResult<Authenticated> {
    let parts = hello::parse_client_hello(handshake)?;
    let shared_static = server.agree(&parts.key_share);
    let probe = keys::probe_key(&shared_static)?;
    let aad = hello::auth_aad(handshake)?;
    let auth = hello::open_auth(&probe, &aad, &parts.session_id)?;

    if auth.version != hello::VERSION {
        return Err(PingwinError::malformed(format!(
            "версия протокола {}, а сервер говорит на {}",
            auth.version,
            hello::VERSION
        )));
    }
    if !policy.admit(&parts.key_share, auth.time) {
        return Err(PingwinError::Rejected);
    }
    let password = policy.password(&auth.user).ok_or(PingwinError::Rejected)?;

    Ok(Authenticated {
        session_id: parts.session_id,
        client_public: parts.key_share,
        cover: parts.server_name,
        auth,
        password,
        shared_static,
    })
}

async fn finish<S>(
    io: &mut S,
    client_hello: &[u8],
    authenticated: Authenticated,
) -> PingwinResult<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let algorithm = if authenticated.auth.wants_chacha() {
        Algorithm::ChaCha20Poly1305
    } else {
        Algorithm::Aes256Gcm
    };

    // Ранние данные читаются **до** ответа: они уже в сокете, и ответ на них
    // всё равно уйдёт после `ServerHello`.
    let early = if authenticated.auth.has_early_data() {
        Some(
            read_early(
                io,
                client_hello,
                &authenticated.shared_static,
                &authenticated.password,
                algorithm,
            )
            .await?,
        )
    } else {
        None
    };

    let ephemeral = StaticSecret::random();
    let ephemeral_public = *PublicKey::from(&ephemeral).as_bytes();
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);

    let server_hello =
        hello::build_server_hello(&authenticated.session_id, &ephemeral_public, &random)?;
    let mut flight = server_hello.clone();
    flight.extend_from_slice(&record::CHANGE_CIPHER_SPEC);
    io.write_all(&flight).await?;
    io.flush().await?;

    let shared_ephemeral = *ephemeral
        .diffie_hellman(&PublicKey::from(authenticated.client_public))
        .as_bytes();
    let transcript = keys::transcript(client_hello, &server_hello);
    let keys = keys::session_keys(
        &transcript,
        &authenticated.shared_static,
        &shared_ephemeral,
        &authenticated.password,
    )?;

    Ok(Outcome::Ours(Box::new(Accepted {
        keys,
        algorithm,
        user: authenticated.auth.user,
        cover: authenticated.cover,
        early,
    })))
}

/// Читает единственную запись ранних данных.
///
/// Их ровно одна, и это часть формата: признак в данных опознания говорит
/// «дальше идёт одна запись», а не «дальше идут ранние данные, пока я не
/// скажу». Договорённость про «пока не скажу» потребовала бы отдельного
/// сообщения о конце ранних данных — того самого, из-за которого у TLS 1.3
/// эта часть рукопожатия самая запутанная.
async fn read_early<S>(
    io: &mut S,
    client_hello: &[u8],
    shared_static: &[u8; 32],
    password: &[u8],
    algorithm: Algorithm,
) -> PingwinResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let key = keys::zero_rtt_key(&keys::hash(client_hello), shared_static, password)?;
    let mut cipher = Cipher::new(algorithm, &key)?;

    // Между приветствием и ранними данными едет `ChangeCipherSpec` — так же,
    // как у настоящего TLS 1.3 с ранними данными. Пропускаем её, а не считаем
    // ошибкой: свой же клиент её и посылает.
    let record = read_record(io, record::CONTENT_DATA).await?;
    let body = data_of(&record, record::CONTENT_DATA)
        .ok_or_else(|| PingwinError::malformed("вместо ранних данных пришло не то"))?;

    let mut body = body.to_vec();
    let plain = record::open(&mut cipher, &mut body)?;
    body.truncate(plain);
    Ok(body)
}

/// Чем закончить, когда время вышло.
///
/// Успели что-то прочитать — это чужой клиент, и прочитанное уходит
/// прикрытию. Не успели ничего — соединение молчало с самого начала, и
/// поднимать ради него ещё одно, к прикрытию, незачем: обычный веб-сервер
/// такое тоже просто закрывает по своему сроку.
fn give_up(seen: Vec<u8>) -> PingwinResult<Outcome> {
    if seen.is_empty() {
        return Err(TransportError::Timeout("рукопожатие pingwin").into());
    }
    Ok(Outcome::Foreign(seen))
}

/// Похож ли заголовок на запись TLS хоть отдалённо.
///
/// Проверка грубая и намеренно такая: тип записи из тех пяти, что бывают у
/// TLS, и старший байт версии — тройка. `GET / HTTP/1.1` не проходит ни по
/// одному условию, а любой настоящий клиент проходит по обоим.
///
/// Без неё `GET ` разбирался бы как запись типа `0x47` длиной 0x202F, сервер
/// ждал бы восемь килобайт тела до конца срока и закрыл бы соединение
/// молча — то есть повёл бы себя не так, как повёл бы себя сайт. Ровно по
/// этой разнице такие серверы и находят.
fn looks_like_tls(header: &[u8; record::HEADER_LEN]) -> bool {
    matches!(header[0], 20..=24) && header[1] == 0x03
}

/// Читает одну запись целиком, дописывая прочитанное в `seen`.
///
/// `Ok(None)` — заголовок не похож на TLS: читать дальше нечего, а пять уже
/// прочитанных байт остаются в `seen` и уедут прикрытию.
///
/// Прочитанное попадает в `seen` **до** разбора, а не после: иначе начало
/// чужого запроса терялось бы, и прикрытие получало бы его без первых байт.
async fn read_any_record<S>(io: &mut S, seen: &mut Vec<u8>) -> PingwinResult<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; record::HEADER_LEN];
    io.read_exact(&mut header).await.map_err(closed)?;
    seen.extend_from_slice(&header);
    if !looks_like_tls(&header) {
        return Ok(None);
    }
    let (_, len) = record::parse_header(&header)?;

    let mut out = Vec::with_capacity(record::HEADER_LEN + len);
    out.extend_from_slice(&header);
    out.resize(record::HEADER_LEN + len, 0);
    io.read_exact(&mut out[record::HEADER_LEN..])
        .await
        .map_err(closed)?;

    seen.extend_from_slice(&out[record::HEADER_LEN..]);
    Ok(Some(out))
}

/// Читает записи, пока не встретится запись нужного типа.
async fn read_record<S>(io: &mut S, wanted: u8) -> PingwinResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut ignored = Vec::new();
    loop {
        // Здесь мы уже внутри своего разговора: собеседник обязан говорить
        // записями, и «это не TLS» — ошибка, а не повод уйти к прикрытию.
        let record = read_any_record(io, &mut ignored)
            .await?
            .ok_or_else(|| PingwinError::malformed("вместо записи пришло не то"))?;
        if data_of(&record, wanted).is_some() {
            return Ok(record);
        }
    }
}

/// Тело записи, если её тип — тот, которого ждали.
fn data_of(record: &[u8], wanted: u8) -> Option<&[u8]> {
    (record.first() == Some(&wanted)).then(|| &record[record::HEADER_LEN..])
}

fn closed(err: std::io::Error) -> PingwinError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        return PingwinError::disconnected("собеседник закрыл соединение до рукопожатия");
    }
    PingwinError::Io(err)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use penguin_transport::desync::DesyncConfig;
    use tokio::io::{DuplexStream, ReadBuf, duplex};

    use super::*;
    use crate::wire::frame;
    use crate::wire::replay::{ReplayWindow, now_seconds};

    /// Соединение с TTL, которого на самом деле нет.
    ///
    /// Обход DPI проверяется своим тестом в `penguin-transport`; здесь нужен
    /// только обмен байтами, а `TcpStream` для него потребовал бы сокета.
    struct Fake(DuplexStream);

    impl AsyncRead for Fake {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Fake {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl TtlStream for Fake {
        fn ttl(&self) -> io::Result<u32> {
            Ok(64)
        }

        fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
            Ok(())
        }

        fn set_nodelay(&self, _on: bool) -> io::Result<()> {
            Ok(())
        }
    }

    /// Сервер с одним пользователем и настоящим окном повторов.
    struct Policy {
        password: Vec<u8>,
        tag: [u8; 8],
        replay: Mutex<ReplayWindow>,
    }

    impl Policy {
        fn new(password: &str, server_public: &[u8; PUBLIC_LEN]) -> Self {
            Self {
                password: password.as_bytes().to_vec(),
                tag: keys::user_tag(password.as_bytes(), server_public).expect("считается"),
                replay: Mutex::new(ReplayWindow::default()),
            }
        }
    }

    impl ServerPolicy for Policy {
        fn password(&self, user: &[u8; 8]) -> Option<Vec<u8>> {
            (*user == self.tag).then(|| self.password.clone())
        }

        fn admit(&self, ephemeral: &[u8; PUBLIC_LEN], time: u64) -> bool {
            let Ok(mut replay) = self.replay.lock() else {
                return false;
            };
            let now = now_seconds();
            replay.time_is_fresh(time, now) && replay.admit(*ephemeral, now)
        }
    }

    /// Срок рукопожатия в проверках.
    ///
    /// Заведомо больше, чем нужно исправному обмену, и заметно меньше, чем
    /// готов ждать человек, глядя на упавший тест.
    const TEST_LIMIT: Duration = Duration::from_secs(5);

    fn cover() -> Address {
        Address::domain("www.microsoft.com")
    }

    /// Прогоняет рукопожатие целиком и отдаёт обе стороны.
    async fn shake(
        password: &str,
        early: &[u8],
        desync: Desync,
        policy_password: &str,
    ) -> (PingwinResult<Established>, PingwinResult<Outcome>) {
        let server_keys = StaticKeyPair::generate();
        let server_public = server_keys.public;
        let policy = Policy::new(policy_password, &server_public);

        let (client_io, server_io) = duplex(64 * 1024);
        let mut client_io = Fake(client_io);
        let mut server_io = Fake(server_io);

        let server_side =
            tokio::spawn(
                async move { accept(&mut server_io, &server_keys, &policy, TEST_LIMIT).await },
            );

        let cover = cover();
        let client = connect(
            &mut client_io,
            &ClientParams {
                server_public,
                password: password.as_bytes(),
                cover: &cover,
                fingerprint: Fingerprint::Chrome,
                algorithm: Algorithm::Aes256Gcm,
                desync: &desync,
                early,
            },
        )
        .await;

        let server = server_side.await.unwrap_or_else(|err| {
            Err(PingwinError::disconnected(format!("задача сервера: {err}")))
        });
        (client, server)
    }

    #[tokio::test]
    async fn both_sides_end_up_with_the_same_keys() {
        // Это и есть рукопожатие: разошлись ключи — разошлось всё.
        let (client, server) = shake("secret", &[], Desync::disabled(), "secret").await;
        let client = client.expect("клиент поздоровался");
        let Ok(Outcome::Ours(accepted)) = server else {
            panic!("свой клиент принят за чужого");
        };
        assert_eq!(client.keys.c2s, accepted.keys.c2s);
        assert_eq!(client.keys.s2c, accepted.keys.s2c);
        assert_eq!(client.keys.pad_c2s, accepted.keys.pad_c2s);
        assert_eq!(accepted.cover.as_deref(), Some("www.microsoft.com"));
        assert!(accepted.early.is_none());
    }

    #[tokio::test]
    async fn the_first_request_rides_with_the_hello() {
        // Ради этого протокол и устроен так, как устроен: до первого байта
        // ответа проходит один оборот, а не три.
        let early = frame::encode(frame::OPEN, 1, b"target").expect("собирается");
        let (client, server) = shake("secret", &early, Desync::disabled(), "secret").await;
        assert!(client.expect("клиент поздоровался").early_sent);

        let Ok(Outcome::Ours(accepted)) = server else {
            panic!("свой клиент принят за чужого");
        };
        let plain = accepted.early.expect("ранние данные пришли");
        let (header, body) = frame::Frames::new(&plain)
            .next()
            .expect("кадр есть")
            .expect("разбирается");
        assert_eq!(header.cmd, frame::OPEN);
        assert_eq!(body, b"target");
    }

    #[tokio::test]
    async fn a_wrong_password_looks_like_an_ordinary_site() {
        // Сервер не отвечает отказом — он отдаёт соединение прикрытию. Всё,
        // что клиент из этого узнаёт, — что разговора не вышло.
        let (client, server) = shake("secret", &[], Desync::disabled(), "другой").await;
        assert!(matches!(server, Ok(Outcome::Foreign(_))));
        assert!(client.is_err(), "клиент решил, что всё хорошо");
    }

    #[tokio::test]
    async fn what_the_server_read_goes_to_the_cover_untouched() {
        // Иначе прикрытие получит запрос без начала и ответит ошибкой — а
        // это и есть та самая разница, по которой сервер находят.
        let (mut client_io, mut server_io) = duplex(64 * 1024);
        let server_keys = StaticKeyPair::generate();
        let policy = Policy::new("secret", &server_keys.public);

        let probe: Vec<u8> = {
            let (hello, _) = Fingerprint::Chrome
                .build(&cover(), penguin_utls::random_session_id())
                .expect("собирается");
            hello.record_bytes()
        };
        let sent = probe.clone();
        tokio::spawn(async move {
            for _ in 0..=MAX_FOREIGN_HELLOS {
                if client_io.write_all(&sent).await.is_err() {
                    break;
                }
            }
        });

        let outcome = accept(&mut server_io, &server_keys, &policy, TEST_LIMIT)
            .await
            .expect("чтение");
        let Outcome::Foreign(seen) = outcome else {
            panic!("чужое приветствие принято за своё");
        };
        assert!(seen.starts_with(&probe), "начало запроса потеряно");
        assert_eq!(seen.len() % probe.len(), 0);
    }

    #[tokio::test]
    async fn the_cover_answering_instead_of_the_server_reads_as_a_refusal() {
        // Так это и выглядит на живом сервере: не узнав клиента, он отдаёт
        // соединение веб-серверу, и клиент получает от него `400`. Назвать
        // это «сервер ответил не по протоколу» значит отправить человека
        // искать поломку в сети вместо двух полей профиля.
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut client_io = Fake(client_io);

        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            let _ = server_io.read(&mut buffer).await;
            let _ = server_io
                .write_all(b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n")
                .await;
            // Соединение держим открытым: закрытое дало бы обрыв, а мы
            // проверяем именно ответ прикрытия.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cover = cover();
        let desync = Desync::disabled();
        let answer = connect(
            &mut client_io,
            &ClientParams {
                server_public: [9u8; PUBLIC_LEN],
                password: b"secret",
                cover: &cover,
                fingerprint: Fingerprint::Chrome,
                algorithm: Algorithm::Aes256Gcm,
                desync: &desync,
                early: &[],
            },
        )
        .await;

        assert!(
            matches!(answer.as_ref().err(), Some(PingwinError::Rejected)),
            "ожидали отказ, получили {:?}",
            answer.err().map(|err| err.to_string())
        );
    }

    #[tokio::test]
    async fn something_that_is_not_tls_at_all_also_goes_to_the_cover() {
        // Проба браузером — самый частый способ посмотреть, что на порту.
        // Она не разбирается как запись TLS, и закрыть на ней соединение
        // значило бы ответить не так, как ответил бы обычный сайт.
        let server_keys = StaticKeyPair::generate();
        let policy = Policy::new("secret", &server_keys.public);

        let (mut client_io, mut server_io) = duplex(64 * 1024);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client_io.write_all(request).await.expect("записалось");

        let outcome = accept(&mut server_io, &server_keys, &policy, TEST_LIMIT)
            .await
            .expect("чтение");
        let Outcome::Foreign(seen) = outcome else {
            panic!("запрос HTTP принят за своё приветствие");
        };
        assert!(
            request.starts_with(&seen[..]),
            "прикрытию достались не те байты: {seen:?}"
        );
        assert!(!seen.is_empty(), "начало запроса потеряно");
    }

    #[tokio::test]
    async fn a_decoy_hello_does_not_stop_the_real_one() {
        // Ложная посылка обхода DPI доходит до сервера тогда, когда TTL не
        // сработал. Сервер обязан пропустить её и принять следующую.
        let desync = DesyncConfig {
            strategy: "fake".to_owned(),
            ..DesyncConfig::default()
        }
        .compile()
        .expect("настройки верны");

        let (client, server) = shake("secret", &[], desync, "secret").await;
        client.expect("клиент поздоровался");
        assert!(matches!(server, Ok(Outcome::Ours(_))));
    }

    #[tokio::test]
    async fn a_replayed_hello_is_refused_the_second_time() {
        // Повтор ранних данных — единственная настоящая цена 0-RTT, и она
        // закрыта окном, а не оставлена приложению.
        let server_keys = StaticKeyPair::generate();
        let server_public = server_keys.public;
        let policy = Policy::new("secret", &server_public);

        // Первую посылку записываем, вторым разом проигрываем её же. Клиент
        // при этом ответа не дождётся — он нам и не нужен, нужна посылка.
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut client_io = Fake(client_io);
        let client = tokio::spawn(async move {
            let cover = Address::domain("www.microsoft.com");
            let desync = Desync::disabled();
            let params = ClientParams {
                server_public,
                password: b"secret",
                cover: &cover,
                fingerprint: Fingerprint::Chrome,
                algorithm: Algorithm::Aes256Gcm,
                desync: &desync,
                early: &[],
            };
            let _ = connect(&mut client_io, &params).await;
        });

        let mut flight = Vec::new();
        // Приветствие и `ChangeCipherSpec` — вся первая посылка без 0-RTT.
        for _ in 0..2 {
            read_any_record(&mut server_io, &mut flight)
                .await
                .expect("посылка пришла");
        }
        client.abort();

        for expected_ours in [true, false] {
            // Собеседник остаётся живым на всё время разбора: закрытый
            // duplex не дал бы серверу ответить, и проверялось бы не то.
            let (mut client_io, mut server_io) = duplex(64 * 1024);
            client_io.write_all(&flight).await.expect("посылка ушла");

            let outcome = accept(&mut server_io, &server_keys, &policy, TEST_LIMIT)
                .await
                .expect("чтение");
            assert_eq!(
                matches!(outcome, Outcome::Ours(_)),
                expected_ours,
                "повтор прошёл"
            );
            drop(client_io);
        }
    }
}

//! Фоновая задача соединения: входящие однонаправленные потоки и датаграммы.
//!
//! Сервер открывает поток управления и, возможно, потоки QPACK; их надо
//! читать всё время жизни соединения, иначе не узнать ни настроек, ни
//! `GOAWAY`. Здесь же разбираются датаграммы, если их просили.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;
use tokio::task::JoinSet;

use super::code::{
    H3_CLOSED_CRITICAL_STREAM, H3_FRAME_UNEXPECTED, H3_ID_ERROR, H3_MISSING_SETTINGS,
    H3_STREAM_CREATION_ERROR, stream_type,
};
use super::connection::{close_with, var_int};
use super::datagram;
use super::dispatch::Router;
use super::error::{H3Error, H3Result};
use super::frame;
use super::reader::{FrameReader, read_error};
use super::settings::{self, Settings};

/// Предел кадров потока управления: `SETTINGS` и `GOAWAY` крошечные.
const CONTROL_FRAME_LIMIT: usize = 16 * 1024;

/// Какие потоки собеседник уже открыл: каждый — не больше одного раза.
#[derive(Default)]
struct Seen {
    control: AtomicBool,
    encoder: AtomicBool,
    decoder: AtomicBool,
}

/// Крутит соединение, пока оно живо.
///
/// `control` — свой поток управления. Он держится здесь, а не отпускается:
/// закрыть его — ошибка соединения (RFC 9114, §6.2.1).
pub(super) async fn drive(
    quic: quinn::Connection,
    control: quinn::SendStream,
    settings: watch::Sender<Option<Settings>>,
    router: Option<Arc<Router>>,
) {
    let _control = control;
    let settings = Arc::new(settings);
    let seen = Arc::new(Seen::default());
    let mut streams = JoinSet::new();

    let err = loop {
        tokio::select! {
            accepted = quic.accept_uni() => match accepted {
                Ok(recv) => {
                    streams.spawn(handle_uni(recv, Arc::clone(&seen), Arc::clone(&settings)));
                }
                Err(err) => break H3Error::closed(err),
            },
            datagram = read_datagram(&quic, router.as_deref()) => {
                if let Err(err) = datagram {
                    break err;
                }
            }
            Some(joined) = streams.join_next() => {
                if let Ok(Err(err)) = joined {
                    break err;
                }
            }
        }
    };

    if let H3Error::Protocol { code, reason } = &err {
        close_with(&quic, *code, reason);
    }
    tracing::debug!(%err, "соединение HTTP/3 завершено");
}

/// Читает одну датаграмму и отдаёт её потоку. Без маршрутизатора не
/// читает вовсе: датаграммы соединения тогда принадлежат не HTTP/3.
async fn read_datagram(quic: &quinn::Connection, router: Option<&Router>) -> H3Result<()> {
    let Some(router) = router else {
        return std::future::pending().await;
    };
    let raw = quic.read_datagram().await.map_err(H3Error::closed)?;
    let (stream_id, payload) = datagram::decode(raw)?;
    router.route(stream_id, payload);
    Ok(())
}

/// Разбирает один входящий однонаправленный поток.
async fn handle_uni(
    mut recv: quinn::RecvStream,
    seen: Arc<Seen>,
    settings: Arc<watch::Sender<Option<Settings>>>,
) -> H3Result<()> {
    // Поток вправе закрыться и до типа (§6.2) — это не ошибка.
    let Some(kind) = read_stream_type(&mut recv).await else {
        return Ok(());
    };
    match kind {
        stream_type::CONTROL => {
            once(&seen.control, "второй поток управления")?;
            read_control(FrameReader::new(recv), &settings).await
        }
        stream_type::QPACK_ENCODER => {
            once(&seen.encoder, "второй поток кодировщика QPACK")?;
            drain_critical(recv).await
        }
        stream_type::QPACK_DECODER => {
            once(&seen.decoder, "второй поток декодировщика QPACK")?;
            drain_critical(recv).await
        }
        // `MAX_PUSH_ID` клиент не слал (§6.2.2).
        stream_type::PUSH => Err(H3Error::protocol(
            H3_ID_ERROR,
            "проталкивание без MAX_PUSH_ID",
        )),
        _ => {
            // Незнакомый тип не ошибка соединения (§6.2); поток мог
            // закрыться сам — тогда и останавливать нечего.
            let _ = recv.stop(var_int(H3_STREAM_CREATION_ERROR));
            Ok(())
        }
    }
}

/// Тип потока — варинт в начале. `None` — поток кончился или сброшен раньше.
async fn read_stream_type(recv: &mut quinn::RecvStream) -> Option<u64> {
    let mut buf = [0u8; 8];
    recv.read_exact(&mut buf[..1]).await.ok()?;
    let len = 1usize << (buf[0] >> 6);
    recv.read_exact(&mut buf[1..len]).await.ok()?;
    crate::varint::try_decode(&buf[..len]).map(|(kind, _)| kind)
}

fn once(flag: &AtomicBool, reason: &str) -> H3Result<()> {
    if flag.swap(true, Ordering::Relaxed) {
        return Err(H3Error::protocol(H3_STREAM_CREATION_ERROR, reason));
    }
    Ok(())
}

/// Поток управления сервера (§6.2.1, §7.2).
async fn read_control(
    mut reader: FrameReader,
    settings: &watch::Sender<Option<Settings>>,
) -> H3Result<()> {
    let first = critical(reader.header().await)?;
    if first.kind != frame::SETTINGS {
        return Err(H3Error::protocol(
            H3_MISSING_SETTINGS,
            "первый кадр потока управления — не SETTINGS",
        ));
    }
    let payload = critical(reader.payload(CONTROL_FRAME_LIMIT).await.map(Some))?;
    settings.send_replace(Some(settings::decode(&payload)?));

    loop {
        let header = critical(reader.header().await)?;
        match header.kind {
            frame::GOAWAY => {
                let payload = critical(reader.payload(CONTROL_FRAME_LIMIT).await.map(Some))?;
                // Новые запросы сервер отклонит сам; уже идущие доживут.
                tracing::debug!(id = ?crate::varint::try_decode(&payload), "сервер прислал GOAWAY");
            }
            kind if is_unexpected_on_control(kind) => {
                return Err(H3Error::protocol(
                    H3_FRAME_UNEXPECTED,
                    format!("кадр {kind:#x} на потоке управления"),
                ));
            }
            // `CANCEL_PUSH` и незнакомые типы пропускаются (§7.2.8, §9).
            _ => critical(reader.skip().await.map(Some))?,
        }
    }
}

/// Кадры, которым не место на потоке управления сервера.
fn is_unexpected_on_control(kind: u64) -> bool {
    matches!(
        kind,
        frame::DATA | frame::HEADERS | frame::SETTINGS | frame::PUSH_PROMISE | frame::MAX_PUSH_ID
    ) || frame::is_reserved_http2(kind)
}

/// Поток QPACK. При нулевой ёмкости таблицы в нём нечего применять; он
/// читается, чтобы не стоять на окне потока, и не должен закрываться.
async fn drain_critical(mut recv: quinn::RecvStream) -> H3Result<()> {
    loop {
        match recv.read_chunk(usize::MAX, true).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(closed_critical()),
            Err(err) => return Err(critical_error(read_error(err))),
        }
    }
}

/// Конец критичного потока — ошибка соединения, обрыв соединения — нет.
fn critical<T>(result: H3Result<Option<T>>) -> H3Result<T> {
    match result {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(closed_critical()),
        Err(err) => Err(critical_error(err)),
    }
}

/// Сброс критичного потока — то же, что его закрытие.
fn critical_error(err: H3Error) -> H3Error {
    match err {
        H3Error::Reset(_) => closed_critical(),
        err => err,
    }
}

fn closed_critical() -> H3Error {
    H3Error::protocol(H3_CLOSED_CRITICAL_STREAM, "критичный поток закрыт")
}

//! Соединение HTTP/3 поверх готового соединения QUIC.
//!
//! QUIC приходит снаружи; здесь поток управления с `SETTINGS`, фоновая задача и запросы.

use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use penguin_proto::random;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::code::{H3_NO_ERROR, stream_type};
use super::control;
use super::datagram;
use super::dispatch::{DatagramReceiver, Router};
use super::error::{H3Error, H3Result};
use super::frame;
use super::message::Request;
use super::settings::{self, Settings};
use super::stream::{RequestStream, write_error};

/// Свой предел блока полей ответа; объявляется серверу в `SETTINGS`.
const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// Как поднять HTTP/3.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Объявить и принимать датаграммы HTTP/3 (RFC 9297).
    ///
    /// Выключено — датаграммы QUIC не трогаются (они нужны протоколу, как Hysteria 2).
    pub datagrams: bool,
}

/// Соединение HTTP/3. Клонируется: все клоны — одно соединение.
#[derive(Debug, Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    quic: quinn::Connection,
    settings: watch::Receiver<Option<Settings>>,
    router: Option<Arc<Router>>,
    driver: JoinHandle<()>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Задача держит клон соединения и сама не кончится.
        self.driver.abort();
    }
}

impl Connection {
    /// Поднимает HTTP/3: открывает поток управления и шлёт `SETTINGS`.
    ///
    /// Настроек сервера не ждёт (RFC 9114, §7.2.4.2), кроме расширенного `CONNECT`.
    pub async fn new(quic: quinn::Connection, options: Options) -> H3Result<Self> {
        let mut control = quic.open_uni().await.map_err(H3Error::closed)?;
        control
            .write_all(&control_preface(options.datagrams))
            .await
            .map_err(write_error)?;

        let (settings_tx, settings) = watch::channel(None);
        let router = options.datagrams.then(Arc::default);
        let driver = tokio::spawn(control::drive(
            quic.clone(),
            control,
            settings_tx,
            router.clone(),
        ));

        Ok(Self {
            inner: Arc::new(Inner {
                quic,
                settings,
                router,
                driver,
            }),
        })
    }

    /// Соединение QUIC под HTTP/3.
    pub fn quic(&self) -> &quinn::Connection {
        &self.inner.quic
    }

    /// Ждёт настройки сервера. Срок ставит вызывающий.
    pub async fn peer_settings(&self) -> H3Result<Settings> {
        let mut settings = self.inner.settings.clone();
        let result = settings.wait_for(Option::is_some).await;
        match result {
            Ok(settings) => Ok(settings.clone().unwrap_or_default()),
            Err(_) => Err(self.lost()),
        }
    }

    /// Отправляет запрос и возвращает его поток. Тело и ответ — через него.
    pub async fn send_request(&self, request: &Request) -> H3Result<RequestStream> {
        if request.is_extended_connect() && !self.peer_settings().await?.enable_connect_protocol {
            // RFC 9220, §3: без согласия сервера `:protocol` слать нельзя.
            return Err(H3Error::Unsupported("расширенный CONNECT (RFC 9220)"));
        }
        let block = request.encode();
        if let Some(limit) = self.current_settings().max_field_section_size
            && request.field_section_size() as u64 > limit
        {
            return Err(H3Error::Message(format!(
                "запрос больше предела сервера в {limit} байт"
            )));
        }

        let quic = &self.inner.quic;
        let (mut send, recv) = quic.open_bi().await.map_err(|_| self.lost())?;
        send.write_all(&frame::encode(frame::HEADERS, &block))
            .await
            .map_err(write_error)?;
        Ok(RequestStream::new(
            send,
            recv,
            quic.clone(),
            MAX_FIELD_SECTION_SIZE as usize,
        ))
    }

    /// Можно ли сейчас слать датаграммы HTTP/3: свои включены, сервер их
    /// объявил, QUIC их пропускает.
    pub fn datagrams_available(&self) -> bool {
        self.inner.router.is_some()
            && self.current_settings().h3_datagram
            && self.inner.quic.max_datagram_size().is_some()
    }

    /// Самое длинное содержимое датаграммы для потока `stream_id`.
    pub fn max_datagram_payload(&self, stream_id: u64) -> Option<usize> {
        let overhead = crate::varint::encoded_len(stream_id / 4);
        self.inner
            .quic
            .max_datagram_size()
            .map(|size| size.saturating_sub(overhead))
    }

    /// Отправляет датаграмму запроса `stream_id`.
    pub fn send_datagram(&self, stream_id: u64, payload: &[u8]) -> H3Result<()> {
        if !self.datagrams_available() {
            return Err(H3Error::Unsupported("датаграммы HTTP/3 (RFC 9297)"));
        }
        self.inner
            .quic
            .send_datagram(datagram::encode(stream_id, payload))
            .map_err(datagram_error)
    }

    /// Заводит очередь входящих датаграмм запроса `stream_id`.
    pub fn register_datagrams(&self, stream_id: u64) -> H3Result<DatagramReceiver> {
        let router = self
            .inner
            .router
            .as_ref()
            .ok_or(H3Error::Unsupported("датаграммы HTTP/3 не включены"))?;
        Ok(router.register(stream_id))
    }

    /// Закрывает соединение штатно.
    pub fn close(&self) {
        close_with(&self.inner.quic, H3_NO_ERROR, "");
    }

    fn current_settings(&self) -> Settings {
        self.inner.settings.borrow().clone().unwrap_or_default()
    }

    /// Почему соединение мертво — со слов QUIC, если он знает.
    fn lost(&self) -> H3Error {
        match self.inner.quic.close_reason() {
            Some(reason) => H3Error::closed(reason),
            None => H3Error::Closed("фоновая задача HTTP/3 остановилась".to_owned()),
        }
    }
}

/// Начало своего потока управления: тип и `SETTINGS`.
fn control_preface(datagrams: bool) -> BytesMut {
    let grease = (
        settings::grease_id(random::range(0..1 << 16)),
        random::range(0..1 << 8),
    );
    let payload = settings::encode(MAX_FIELD_SECTION_SIZE, datagrams, grease);
    let mut out = BytesMut::new();
    crate::varint::encode(stream_type::CONTROL, &mut out);
    out.put_slice(&frame::encode(frame::SETTINGS, &payload));
    out
}

fn datagram_error(err: quinn::SendDatagramError) -> H3Error {
    match err {
        quinn::SendDatagramError::TooLarge => H3Error::DatagramTooLarge,
        quinn::SendDatagramError::ConnectionLost(err) => H3Error::closed(err),
        _ => H3Error::Unsupported("датаграммы QUIC"),
    }
}

/// Код ошибки как `VarInt` QUIC. Все коды HTTP/3 далеко внутри предела.
pub(super) fn var_int(code: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX)
}

/// Закрывает соединение с кодом HTTP/3.
pub(super) fn close_with(quic: &quinn::Connection, code: u64, reason: &str) {
    quic.close(var_int(code), reason.as_bytes());
}

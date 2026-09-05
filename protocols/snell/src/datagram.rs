//! Канал датаграмм: один поток на всех адресатов.
//!
//! ```text
//!  туда    [0x01][адрес][данные]   — по одной посылке на кусок
//!  обратно      [адрес][данные]
//! ```
//!
//! # Почему здесь задача, а не два замка
//!
//! Граница датаграммы у Snell — это граница **куска** общего кадра: длины
//! внутри посылки нет вовсе, и всё, что осталось после адреса, и есть данные.
//! Значит читать канал можно только кусками, а кусок читает и пишет один и
//! тот же объект — расшифровка и зашифровка идут по своим счётчикам, но
//! состояние у них общее.
//!
//! Делить его замком нельзя: чтение датаграммы ждёт сети, и держать под
//! замком отправку означало бы канал, который молчит, пока молчит собеседник.
//! Поэтому объектом владеет отдельная задача, а наружу торчат две очереди.
//!
//! # Первый кусок особенный
//!
//! Он начинается с ответа сервера — того же байта, что и у соединения. За
//! ответом в том же куске может идти первая датаграмма, а может и не идти.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_transport::aead::MAX_CHUNK;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::chunks::Chunks;
use crate::error::{SnellError, SnellResult};
use crate::frame::{reply, udp};

/// Сколько датаграмм держать в очереди в каждую сторону.
const QUEUE: usize = 512;

/// Канал датаграмм через сервер Snell.
pub struct SnellDatagram {
    /// Что отправить.
    outgoing: mpsc::Sender<(Bytes, SocketAddress)>,
    /// Что пришло.
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    /// Задача, владеющая потоком.
    task: JoinHandle<()>,
    /// Почему канал умер. Пусто — жив.
    death: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for SnellDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellDatagram").finish()
    }
}

impl SnellDatagram {
    /// Заводит канал вокруг уже открытого потока.
    pub fn new(io: Box<dyn Chunks>) -> Self {
        let (outgoing, to_send) = mpsc::channel(QUEUE);
        let (arrived, incoming) = mpsc::channel(QUEUE);
        let death = Arc::new(Mutex::new(None));

        let task = tokio::spawn(run(io, to_send, arrived, Arc::clone(&death)));
        Self {
            outgoing,
            incoming: Mutex::new(incoming),
            task,
            death,
        }
    }

    /// Почему канал умер.
    async fn why(&self) -> String {
        self.death
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| "канал датаграмм закрылся".to_owned())
    }
}

impl Drop for SnellDatagram {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[async_trait]
impl ProxyDatagram for SnellDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        // Проверка до очереди: посылка, которая не поместится в кусок, не
        // поместится в него и через секунду.
        if 1 + udp::address_len(target) + payload.len() > MAX_CHUNK {
            return Err(SnellError::Oversized(payload.len()).into());
        }

        if self.outgoing.send((payload, target.clone())).await.is_err() {
            return Err(SnellError::disconnected(self.why().await).into());
        }
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        match incoming.recv().await {
            Some(packet) => Ok(packet),
            None => Err(SnellError::disconnected(self.why().await).into()),
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.task.abort();
        Ok(())
    }
}

/// Владеет потоком: шлёт то, что дали, и раздаёт то, что пришло.
async fn run(
    mut io: Box<dyn Chunks>,
    mut to_send: mpsc::Receiver<(Bytes, SocketAddress)>,
    arrived: mpsc::Sender<(Bytes, SocketAddress)>,
    death: Arc<Mutex<Option<String>>>,
) {
    let reason = pump(&mut io, &mut to_send, &arrived).await;
    tracing::debug!(%reason, "канал датаграмм Snell закрылся");
    *death.lock().await = Some(reason);
}

/// Возит датаграммы, пока получается. Возвращает причину конца.
async fn pump(
    io: &mut Box<dyn Chunks>,
    to_send: &mut mpsc::Receiver<(Bytes, SocketAddress)>,
    arrived: &mpsc::Sender<(Bytes, SocketAddress)>,
) -> String {
    // Ответ сервера впереди первой датаграммы: посылать в неоткрытый канал
    // незачем, и отказ здесь виден сразу, а не через таймаут.
    let mut answered = false;

    loop {
        enum Step {
            Came(std::io::Result<Option<bytes::BytesMut>>),
            Leaves(Option<(Bytes, SocketAddress)>),
        }

        // Чтение куска отменяемо: разобранное лежит в самом потоке, а не в
        // задаче, которую бросили.
        let step = tokio::select! {
            chunk = io.read_chunk() => Step::Came(chunk),
            packet = to_send.recv() => Step::Leaves(packet),
        };

        match step {
            Step::Came(Err(err)) => return err.to_string(),
            Step::Came(Ok(None)) => return "сервер закрыл канал".to_owned(),
            Step::Came(Ok(Some(mut chunk))) => {
                if !answered {
                    match reply::decode(&chunk) {
                        Ok(Some((reply, used))) => {
                            if let Err(err) = reply.into_result() {
                                return err.to_string();
                            }
                            answered = true;
                            let _ = chunk.split_to(used);
                        }
                        Ok(None) => continue,
                        Err(err) => return err.to_string(),
                    }
                    // Ответ мог приехать один, без датаграммы за ним.
                    if chunk.is_empty() {
                        continue;
                    }
                }

                match udp::open(&chunk) {
                    Ok((from, payload)) => {
                        if arrived
                            .send((Bytes::copy_from_slice(payload), from))
                            .await
                            .is_err()
                        {
                            return "канал датаграмм больше никому не нужен".to_owned();
                        }
                    }
                    // Одна кривая посылка не повод рвать канал: следующая
                    // может быть в порядке, а вот потерянный канал означает
                    // потерянные запросы DNS.
                    Err(err) => tracing::debug!(%err, "посылка не по протоколу"),
                }
            }
            Step::Leaves(None) => return "канал датаграмм закрыт".to_owned(),
            Step::Leaves(Some((payload, target))) => {
                let sealed = match udp::seal(&target, &payload) {
                    Ok(sealed) => sealed,
                    Err(err) => {
                        tracing::debug!(%err, "адресат не помещается в посылку");
                        continue;
                    }
                };
                if let Err(err) = io.write_chunk(&sealed).await {
                    return err.to_string();
                }
            }
        }
    }
}

/// Проверяет, что версия умеет датаграммы.
pub fn check(udp_works: bool, version: crate::version::Version) -> SnellResult<()> {
    if udp_works {
        return Ok(());
    }
    Err(SnellError::UdpUnsupported(if version.udp() {
        "проксирование UDP выключено в настройках профиля".to_owned()
    } else {
        format!("Snell {version} не умеет UDP: он появился с третьей версии")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::Version;

    #[test]
    fn the_reason_names_the_version_when_the_version_is_the_reason() {
        // «Выключено в настройках» и «эта версия так не умеет» — разные беды,
        // и человек по сообщению должен понять, что чинить.
        let err = check(false, Version::V1).expect_err("не умеет");
        assert!(err.to_string().contains("с третьей версии"), "{err}");

        let err = check(false, Version::V4).expect_err("выключено");
        assert!(err.to_string().contains("выключено в настройках"), "{err}");

        check(true, Version::V4).expect("умеет и включено");
    }
}

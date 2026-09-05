//! Один канал `CONNECT-UDP`: поток HTTP/3 до одного адреса назначения.
//!
//! # Почему только капсулы, а не кадры `HTTP/3 DATAGRAM`
//!
//! RFC 9298 предлагает два способа переносить UDP-нагрузку по одному и тому
//! же потоку `CONNECT-UDP` (RFC 9297, §3.5 объявляет их семантически
//! одинаковыми):
//!
//! - **капсулой `DATAGRAM`** прямо в теле потока — надёжно, по порядку,
//!   с задержкой на потерю пакета (`HTTP/3` поверх `QUIC` тормозит поток
//!   целиком, пока не пришёл потерянный кусок, — то самое, ради чего вообще
//!   существует второй способ);
//! - **кадром `HTTP/3 DATAGRAM`** поверх QUIC напрямую — без гарантий
//!   доставки и порядка, зато без этой задержки; ровно то, что и нужно UDP.
//!
//! Второй способ требует, чтобы кадр называл поток, к которому относится, —
//! номером потока, делённым на четыре (RFC 9297, §2.1: «Quarter Stream
//! ID»). Взять этот номер можно только у объекта, которым `h3` открыл поток,
//! а версия `0.0.8`, которой пользуется этот крейт, наружу его не отдаёт:
//! ни `RequestStream`, ни `SendRequest::send_request` не возвращают ничего
//! похожего на `StreamId` (проверено по исходникам крейта — не по памяти).
//! Подделать номер, считая свои же открытые потоки по порядку, значило бы
//! положиться на порядок выдачи ID в `quinn`, который нигде не
//! документирован как часть публичного контракта, — и один параллельный
//! вызов [`crate::session::Session::open_flow`] эту догадку уже ломает.
//!
//! Поэтому этот крейт — сознательно — говорит только первым способом.
//! Рабочий CONNECT-UDP, интероперабельный с любым сервером по RFC 9298 (он
//! обязан принимать капсулы — это базовый уровень, а не расширение), но без
//! ускорения, ради которого RFC 9297 вообще заводит датаграммы HTTP.
//! [`crate::transport`] по той же причине не объявляет
//! `SETTINGS_H3_DATAGRAM` — своя нечестность была бы хуже, чем прямо не
//! уметь.

use std::future::poll_fn;

use bytes::Bytes;
use penguin_core::address::SocketAddress;
use tokio::sync::{Mutex, mpsc};

use crate::capsule::{self, CapsuleReader};
use crate::error::{MasqueError, MasqueResult};
use crate::transport::{H3RecvHalf, H3SendHalf};

/// Один канал `CONNECT-UDP` до одного адреса назначения.
pub struct Flow {
    target: SocketAddress,
    send: Mutex<H3SendHalf>,
    reader: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flow")
            .field("target", &self.target)
            .finish()
    }
}

impl Flow {
    /// Заводит канал вокруг уже открытого и подтверждённого потока
    /// `CONNECT-UDP`: делит его на половины и запускает чтение капсул.
    ///
    /// `incoming` — общая очередь той [`crate::datagram::MasqueDatagram`],
    /// что открыла этот канал: датаграммы от разных целей одного и того же
    /// направления `bind_udp` сходятся в одну очередь, как и у остальных
    /// протоколов с [`penguin_proto::datagram::ProxyDatagram`].
    pub fn new(
        target: SocketAddress,
        send: H3SendHalf,
        recv: H3RecvHalf,
        incoming: mpsc::Sender<(Bytes, SocketAddress)>,
    ) -> Self {
        let reader_target = target.clone();
        let reader = tokio::spawn(read_capsules(recv, reader_target, incoming));

        Self {
            target,
            send: Mutex::new(send),
            reader,
        }
    }

    /// Отправляет UDP-нагрузку в туннель капсулой `DATAGRAM` (RFC 9297, §3.5).
    pub async fn send(&self, payload: &[u8]) -> MasqueResult<()> {
        let capsule = capsule::encode_udp_datagram(payload)?;
        let mut send = self.send.lock().await;
        send.send_data(capsule)
            .await
            .map_err(|e| MasqueError::Disconnected(e.to_string()))
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        // Без этого задача чтения переживает канал и держит его половину
        // потока открытой — тот самый «после отключения не остаётся живой
        // задачи» из общего чек-листа приёмки протокола.
        self.reader.abort();
    }
}

/// Читает капсулы `DATAGRAM` из потока и раскладывает их в общую очередь.
///
/// Останавливается сама, когда поток заканчивается или рвётся, — сервер
/// закрыл канал, и открывать его снова придётся заново через
/// [`crate::session::Session::open_flow`], а не чинить эту задачу.
async fn read_capsules(
    mut recv: H3RecvHalf,
    target: SocketAddress,
    incoming: mpsc::Sender<(Bytes, SocketAddress)>,
) {
    let mut reader = CapsuleReader::new();

    loop {
        let chunk = match poll_fn(|cx| recv.poll_recv_data(cx)).await {
            Ok(Some(chunk)) => chunk,
            // Поток закрылся штатно — прокси завершил канал.
            Ok(None) => return,
            Err(err) => {
                tracing::debug!(%target, %err, "канал CONNECT-UDP оборвался при чтении");
                return;
            }
        };
        reader.push(chunk);

        loop {
            match reader.next_datagram() {
                Ok(Some(payload)) => {
                    if incoming.send((payload, target.clone())).await.is_err() {
                        // Получатель канала (MasqueDatagram) уже уронен —
                        // читать больше некому.
                        return;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!(%target, %err, "капсула CONNECT-UDP не разобралась");
                    return;
                }
            }
        }
    }
}

//! Стек в обратную сторону: из адреса назначения получается соединение.
//!
//! Второй вид стека, а не настройка первого. Тот, что в [`crate::stack`],
//! умеет одну сторону: пакеты из TUN превращаются в **принятые** соединения.
//! Здесь нужна обратная — у нас есть адрес назначения, и соединение надо
//! **открыть** через виртуальный интерфейс, который дало направление.
//!
//! ```text
//!   приложение ──► TUN ──► stack ──► движок ──► outgoing ──► WireGuard ──► сеть
//!                          принимает            открывает
//! ```
//!
//! # Кому это нужно
//!
//! Протоколам уровня пакетов: WireGuard, OpenConnect, `CONNECT-IP` из MASQUE.
//! Они не открывают потоков и не знают слова «соединение» — они дают трубу
//! для пакетов. Превращать пакеты в соединения обязан кто-то другой, и это
//! ровно та работа, которую стек уже умеет делать в другую сторону.
//!
//! # Почему стрелка зависимостей не ломается
//!
//! `PacketOutbound` из `penguin-proto` — это `mtu`, `send`, `recv`, то есть
//! ровно то же, что `penguin_tun::TunDevice`. Поэтому направление
//! подставляется сюда **как устройство**, и `netstack` про протоколы уровня
//! пакетов по-прежнему не знает ничего. Переходник живёт в движке: там уже
//! есть и то и другое.
//!
//! # Что переиспользуется
//!
//! Устройство ([`crate::device`]), разбор и сборка заголовков IP
//! ([`crate::ip`], [`crate::udp::session`]), таблица соединений и перекачка
//! данных ([`crate::tcp`]). Своё здесь только два: сокет, открываемый по
//! требованию, и свои порты — внутри тоннеля адрес один на всё, и отличать
//! потоки друг от друга приходится портом ([`nat`]).

pub mod connect;
pub mod nat;
pub mod run;

use penguin_tun::TunDevice;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::StackConfig;
use crate::stack::Datagram;

pub use connect::{ConnectError, Connector};

/// Сколько запросов на соединение держать в очереди.
///
/// Переполнение означает, что цикл не успевает открывать сокеты; ждать в
/// очереди при этом честнее, чем отказывать, — открытие идёт быстро.
pub const REQUEST_QUEUE: usize = 128;

/// Сколько датаграмм держать в очереди в каждую сторону.
pub const UDP_QUEUE: usize = 512;

/// Каналы, через которые движок говорит с исходящим стеком.
pub struct OutgoingHandles {
    /// Чем открывать соединения.
    pub connector: Connector,
    /// Датаграммы наружу.
    ///
    /// `source` — адрес приложения: на провод он не попадает, он нужен, чтобы
    /// движок узнал свою сессию в ответе. `destination` — куда идти.
    pub udp_send: mpsc::Sender<Datagram>,
    /// Датаграммы обратно. Поля значат то же, что и в запросе, — переставлять
    /// их местами не нужно.
    pub udp_recv: mpsc::Receiver<Datagram>,
}

impl std::fmt::Debug for OutgoingHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingHandles").finish()
    }
}

/// Запускает исходящий стек поверх интерфейса.
///
/// `device` здесь — не адаптер системы, а виртуальный интерфейс внутри
/// тоннеля: тот, который дало направление уровня пакетов. Адреса и MTU в
/// `config` тоже его, а не адаптера, и приходят они **от сервера**.
pub fn spawn(
    device: Box<dyn TunDevice>,
    config: StackConfig,
    cancel: CancellationToken,
) -> OutgoingHandles {
    let (connector, requests) = Connector::new(REQUEST_QUEUE);
    let (udp_send, udp_from_engine) = mpsc::channel(UDP_QUEUE);
    let (udp_to_engine, udp_recv) = mpsc::channel(UDP_QUEUE);

    tokio::spawn(run::run(
        device,
        config,
        cancel,
        requests,
        udp_from_engine,
        udp_to_engine,
    ));

    OutgoingHandles {
        connector,
        udp_send,
        udp_recv,
    }
}

//! Стек в обратную сторону: из адреса назначения получается открытое соединение.
//!
//! Нужен протоколам уровня пакетов (WireGuard, `CONNECT-IP`): направление подставляется как
//! устройство ([`penguin_tun::TunDevice`]), переходник живёт в движке. Устройство, разбор
//! заголовков и перекачка данных общие со входящим стеком; своё здесь — сокет по требованию
//! и свои порты ([`nat`]).
//!
//! ```text
//!   приложение ──► TUN ──► stack ──► движок ──► outgoing ──► WireGuard ──► сеть
//!                          принимает            открывает
//! ```

pub mod connect;
pub mod nat;
pub mod run;

use penguin_tun::TunDevice;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::StackConfig;
use crate::stack::Datagram;

pub use connect::{ConnectError, Connector};

/// Глубина очереди запросов на соединение.
pub const REQUEST_QUEUE: usize = 128;

/// Глубина очереди датаграмм в каждую сторону.
pub const UDP_QUEUE: usize = 512;

/// Каналы, через которые движок говорит с исходящим стеком.
pub struct OutgoingHandles {
    /// Чем открывать соединения.
    pub connector: Connector,
    /// Датаграммы наружу: `source` — адрес приложения (на провод не попадает), `destination` — куда идти.
    pub udp_send: mpsc::Sender<Datagram>,
    /// Датаграммы обратно; поля значат то же, что в запросе.
    pub udp_recv: mpsc::Receiver<Datagram>,
}

impl std::fmt::Debug for OutgoingHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingHandles").finish()
    }
}

/// Запускает исходящий стек; `device` и адреса в `config` — интерфейс тоннеля, а не адаптер системы.
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

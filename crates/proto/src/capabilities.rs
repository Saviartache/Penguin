//! Что протокол умеет: UDP, мультиплексирование, смена порта, свои DNS.

/// Возможности исходящего направления; маршрутизатор спрашивает их до выдачи соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Умеет проксировать UDP.
    pub udp: bool,
    /// Несколько потоков в одном соединении.
    pub multiplex: bool,
    /// Умеет менять порт сервера на ходу.
    pub port_hopping: bool,
    /// Принимает доменное имя и разрешает его на своей стороне.
    pub remote_dns: bool,
}

impl Capabilities {
    /// Ничего сверх обычного TCP.
    pub const TCP_ONLY: Self = Self {
        udp: false,
        multiplex: false,
        port_hopping: false,
        remote_dns: false,
    };
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::TCP_ONLY
    }
}

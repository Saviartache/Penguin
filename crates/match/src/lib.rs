//! Чистые сопоставители. Ни сети, ни файлов, ни системных вызовов — только
//! «подходит / не подходит».
//!
//! Отсюда главное свойство крейта: **весь набор правил проверяется тестами без
//! сети, без прав и без ожидания**. Сопоставитель получает
//! [`target::MatchTarget`] — уже собранное описание соединения — и отвечает
//! `true` или `false`. Он не ходит в DNS, не читает таблицу процессов и не
//! смотрит на часы; всё это делают те, кто эту цель для него собирает.
//!
//! Второе свойство — дорогая работа делается один раз. Регулярные выражения
//! компилируются при сборке правил, подсети складываются в дерево, подстроки —
//! в автомат Ахо — Корасик. На горячем пути остаётся только поиск.
//!
//! ```text
//!  логика   ── all / any / not, любая глубина вложенности
//!  process  ── путь, имя, каталог, шаблон
//!  address  ── подсеть, домен, порт, страна
//!  network  ── tcp/udp, v4/v6
//! ```

pub mod address;
pub mod logic;
pub mod matcher;
pub mod network;
pub mod process;
pub mod target;

pub use address::{DomainSet, IpSet, PortSet};
pub use logic::{All, Always, Any, Not};
pub use matcher::Matcher;
pub use network::{IpFamilySet, NetworkSet};
pub use process::set::{ProcessSet, ProcessSetBuilder};
pub use target::MatchTarget;

#[cfg(test)]
pub(crate) mod test_support {
    use std::net::SocketAddr;

    use penguin_core::network::Network;

    use crate::target::MatchTarget;

    /// Цель по умолчанию: TCP на `1.2.3.4:443`, без имени и без владельца.
    pub(crate) fn target() -> MatchTarget<'static> {
        let destination: SocketAddr = "1.2.3.4:443".parse().expect("адрес");
        MatchTarget::to_address(Network::Tcp, destination)
    }
}

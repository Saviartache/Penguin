//! MASQUE: `CONNECT-UDP` поверх HTTP/3 (RFC 9298).
//!
//! ## Источники
//!
//! Прочитан текст самих RFC, а не пересказы:
//!
//! - **RFC 9298** — «Proxying UDP in HTTP» (`CONNECT-UDP`): §2 (шаблон URI),
//!   §3 (запрос и ответ), §5 (кадр датаграммы UDP-проксирования).
//! - **RFC 9297** — «HTTP Datagrams and the Capsule Protocol»: §2.1
//!   (кадр `HTTP/3 DATAGRAM` и настройка `SETTINGS_H3_DATAGRAM`), §3.2
//!   (протокол капсул), §3.5 (капсула `DATAGRAM` и её равнозначность кадру).
//! - **RFC 9220** — расширенный `CONNECT` в HTTP/3 и настройка
//!   `SETTINGS_ENABLE_CONNECT_PROTOCOL` (её проверяет
//!   [`penguin_transport::h3`]).
//! - **RFC 9484** — «Proxying IP in HTTP» (`CONNECT-IP`): §3 (шаблон URI по
//!   умолчанию), §4.2—4.5 (запрос и ответ через HTTP/1.1 `Upgrade` и через
//!   HTTP/3, см. [`ip`]), §4.7 (капсулы согласования адреса и маршрута),
//!   §5—6 (Context ID и формат датаграммы IP-проксирования).
//!
//! ## Два режима одного протокола — и почему это два разных модуля
//!
//! MASQUE — это семейство: RFC 9298 даёт `CONNECT-UDP` (труба для
//! датаграмм с адресом на каждой посылке — точно то, что описывает
//! [`penguin_proto::datagram::ProxyDatagram`], реализовано корнем этого
//! крейта), а RFC 9484 — `CONNECT-IP` (труба для целых IP-пакетов — то, что
//! описывает [`penguin_proto::packet::PacketOutbound`], реализовано в
//! [`ip`]). Оба режима есть, и оба — в этом крейте: имя протокола в
//! настройках у второго — `masque-ip`.
//!
//! Не расширение уже написанного `Session`, а отдельный модуль: `CONNECT-IP`
//! не открывает несколько каналов на разные цели, как `CONNECT-UDP` (одна
//! труба — весь трафик), и требует своего протокола согласования адреса —
//! капсул `ADDRESS_ASSIGN`/`ADDRESS_REQUEST`/`ROUTE_ADVERTISEMENT` (RFC 9484,
//! §4.7), которых `Session`/`Flow`/`MasqueDatagram` этого крейта не знают
//! вовсе. Общий фундамент — только [`capsule`] (разбор капсулы
//! `Type`/`Length`/`Value`); всё остальное у
//! [`ip`] своё, вплоть до другого транспорта — подробности там же.
//!
//! ## Датаграммы HTTP/3 и расширенный CONNECT
//!
//! HTTP/3 — свой, из [`penguin_transport::h3`]. Клиент объявляет
//! `SETTINGS_H3_DATAGRAM` (RFC 9297, §2.1.1), и если прокси ответил тем же,
//! UDP едет кадрами `HTTP/3 DATAGRAM`, помеченными номером потока своего
//! канала, — без задержки на потерянном пакете. Иначе — капсулами
//! `DATAGRAM` по потоку (RFC 9297, §3.5), семантически тем же самым.
//! Подробности — в [`flow`].
//!
//! Расширенный `CONNECT` (RFC 9220) прокси обязан объявить прежде, чем
//! клиент пошлёт `:protocol: connect-udp` (RFC 9298, §3.4). HTTP/3 ждёт его
//! `SETTINGS` и без этого запрос не шлёт: такой прокси — ошибка настроек,
//! а не обрыв, и повторять её незачем.
//!
//! ## Сверка
//!
//! - [`capsule`] и [`request`] сверены по формату из RFC 9297/9298 построчно
//!   (см. документацию каждого модуля); отдельных тестовых векторов для
//!   капсул и запроса `CONNECT-UDP` ни в одном из RFC нет — сверки по
//!   готовым байтам для них не существует, и это не скрывается.
//! - У [`ip`] капсулы согласования адреса (`ADDRESS_ASSIGN`/`ADDRESS_REQUEST`/
//!   `ROUTE_ADVERTISEMENT`) сверены так же — по формату из RFC 9484 §4.7, без
//!   опубликованных тестовых векторов, круговым проходом кодирование-разбор.
//! - Против живого сервера MASQUE (ни RFC 9298, ни RFC 9484) не
//!   проверялось — это работа `scripts/interop`, вне границы этой фазы.
//!
//! ## Устройство
//!
//! ```text
//!  CONNECT-UDP (корень крейта):
//!
//!  factory ──► outbound ──► session ──┬─► transport (QUIC + HTTP/3)
//!                             │        │
//!                             │        └─► request (запрос CONNECT-UDP, разбор ответа)
//!                             │
//!                             └─► datagram (кэш адрес → канал) ──► flow (датаграммы или капсулы)
//!                                                                       │
//!                                                                       └─► capsule
//!
//!  CONNECT-IP (модуль `ip`, свой транспорт — см. документ модуля):
//!
//!  ip::factory ──► ip::outbound ──┬─► ip::connect (TLS + апгрейд или HTTP/3, ip::request)
//!                                  │
//!                                  └─► ip::negotiate (ADDRESS_REQUEST/ASSIGN) ──► ip::capsule
//!                                                                                     │
//!                                                                                     └─► capsule
//! ```
//!
//! `capsule` не знает ни про HTTP/3, ни про `quinn`, ни про TLS — это
//! чистый разбор байтов, тестируемый без сети (`AGENTS.md`, правило 2.3); то
//! же верно для `ip::capsule`.
//!
//! ## Границы
//!
//! Крейт зависит только от [`penguin_core`], [`penguin_proto`] и
//! [`penguin_transport`]. Сокетов он не открывает — их выдаёт
//! [`penguin_proto::dialer::Dialer`], иначе рукопожатие ушло бы в
//! собственный, ещё не поднятый тоннель.

pub mod capsule;
pub mod config;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod flow;
pub mod ip;
pub mod outbound;
pub mod request;
pub mod session;
pub mod transport;

pub use config::MasqueConfig;
pub use error::{MasqueError, MasqueResult};
pub use factory::MasqueFactory;
pub use ip::{MasqueIpFactory, PROTOCOL_MASQUE_IP};
pub use outbound::MasqueOutbound;

/// Имя протокола в конфигурации.
///
/// Стоит в файлах настроек пользователей — менять нельзя.
pub const PROTOCOL_MASQUE: &str = "masque";

//! Приём TCP-соединений из тоннеля.
//!
//! Состояние TCP — то, ради чего в клиенте вообще есть стек: рукопожатие,
//! окна, перепосылка, порядок. Писать это самим незачем, есть smoltcp.
//!
//! Наружу сокеты стека не выдаются ([`conn`]): стек однопоточный, и трогать
//! его сокеты из чужой задачи нельзя. Вместо этого цикл перекладывает данные
//! между сокетом и парой очередей, а движок видит обычный поток.

pub mod conn;
pub mod listener;
pub mod table;

pub use conn::{ConnectionEnds, TcpConnection};
pub use listener::{Accepted, TcpListener};
pub use table::{ConnectionTable, FlowKey};

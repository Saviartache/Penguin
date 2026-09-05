//! Перекладывание данных между сокетом smoltcp и очередями движка.
//!
//! Одно на два стека, и это не экономия строк: тонкость здесь в двух
//! задержанных блоках, и написать её дважды значит однажды написать
//! по-разному.
//!
//! ```text
//!   сокет ──► [задержанный блок] ──► движок
//!   сокет ◄── [задержанный блок] ◄── движок
//! ```
//!
//! # Про стороны
//!
//! Со стороны TUN за сокетом стоит приложение, со стороны тоннеля — сервер.
//! Здесь это неразличимо и нарочно: сокет есть сокет, движок есть движок, а
//! кто на том конце — вопрос того, кто завёл стек.

use bytes::Bytes;
use smoltcp::socket::tcp;
use tokio::sync::mpsc;

use super::table::Entry;

/// Перекладывает данные в обе стороны за один оборот цикла.
pub fn pump_data(socket: &mut tcp::Socket<'_>, entry: &mut Entry) {
    from_socket(socket, entry);
    to_socket(socket, entry);
}

/// От сокета к движку.
///
/// Задержанный блок идёт первым, и пока он не ушёл, из сокета не берётся
/// ничего нового: вынутое из сокета для TCP уже отправлено и подтверждено, и
/// выбросить его значит проделать в потоке дыру.
fn from_socket(socket: &mut tcp::Socket<'_>, entry: &mut Entry) {
    loop {
        let chunk = match entry.to_engine.take() {
            Some(chunk) => chunk,
            None if socket.can_recv() => {
                let Ok(chunk) = socket.recv(|buffer| {
                    let taken = Bytes::copy_from_slice(buffer);
                    (buffer.len(), taken)
                }) else {
                    break;
                };
                if chunk.is_empty() {
                    break;
                }
                chunk
            }
            None => break,
        };

        match entry.ends.to_engine.try_send(chunk) {
            Ok(()) => {}
            // Движок не успевает. Держим блок у себя: сокет перестанет
            // читаться, окно TCP закроется, и другая сторона притормозит сама
            // — это и есть обратное давление.
            Err(mpsc::error::TrySendError::Full(chunk)) => {
                entry.to_engine = Some(chunk);
                break;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
}

/// От движка к сокету.
fn to_socket(socket: &mut tcp::Socket<'_>, entry: &mut Entry) {
    loop {
        let chunk = match entry.to_socket.take() {
            Some(chunk) => chunk,
            None => match entry.ends.from_engine.try_recv() {
                Ok(chunk) => chunk,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Движок закрыл свою сторону — закрываем сокет на запись.
                    entry.engine_closed = true;
                    socket.close();
                    break;
                }
            },
        };

        if !socket.can_send() {
            entry.to_socket = Some(chunk);
            break;
        }

        match socket.send_slice(&chunk) {
            // Записалось столько, сколько поместилось. Хвост остаётся до
            // следующего оборота: считать частичную запись полной значит
            // потерять середину потока.
            Ok(sent) if sent < chunk.len() => {
                entry.to_socket = Some(chunk.slice(sent..));
                break;
            }
            Ok(_) => {}
            Err(_) => {
                entry.to_socket = Some(chunk);
                break;
            }
        }
    }
}

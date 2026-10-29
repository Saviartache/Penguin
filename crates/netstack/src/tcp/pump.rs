//! Перекладывание данных между сокетом smoltcp и очередями движка; общее для обоих стеков.
//!
//! Со стороны TUN за сокетом приложение, со стороны тоннеля — сервер; здесь они неразличимы.

use bytes::Bytes;
use smoltcp::socket::tcp;
use tokio::sync::mpsc;

use super::table::Entry;

/// Перекладывает данные в обе стороны за один оборот цикла.
pub fn pump_data(socket: &mut tcp::Socket<'_>, entry: &mut Entry) {
    if entry
        .ends
        .aborted
        .load(std::sync::atomic::Ordering::Acquire)
    {
        socket.abort();
        return;
    }
    from_socket(socket, entry);
    to_socket(socket, entry);
}

/// От сокета к движку; задержанный блок идёт первым, иначе в потоке будет дыра.
fn from_socket(socket: &mut tcp::Socket<'_>, entry: &mut Entry) {
    let Some(to_engine) = &entry.ends.to_engine else {
        return;
    };
    loop {
        let chunk = match entry.to_engine.take() {
            Some(chunk) => chunk,
            None if socket.can_recv() => {
                let Ok(chunk) =
                    socket.recv(|buffer| (buffer.len(), Bytes::copy_from_slice(buffer)))
                else {
                    break;
                };
                if chunk.is_empty() {
                    break;
                }
                chunk
            }
            None => {
                // Без этого полузакрытое соединение висит в CLOSE_WAIT, а поток к серверу — открытым.
                if peer_finished(socket.state()) {
                    entry.ends.to_engine = None;
                }
                break;
            }
        };

        match to_engine.try_send(chunk) {
            Ok(()) => {}
            // Блок остаётся у нас: окно TCP закроется — это и есть обратное давление.
            Err(mpsc::error::TrySendError::Full(chunk)) => {
                entry.to_engine = Some(chunk);
                break;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
}

/// Сторона сокета прислала `FIN`: данных от неё больше не будет.
fn peer_finished(state: tcp::State) -> bool {
    matches!(
        state,
        tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait
    )
}

/// От движка к сокету; частичная запись оставляет хвост до следующего оборота.
fn to_socket(socket: &mut tcp::Socket<'_>, entry: &mut Entry) {
    loop {
        let chunk = match entry.to_socket.take() {
            Some(chunk) => chunk,
            None => match entry.ends.from_engine.try_recv() {
                Ok(chunk) => chunk,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
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

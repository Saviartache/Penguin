//! TCP-поток поверх двунаправленного QUIC-потока.
//!
//! Одно прикладное соединение — один поток QUIC внутри общего соединения с
//! сервером. Рукопожатие платится один раз на весь клиент, а не на каждую
//! вкладку браузера; блокировка головы очереди при этом не возникает, потому
//! что потоки QUIC независимы: потерянный пакет одного не задерживает
//! остальные.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::frame::tcp;

/// Будущее, дочитывающее ответ сервера и возвращающее поток обратно.
type PendingResponse = Pin<Box<dyn Future<Output = io::Result<RecvStream>> + Send>>;

/// Состояние приёмной половины.
enum Reading {
    /// Ответ сервера ещё не прочитан. Так бывает только при быстром старте.
    Awaiting(PendingResponse),
    /// Ответ разобран, дальше идут прикладные данные.
    Ready(RecvStream),
    /// Сервер отказал или поток сломался.
    Failed(Option<io::Error>),
}

/// Прикладной поток до целевого адреса.
///
/// Половины разделены в QUIC и живут своей жизнью. Отсюда важное свойство:
/// закрытие на запись (`poll_shutdown`) не рвёт чтение, и полузакрытое
/// соединение — то самое, на котором держится, например, `HTTP/1.0` с
/// `Connection: close`, — работает как ему положено.
pub struct TcpStream {
    send: SendStream,
    recv: Reading,
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &self.recv {
            Reading::Awaiting(_) => "ожидает ответа",
            Reading::Ready(_) => "готов",
            Reading::Failed(_) => "сломан",
        };
        f.debug_struct("TcpStream").field("recv", &state).finish()
    }
}

impl TcpStream {
    /// Поток, у которого ответ сервера уже прочитан и оказался успешным.
    pub fn established(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv: Reading::Ready(recv),
        }
    }

    /// Поток быстрого старта: запрос отправлен, ответ ещё не прочитан.
    ///
    /// Экономит один оборот до сервера на каждое соединение — приложение
    /// начинает слать данные, не дожидаясь подтверждения. Цена: отказ
    /// выясняется не при открытии, а при первом чтении, и к этому моменту
    /// приложение уже отправило свои первые байты в никуда.
    ///
    /// Ответ дочитывается лениво, на первом же `poll_read`. Отдельной задачей
    /// это сделать нельзя: у принимающей половины потока может быть только
    /// один читатель, и им должен остаться сам поток.
    pub fn fast_open(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv: Reading::Awaiting(Box::pin(read_response(recv))),
        }
    }
}

/// Дочитывает ответ сервера и отдаёт поток дальше.
async fn read_response(mut recv: RecvStream) -> io::Result<RecvStream> {
    let response = tcp::read_response(&mut recv).await?;
    if response.ok {
        Ok(recv)
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("сервер отказал в соединении: {}", response.message),
        ))
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match &mut this.recv {
                Reading::Ready(recv) => return AsyncRead::poll_read(Pin::new(recv), cx, buf),

                Reading::Awaiting(pending) => match ready!(pending.as_mut().poll(cx)) {
                    Ok(recv) => this.recv = Reading::Ready(recv),
                    Err(err) => this.recv = Reading::Failed(Some(err)),
                },

                Reading::Failed(err) => {
                    // Ошибка отдаётся один раз: повторное чтение сломанного
                    // потока — это конец данных, а не бесконечная ошибка.
                    return Poll::Ready(match err.take() {
                        Some(err) => Err(err),
                        None => Ok(()),
                    });
                }
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Явный вызов через трейт: у `SendStream` есть собственный `poll_write`
        // с другим типом ошибки, и без уточнения выбирается именно он.
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `poll_shutdown` у quinn закрывает поток на запись и ждёт, пока
        // отправленное будет подтверждено, — это и есть корректный аналог
        // `FIN` в TCP. Обрывать поток здесь (`reset`) было бы ошибкой:
        // приложение потеряло бы последние отправленные байты.
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

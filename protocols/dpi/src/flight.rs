//! Поток до сайта, у которого первая посылка уходит по плану обхода.
//!
//! # Почему это устроено состоянием, а не `async`-функцией
//!
//! Посылку, которую надо разрезать, пишет не этот крейт: её пишет конвейер
//! движка, копируя байты приложения в поток. Всё, что здесь есть, — это
//! [`AsyncWrite`], и первая запись в него попадает уже готовой.
//!
//! Отсюда две вещи. Первая: план исполняется прямо в `poll_write` — шагами
//! ([`Step`]), а не `await`-ами, потому что владеть задачей и ждать в ней
//! здесь некому. Вторая: сам поток при этом остаётся на месте — его вторую
//! половину в это же время читает соседняя задача (`tokio::io::split`), и
//! унести его внутрь незавершённого будущего значило бы остановить чтение.
//!
//! # Что считается первой посылкой
//!
//! Первая непустая запись. В режиме TUN это ровно приветствие приложения:
//! конвейер сначала читает начало соединения, чтобы узнать имя узла, и потом
//! отдаёт прочитанное одним куском.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use penguin_transport::desync::write::TtlStream;
use penguin_transport::desync::{DEFAULT_TTL, Desync, Step};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// Сколько байт первой записи вообще разрезается.
///
/// Решение DPI принимает по началу потока, и всё, что дальше, для обхода
/// бесполезно. Ограничение нужно ради памяти: без него сюда скопировалась бы
/// запись любого размера.
const MAX_FIRST_FLIGHT: usize = 16 * 1024;

/// Поток, обходящий DPI своей первой посылкой.
pub struct FirstFlight<S> {
    stream: S,
    plan: Desync,
    /// Имя узла: от него считаются точки разреза.
    host: Option<String>,
    state: State,
}

/// Что происходит с потоком сейчас.
enum State {
    /// Первой посылки ещё не было.
    Waiting,
    /// Посылка уходит по плану.
    Sending(Flight),
    /// Обычный поток: план исполнен либо неприменим.
    Plain,
}

/// Незавершённая отправка первой посылки.
struct Flight {
    payload: Vec<u8>,
    steps: Vec<Step>,
    /// Текущий шаг.
    at: usize,
    /// Сколько байт текущего куска уже записано.
    written: usize,
    /// TTL, с которым сокет пришёл, — его же и возвращаем.
    normal_ttl: u32,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl<S: TtlStream> FirstFlight<S> {
    /// Оборачивает соединение планом обхода.
    pub fn new(stream: S, plan: Desync, host: Option<String>) -> Self {
        Self {
            stream,
            plan,
            host,
            state: State::Waiting,
        }
    }

    /// Готовит отправку первой посылки.
    ///
    /// План, состоящий из одного куска, — это отсутствие плана: имени узла в
    /// посылке не нашлось и резать не по чему. Тогда поток становится обычным
    /// и не платит ни копированием, ни лишним состоянием.
    fn begin(&mut self, buf: &[u8]) {
        let payload = buf[..buf.len().min(MAX_FIRST_FLIGHT)].to_vec();
        // Ложной посылки здесь нет и быть не может: на том конце обычный
        // сайт (см. документ крейта).
        let steps = self.plan.steps(&payload, self.host.as_deref(), false);
        if steps.len() < 2 {
            self.state = State::Plain;
            return;
        }

        // Без этого куски склеятся в ядре, и разреза не будет ни одного.
        let _ = self.stream.set_nodelay(true);
        self.state = State::Sending(Flight {
            payload,
            steps,
            at: 0,
            written: 0,
            // Значение сокета, а не своё: у Windows умолчание 128, а не 64,
            // и вернуть «как у всех» значило бы сменить приметы всему
            // дальнейшему разговору.
            normal_ttl: self.stream.ttl().unwrap_or(DEFAULT_TTL),
            sleep: None,
        });
    }

    /// Двигает отправку до ближайшего ожидания.
    ///
    /// Готово — это записанная целиком первая посылка; столько байт и
    /// засчитывается вызывающему.
    fn drive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let State::Sending(flight) = &mut self.state else {
            return Poll::Ready(Ok(0));
        };

        while let Some(step) = flight.steps.get(flight.at) {
            match step {
                Step::Fool => {
                    let _ = self.stream.set_ttl(self.plan.ttl());
                }
                Step::Restore => {
                    let _ = self.stream.set_ttl(flight.normal_ttl);
                }
                // Шага с ложной посылкой план без неё не выдаёт.
                Step::Decoy => {}
                Step::Chunk(piece) => {
                    let from = piece.start + flight.written;
                    let tail = &flight.payload[from..piece.end];
                    match ready!(Pin::new(&mut self.stream).poll_write(cx, tail)) {
                        Ok(0) => {
                            let _ = self.stream.set_ttl(flight.normal_ttl);
                            self.state = State::Plain;
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Ok(written) => {
                            flight.written += written;
                            if from + written < piece.end {
                                continue;
                            }
                            flight.written = 0;
                        }
                        Err(err) => {
                            // TTL возвращается при любом исходе: иначе весь
                            // дальнейший разговор ушёл бы на три перехода.
                            let _ = self.stream.set_ttl(flight.normal_ttl);
                            self.state = State::Plain;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                Step::Pause(pause) => {
                    let sleep = flight
                        .sleep
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep(*pause)));
                    ready!(sleep.as_mut().poll(cx));
                    flight.sleep = None;
                }
            }
            flight.at += 1;
        }

        let sent = flight.payload.len();
        let _ = self.stream.set_ttl(flight.normal_ttl);
        self.state = State::Plain;
        Poll::Ready(Ok(sent))
    }
}

impl<S: TtlStream + AsyncRead + Unpin> AsyncWrite for FirstFlight<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if matches!(me.state, State::Waiting) && !buf.is_empty() {
            me.begin(buf);
        }
        match me.state {
            // Отправка началась с первой записи и с неё же считает байты:
            // вызывающий обязан повторить её тем же куском, и `write_all`
            // именно так и делает.
            State::Sending(_) => me.drive(cx),
            _ => Pin::new(&mut me.stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstFlight<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.stream).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use penguin_transport::desync::DesyncConfig;
    use tokio::io::AsyncWriteExt;

    use super::*;

    /// Сокет, который запоминает, что и с каким TTL в него записали.
    #[derive(Default)]
    struct Recorder {
        ttl: Mutex<u32>,
        nodelay: Mutex<bool>,
        writes: Mutex<Vec<(u32, Vec<u8>)>>,
        /// Сколько байт принимать за раз. Ноль — сколько дадут.
        chunk: usize,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                ttl: Mutex::new(DEFAULT_TTL),
                ..Self::default()
            }
        }

        /// Сокет, принимающий по столько байт за раз: так ведёт себя полное
        /// окно отправки, и кусок в него влезает не целиком.
        fn slow(chunk: usize) -> Self {
            Self {
                chunk,
                ..Self::new()
            }
        }

        fn writes(&self) -> Vec<(u32, Vec<u8>)> {
            self.writes.lock().map(|w| w.clone()).unwrap_or_default()
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let take = if self.chunk == 0 {
                buf.len()
            } else {
                self.chunk.min(buf.len())
            };
            let ttl = self.ttl.lock().map(|t| *t).unwrap_or(DEFAULT_TTL);
            if let Ok(mut writes) = self.writes.lock() {
                writes.push((ttl, buf[..take].to_vec()));
            }
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl TtlStream for Recorder {
        fn ttl(&self) -> io::Result<u32> {
            self.ttl.lock().map(|t| *t).map_err(broken)
        }

        fn set_ttl(&self, ttl: u32) -> io::Result<()> {
            *self.ttl.lock().map_err(broken)? = ttl;
            Ok(())
        }

        fn set_nodelay(&self, on: bool) -> io::Result<()> {
            *self.nodelay.lock().map_err(broken)? = on;
            Ok(())
        }
    }

    fn broken<E>(_: E) -> io::Error {
        io::Error::other("замок сломан")
    }

    fn plan(strategy: &str) -> Desync {
        DesyncConfig {
            strategy: strategy.to_owned(),
            ..DesyncConfig::default()
        }
        .compile()
        .expect("настройки верны")
    }

    /// Приветствие с именем узла внутри — то, ради чего всё и заведено.
    fn hello() -> Vec<u8> {
        let mut payload = vec![0u8; 8];
        payload.extend_from_slice(b"rutracker.org");
        payload.extend_from_slice(&[0u8; 8]);
        payload
    }

    #[tokio::test]
    async fn the_name_is_cut_in_the_middle() {
        let mut stream = FirstFlight::new(
            Recorder::new(),
            plan("multisplit"),
            Some("rutracker.org".to_owned()),
        );
        stream.write_all(&hello()).await.expect("записалось");

        let pieces: Vec<Vec<u8>> = stream
            .stream
            .writes()
            .into_iter()
            .map(|(_, data)| data)
            .collect();
        assert_eq!(pieces.len(), 2, "имя обязано разъехаться по сегментам");
        assert!(pieces[0].ends_with(b"rutrac"));
        assert!(pieces[1].starts_with(b"ker.org"));
        assert!(
            *stream.stream.nodelay.lock().expect("замок"),
            "без NODELAY куски склеятся в ядре"
        );
    }

    #[tokio::test]
    async fn only_the_first_flight_is_touched() {
        // Резать весь разговор незачем: решение DPI принимает по началу
        // потока, а каждый лишний разрез — это лишний сегмент.
        let mut stream = FirstFlight::new(
            Recorder::new(),
            plan("multisplit"),
            Some("rutracker.org".to_owned()),
        );
        stream.write_all(&hello()).await.expect("записалось");
        stream
            .write_all(b"GET / HTTP/1.1")
            .await
            .expect("записалось");

        let writes = stream.stream.writes();
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[2].1, b"GET / HTTP/1.1".to_vec());
    }

    #[tokio::test]
    async fn disorder_lowers_the_ttl_of_the_first_piece_only() {
        let mut stream = FirstFlight::new(
            Recorder::new(),
            plan("disorder"),
            Some("rutracker.org".to_owned()),
        );
        stream.write_all(&hello()).await.expect("записалось");

        let writes = stream.stream.writes();
        assert_eq!(writes[0].0, 3, "первый кусок обязан не дойти");
        assert_eq!(writes[1].0, DEFAULT_TTL, "второй — дойти");
        assert_eq!(
            stream.stream.ttl().expect("TTL"),
            DEFAULT_TTL,
            "TTL не вернули: весь разговор уйдёт на три перехода"
        );
    }

    #[tokio::test]
    async fn a_payload_without_the_name_goes_whole() {
        // Резать по ориентиру, которого в посылке нет, нечего — и выдумывать
        // место нельзя: лишний сегмент ничего не обходит.
        let mut stream = FirstFlight::new(
            Recorder::new(),
            plan("multisplit"),
            Some("rutracker.org".to_owned()),
        );
        stream
            .write_all(b"nothing like it")
            .await
            .expect("записалось");
        assert_eq!(stream.stream.writes().len(), 1);
    }

    #[tokio::test]
    async fn a_piece_that_does_not_fit_at_once_is_written_to_the_end() {
        // Окно отправки бывает полным, и `poll_write` принимает меньше, чем
        // дали. Досчитать байты обязан этот слой: вызывающему он обещал
        // записать посылку целиком.
        let mut stream = FirstFlight::new(
            Recorder::slow(3),
            plan("multisplit"),
            Some("rutracker.org".to_owned()),
        );
        let payload = hello();
        stream.write_all(&payload).await.expect("записалось");

        let written: Vec<u8> = stream
            .stream
            .writes()
            .into_iter()
            .flat_map(|(_, data)| data)
            .collect();
        assert_eq!(
            written, payload,
            "посылка обязана уйти целиком и по порядку"
        );
    }
}

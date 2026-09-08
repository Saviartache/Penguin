//! Сама отправка первой посылки по плану: разрез, перестановка, ложная копия.
//!
//! # Почему это работает из пространства пользователя
//!
//! Двумя свойствами обычного сокета, и больше ничем.
//!
//! **`TCP_NODELAY`.** Без него ядро склеит куски в один сегмент, и разрез
//! перестанет существовать раньше, чем дойдёт до сети. С ним каждый `write`
//! почти всегда становится отдельным сегментом — «почти» здесь честное:
//! гарантии соответствия «один `write` — один сегмент» в TCP нет и быть не
//! может, но при коротких посылках и пустой очереди отправки оно выполняется.
//!
//! **TTL сокета.** Его можно менять на живом соединении, и следующий сегмент
//! уйдёт уже с новым. На этом стоят и `disorder`, и `fake`: сегмент с малым
//! TTL умирает на маршрутизаторе за DPI, но DPI его увидеть успевает.
//!
//! # Гонка, которой здесь нельзя избежать
//!
//! TTL читается ядром в момент, когда пакет уходит, а не в момент `write`.
//! Между «записали кусок с малым TTL» и «вернули TTL обратно» есть окно, в
//! котором пакет может уйти уже с восстановленным значением, и весь приём
//! превратится в обычную отправку. Лечится это единственным доступным
//! способом — паузой ([`FOOLING_PAUSE`](crate::desync::plan::FOOLING_PAUSE))
//! перед возвратом TTL. У `zapret2` этой гонки нет вовсе: там пакет собирают
//! целиком и отдают в сеть сами.

use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::desync::plan::{DEFAULT_TTL, Desync, Step};

/// Соединение, у которого можно менять TTL.
///
/// Отдельный типаж, а не [`TcpStream`] прямо в сигнатуре, ровно ради тестов:
/// проверить порядок кусков и значения TTL можно без сети, а с настоящим
/// сокетом нельзя — TTL уходящего пакета из процесса не виден.
pub trait TtlStream: AsyncWrite + Unpin + Send {
    /// Текущий TTL исходящих пакетов.
    fn ttl(&self) -> io::Result<u32>;

    /// Меняет TTL исходящих пакетов.
    fn set_ttl(&self, ttl: u32) -> io::Result<()>;

    /// Включает или выключает склейку мелких посылок.
    fn set_nodelay(&self, on: bool) -> io::Result<()>;
}

impl TtlStream for TcpStream {
    fn ttl(&self) -> io::Result<u32> {
        TcpStream::ttl(self)
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        TcpStream::set_ttl(self, ttl)
    }

    fn set_nodelay(&self, on: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, on)
    }
}

/// Отправляет первую посылку по плану.
///
/// `decoy` — ложная посылка; её выдумывает протокол, а не этот слой (см.
/// документ [`crate::desync`] о том, почему её обязан пропускать сервер).
/// `host` — имя узла внутри посылки, по которому считаются ориентиры разреза.
///
/// TTL возвращается на место при любом исходе, включая ошибку записи: иначе
/// весь дальнейший разговор ушёл бы с малым TTL и не дошёл бы никуда.
pub async fn send_first_flight<S: TtlStream>(
    stream: &mut S,
    plan: &Desync,
    payload: &[u8],
    decoy: Option<&[u8]>,
    host: Option<&str>,
) -> io::Result<()> {
    if plan.is_disabled() {
        stream.write_all(payload).await?;
        return stream.flush().await;
    }

    // Без этого куски склеятся в ядре, и разреза не будет ни одного.
    stream.set_nodelay(true)?;

    // Значение сокета, а не своя константа: у Windows умолчание 128, а не 64,
    // и вернуть «как у всех» значило бы сменить приметы всему дальнейшему
    // разговору — ровно то, от чего обход и заводят.
    let original = stream.ttl().unwrap_or(DEFAULT_TTL);
    let result = run(stream, plan, payload, decoy, host, original).await;
    // Ошибку возврата глотаем намеренно: она означает уже закрытый сокет, и
    // настоящая причина — та, что в `result`.
    let _ = stream.set_ttl(original);
    result
}

async fn run<S: TtlStream>(
    stream: &mut S,
    plan: &Desync,
    payload: &[u8],
    decoy: Option<&[u8]>,
    host: Option<&str>,
    normal_ttl: u32,
) -> io::Result<()> {
    for step in plan.steps(payload, host, decoy.is_some()) {
        match step {
            Step::Fool => stream.set_ttl(plan.ttl())?,
            Step::Restore => stream.set_ttl(normal_ttl)?,
            Step::Decoy => {
                // Шага `Decoy` без ложной посылки план не выдаёт.
                if let Some(decoy) = decoy {
                    stream.write_all(decoy).await?;
                    stream.flush().await?;
                }
            }
            Step::Chunk(piece) => {
                stream.write_all(&payload[piece]).await?;
                stream.flush().await?;
            }
            Step::Pause(pause) => tokio::time::sleep(pause).await,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use super::*;
    use crate::desync::plan::DesyncConfig;

    /// Сокет, который запоминает, что и с каким TTL в него записали.
    #[derive(Default)]
    struct Recorder {
        ttl: Mutex<u32>,
        nodelay: Mutex<bool>,
        writes: Mutex<Vec<(u32, Vec<u8>)>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                ttl: Mutex::new(DEFAULT_TTL),
                ..Self::default()
            }
        }

        fn writes(&self) -> Vec<(u32, Vec<u8>)> {
            self.writes.lock().map(|w| w.clone()).unwrap_or_default()
        }

        fn payloads(&self) -> Vec<Vec<u8>> {
            self.writes().into_iter().map(|(_, data)| data).collect()
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let ttl = self.ttl.lock().map(|t| *t).unwrap_or(DEFAULT_TTL);
            if let Ok(mut writes) = self.writes.lock() {
                writes.push((ttl, buf.to_vec()));
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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

    fn plan(strategy: &str, split: &[&str]) -> Desync {
        DesyncConfig {
            strategy: strategy.to_owned(),
            split_pos: split.iter().map(|s| (*s).to_owned()).collect(),
            ..DesyncConfig::default()
        }
        .compile()
        .expect("настройки верны")
    }

    #[tokio::test]
    async fn without_a_plan_the_payload_goes_in_one_piece() {
        let mut socket = Recorder::new();
        send_first_flight(&mut socket, &Desync::disabled(), b"hello", None, None)
            .await
            .expect("записалось");
        assert_eq!(socket.payloads(), vec![b"hello".to_vec()]);
        assert!(
            !*socket.nodelay.lock().expect("замок"),
            "склейку не трогали"
        );
    }

    #[tokio::test]
    async fn multisplit_cuts_the_payload_where_asked() {
        let mut socket = Recorder::new();
        send_first_flight(
            &mut socket,
            &plan("multisplit", &["2"]),
            b"hello",
            None,
            None,
        )
        .await
        .expect("записалось");
        assert_eq!(socket.payloads(), vec![b"he".to_vec(), b"llo".to_vec()]);
        assert!(
            *socket.nodelay.lock().expect("замок"),
            "без NODELAY склеится"
        );
    }

    #[tokio::test]
    async fn disorder_sends_the_first_piece_with_a_short_ttl() {
        // Ради этого приём и существует: первый кусок не доходит, повтор
        // приходит позже, и поток у DPI собирается не тем порядком.
        let mut socket = Recorder::new();
        send_first_flight(&mut socket, &plan("disorder", &["2"]), b"hello", None, None)
            .await
            .expect("записалось");

        let writes = socket.writes();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0], (3, b"he".to_vec()));
        assert_eq!(writes[1], (DEFAULT_TTL, b"llo".to_vec()));
        assert_eq!(socket.ttl().expect("TTL"), DEFAULT_TTL, "TTL не вернули");
    }

    #[tokio::test]
    async fn disorder_without_a_cut_does_not_kill_the_only_piece() {
        // Единственный кусок с малым TTL — это соединение, которое не
        // состоится: повторять его будет нечем, потому что за ним ничего нет.
        let mut socket = Recorder::new();
        send_first_flight(
            &mut socket,
            &plan("disorder", &["99"]),
            b"hello",
            None,
            None,
        )
        .await
        .expect("записалось");
        assert_eq!(socket.writes(), vec![(DEFAULT_TTL, b"hello".to_vec())]);
    }

    #[tokio::test]
    async fn a_fake_goes_first_and_with_a_short_ttl() {
        let mut socket = Recorder::new();
        send_first_flight(
            &mut socket,
            &plan("fake", &[]),
            b"real",
            Some(b"decoy"),
            None,
        )
        .await
        .expect("записалось");

        assert_eq!(
            socket.writes(),
            vec![(3, b"decoy".to_vec()), (DEFAULT_TTL, b"real".to_vec())]
        );
    }

    #[tokio::test]
    async fn a_fake_is_repeated_as_many_times_as_asked() {
        let plan = DesyncConfig {
            strategy: "fake".to_owned(),
            repeats: 3,
            ..DesyncConfig::default()
        }
        .compile()
        .expect("настройки верны");

        let mut socket = Recorder::new();
        send_first_flight(&mut socket, &plan, b"real", Some(b"decoy"), None)
            .await
            .expect("записалось");
        assert_eq!(socket.writes().len(), 4);
    }

    #[tokio::test]
    async fn without_a_decoy_the_fake_phase_is_simply_skipped() {
        // Ложную посылку выдумывает протокол; не дал — значит, ему нечего
        // послать, и выдумывать её здесь нельзя: пропустит её только тот
        // сервер, который о ней знает.
        let mut socket = Recorder::new();
        send_first_flight(&mut socket, &plan("fake", &[]), b"real", None, None)
            .await
            .expect("записалось");
        assert_eq!(socket.payloads(), vec![b"real".to_vec()]);
    }

    #[tokio::test]
    async fn fakedsplit_does_both() {
        let mut socket = Recorder::new();
        send_first_flight(
            &mut socket,
            &plan("fakedsplit", &["2"]),
            b"hello",
            Some(b"decoy"),
            None,
        )
        .await
        .expect("записалось");

        assert_eq!(
            socket.payloads(),
            vec![b"decoy".to_vec(), b"he".to_vec(), b"llo".to_vec()]
        );
    }

    #[tokio::test]
    async fn the_cut_is_measured_from_the_host_inside_the_payload() {
        let mut socket = Recorder::new();
        let payload = b"....www.google.com....";
        send_first_flight(
            &mut socket,
            &plan("multisplit", &["midsld"]),
            payload,
            None,
            Some("www.google.com"),
        )
        .await
        .expect("записалось");

        let pieces = socket.payloads();
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0], b"....www.goo".to_vec());
        assert_eq!(pieces[1], b"gle.com....".to_vec());
    }
}

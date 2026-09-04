//! Пишущая сторона сессии: дополнение и буфер начала.
//!
//! # Почему запись отдельно
//!
//! Дополнение считается **по записям TLS**, а не по кадрам: схема говорит,
//! сколько байт должна занимать запись номер `N`. Значит каждая запись должна
//! уйти своим вызовом со сбросом — иначе куски сольются в одну запись, и вся
//! схема перестанет значить то, что значит. Собрано это здесь, чтобы правило
//! было в одном месте и проверялось без сети.
//!
//! # Буфер начала
//!
//! Первая запись сессии обязана нести настройки, открытие потока и адрес
//! назначения разом: схема считает их одним пакетом, и по отдельности они
//! выглядят иначе. Поэтому сессия начинается с [`Writer::hold`], а отпускает
//! буфер тот, кто открыл первый поток.

use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::frame::{self, HEADER_LEN};
use crate::padding::{Scheme, Step};

/// Пишущая сторона сессии.
#[derive(Debug)]
pub struct Writer<W> {
    io: W,
    /// Копить записи вместо отправки.
    holding: bool,
    /// Накопленное.
    buffer: Vec<u8>,
    /// Дополнять ли ещё. Выключается навсегда после `stop`.
    padding: bool,
    /// Номер записи. Нулевая ушла с опознанием, до сессии.
    pkt: u32,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// Заводит пишущую сторону. Первая запись копится, а не уходит.
    pub fn new(io: W) -> Self {
        Self {
            io,
            holding: true,
            buffer: Vec::new(),
            padding: true,
            pkt: 0,
        }
    }

    /// Копить записи, пока не позовут [`Writer::release`].
    pub fn hold(&mut self) {
        self.holding = true;
    }

    /// Перестать копить. Накопленное уйдёт со следующей записью.
    pub fn release(&mut self) {
        self.holding = false;
    }

    /// Номер последней записи. Нужен журналу и тестам.
    pub fn packets(&self) -> u32 {
        self.pkt
    }

    /// Кладёт байты в буфер начала, минуя дополнение.
    ///
    /// Только для кадра настроек: он собирается до того, как о сессии узнал
    /// кто-нибудь ещё, и уходит первой записью вместе с открытием потока.
    pub fn stash(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Соединение под пишущей стороной: нужно, чтобы закрыть свою половину.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.io
    }

    /// Отправляет кадр, дополняя запись по схеме.
    pub async fn write(&mut self, scheme: &Scheme, frame: &[u8]) -> io::Result<()> {
        if self.holding {
            self.buffer.extend_from_slice(frame);
            return Ok(());
        }

        // Накопленное едет вместе со следующим кадром — одной записью, как и
        // задумано схемой.
        let joined;
        let rest: &[u8] = if self.buffer.is_empty() {
            frame
        } else {
            let mut both = std::mem::take(&mut self.buffer);
            both.extend_from_slice(frame);
            joined = both;
            &joined
        };

        if self.padding {
            self.pkt = self.pkt.wrapping_add(1);
            if self.pkt < scheme.stop() {
                return self.padded(scheme.steps(self.pkt), rest).await;
            }
            // Схема кончилась. Дальше сессия выглядит собой — и это не
            // упущение: дополнять весь разговор стоило бы вдвое дороже, а
            // опознают его по началу.
            self.padding = false;
        }

        write_record(&mut self.io, rest).await
    }

    /// Раскладывает кадр по записям, которые назвала схема.
    async fn padded(&mut self, steps: Vec<Step>, mut rest: &[u8]) -> io::Result<()> {
        for step in steps {
            let remain = rest.len();
            let size = match step {
                // Данные кончились — дальше не дополнять.
                Step::Check if remain == 0 => break,
                Step::Check => continue,
                Step::Size(size) => size,
            };

            if remain > size {
                // Записи мало: уходит ровно столько, сколько назвали.
                write_record(&mut self.io, &rest[..size]).await?;
                rest = &rest[size..];
            } else if remain > 0 {
                // Хвост данных и дополнение до нужного размера за ним.
                let pad = size.saturating_sub(remain + HEADER_LEN);
                if pad > 0 {
                    let mut record = Vec::with_capacity(size);
                    record.extend_from_slice(rest);
                    record.extend_from_slice(&waste(pad));
                    write_record(&mut self.io, &record).await?;
                } else {
                    // Дополнению не хватило места даже на заголовок: запись
                    // уходит как есть. Так же поступает эталон.
                    write_record(&mut self.io, rest).await?;
                }
                rest = &[];
            } else {
                // Данных нет: запись целиком из дополнения.
                write_record(&mut self.io, &waste(size)).await?;
            }
        }

        if !rest.is_empty() {
            write_record(&mut self.io, rest).await?;
        }
        Ok(())
    }
}

/// Отправляет одну запись TLS.
///
/// Сброс здесь обязателен: без него куски склеятся в одну запись, и схема
/// перестанет значить то, что значит.
async fn write_record<W: AsyncWrite + Unpin>(io: &mut W, bytes: &[u8]) -> io::Result<()> {
    io.write_all(bytes).await?;
    io.flush().await
}

/// Кадр-дополнение с нулями внутри.
fn waste(len: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + len);
    frame.extend_from_slice(
        &frame::Header {
            cmd: frame::CMD_WASTE,
            sid: 0,
            len: len.min(frame::MAX_PAYLOAD) as u16,
        }
        .encode(),
    );
    frame.resize(HEADER_LEN + len.min(frame::MAX_PAYLOAD), 0);
    frame
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use crate::padding::Scheme;

    /// Приёмник, который помнит каждую запись отдельно.
    #[derive(Debug, Default)]
    struct Records(Vec<Vec<u8>>);

    impl AsyncWrite for Records {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().0.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn sizes(records: &Records) -> Vec<usize> {
        records.0.iter().map(Vec::len).collect()
    }

    fn scheme(text: &str) -> Scheme {
        Scheme::parse(text.as_bytes()).expect("схема разбирается")
    }

    #[tokio::test]
    async fn a_held_write_goes_out_with_the_next_one() {
        // Настройки, открытие потока и адрес обязаны уехать одной записью:
        // схема считает их одним пакетом.
        let scheme = scheme("stop=2\n1=100-100");
        let mut writer = Writer::new(Records::default());

        writer.write(&scheme, b"aaa").await.expect("копится");
        assert!(sizes(&writer.io).is_empty(), "запись ушла раньше времени");

        writer.release();
        writer.write(&scheme, b"bbb").await.expect("уходит");
        assert_eq!(sizes(&writer.io), vec![100]);
        assert!(writer.io.0[0].starts_with(b"aaabbb"));
    }

    #[tokio::test]
    async fn a_short_write_is_padded_up_to_the_size() {
        let scheme = scheme("stop=2\n1=100-100");
        let mut writer = Writer::new(Records::default());
        writer.release();

        writer.write(&scheme, b"hello").await.expect("уходит");
        assert_eq!(sizes(&writer.io), vec![100]);

        // За данными — кадр-дополнение ровно на остаток.
        let record = &writer.io.0[0];
        assert_eq!(&record[..5], b"hello");
        assert_eq!(record[5], frame::CMD_WASTE);
        let len = u16::from_be_bytes([record[10], record[11]]);
        assert_eq!(usize::from(len), 100 - 5 - HEADER_LEN);
    }

    #[tokio::test]
    async fn a_long_write_is_cut_into_the_sizes_the_scheme_names() {
        let scheme = scheme("stop=2\n1=10-10,20-20");
        let mut writer = Writer::new(Records::default());
        writer.release();

        writer.write(&scheme, &[7_u8; 100]).await.expect("уходит");
        // Десять, двадцать — и остаток одной записью следом.
        assert_eq!(sizes(&writer.io), vec![10, 20, 70]);
    }

    #[tokio::test]
    async fn a_check_mark_stops_the_padding_when_the_data_runs_out() {
        // В этом и смысл проверки: не гнать пустые записи, когда посылать
        // больше нечего.
        let scheme = scheme("stop=2\n1=50-50,c,500-500,c,500-500");
        let mut writer = Writer::new(Records::default());
        writer.release();

        writer.write(&scheme, b"hi").await.expect("уходит");
        assert_eq!(sizes(&writer.io), vec![50]);
    }

    #[tokio::test]
    async fn a_check_mark_is_ignored_while_data_is_left() {
        let scheme = scheme("stop=2\n1=10-10,c,30-30");
        let mut writer = Writer::new(Records::default());
        writer.release();

        writer.write(&scheme, &[7_u8; 25]).await.expect("уходит");
        assert_eq!(sizes(&writer.io), vec![10, 30]);
    }

    #[tokio::test]
    async fn sizes_left_after_the_data_are_filled_with_padding() {
        // Без проверки схема добивает записи дополнением — так у эталона, и
        // размер такой записи на семь байт больше названного.
        let scheme = scheme("stop=2\n1=20-20,30-30");
        let mut writer = Writer::new(Records::default());
        writer.release();

        writer.write(&scheme, &[7_u8; 5]).await.expect("уходит");
        assert_eq!(sizes(&writer.io), vec![20, 30 + HEADER_LEN]);
        assert_eq!(writer.io.0[1][0], frame::CMD_WASTE);
    }

    #[tokio::test]
    async fn a_size_too_small_for_a_padding_frame_is_sent_as_is() {
        // Разница между размером и данными меньше заголовка: дополнять нечем,
        // запись уходит длиннее названного. Так же поступает эталон.
        let scheme = scheme("stop=2\n1=12-12");
        let mut writer = Writer::new(Records::default());
        writer.release();

        writer.write(&scheme, &[7_u8; 10]).await.expect("уходит");
        assert_eq!(sizes(&writer.io), vec![10]);
    }

    #[tokio::test]
    async fn a_packet_the_scheme_says_nothing_about_goes_out_whole() {
        let scheme = scheme("stop=8\n1=10-10");
        let mut writer = Writer::new(Records::default());
        writer.release();

        writer.write(&scheme, &[7_u8; 5]).await.expect("первая");
        writer.write(&scheme, &[7_u8; 40]).await.expect("вторая");
        assert_eq!(sizes(&writer.io)[1..], [40]);
    }

    #[tokio::test]
    async fn padding_stops_for_good_at_the_stop_mark() {
        let scheme = scheme("stop=3\n1=100-100\n2=100-100\n3=100-100");
        let mut writer = Writer::new(Records::default());
        writer.release();

        for _ in 0..4 {
            writer.write(&scheme, b"x").await.expect("уходит");
        }
        // Пакеты 1 и 2 дополнены, 3 и 4 — уже нет.
        assert_eq!(sizes(&writer.io), vec![100, 100, 1, 1]);
        assert_eq!(writer.packets(), 3, "счётчик встал вместе с дополнением");
    }
}

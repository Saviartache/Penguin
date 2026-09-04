//! Задача чтения сессии: разбирает кадры и раскладывает их по потокам.
//!
//! Читает всё соединение одна задача, потому что кадры разных потоков идут
//! вперемешку и разделить их можно только здесь. Она же отвечает на проверки
//! живости и принимает новую схему дополнения.
//!
//! Задача держит слабую ссылку, а не обычную: сессия, которую никто не держит,
//! должна умереть, а не жить, пока сервер молчит.

use std::sync::Weak;

use bytes::Bytes;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, ReadHalf};

use crate::frame::{self, HEADER_LEN, Header};
use crate::kv::Map;
use crate::session::{Msg, Session};

/// Сколько букв текста отказа брать в журнал.
///
/// Текст пишет сервер, а журнал читают люди: длинная строка оттуда — это
/// чужие байты в нашем файле.
const ALERT_LIMIT: usize = 256;

/// Читает сессию, пока она жива.
pub async fn run(session: Weak<Session>, io: ReadHalf<Box<dyn ProxyStream>>) {
    let reason = read_loop(&session, io).await;

    let Some(session) = session.upgrade() else {
        return;
    };
    tracing::debug!(seq = session.seq(), %reason, "сессия AnyTLS закрылась");
    session.mark_dead(reason);
    session.shutdown().await;
    if let Some(pool) = session.pool() {
        pool.forget(session.seq());
    }
}

/// Разбирает кадры, пока не кончатся. Возвращает причину конца.
async fn read_loop(session: &Weak<Session>, mut io: ReadHalf<Box<dyn ProxyStream>>) -> String {
    let mut head = [0_u8; HEADER_LEN];
    loop {
        if let Err(err) = io.read_exact(&mut head).await {
            return match err.kind() {
                std::io::ErrorKind::UnexpectedEof => "сервер закрыл соединение".to_owned(),
                _ => format!("чтение не прошло: {err}"),
            };
        }
        let header = Header::decode(&head);

        let mut data = vec![0_u8; usize::from(header.len)];
        if !data.is_empty()
            && let Err(err) = io.read_exact(&mut data).await
        {
            return format!("кадр оборвался на середине: {err}");
        }

        let Some(session) = session.upgrade() else {
            return "сессию больше никто не держит".to_owned();
        };
        if let Err(reason) = handle(&session, header, data).await {
            return reason;
        }
    }
}

/// Обрабатывает один кадр. `Err` — сессию дальше вести нельзя.
async fn handle(session: &Session, header: Header, data: Vec<u8>) -> Result<(), String> {
    match header.cmd {
        frame::CMD_PSH => {
            if !data.is_empty() {
                session
                    .deliver(header.sid, Msg::Data(Bytes::from(data)))
                    .await;
            }
        }

        frame::CMD_SYN_ACK => {
            session.note_synack();
            if !data.is_empty() {
                // Подтверждение с данными — это отказ: сервер не смог
                // открыть соединение и объяснил почему.
                let text = String::from_utf8_lossy(&data).into_owned();
                session.deliver(header.sid, Msg::Failed(text)).await;
                session.forget_stream(header.sid);
            }
        }

        frame::CMD_FIN => {
            // Сначала конец в очередь, потом снятие потока: иначе очередь
            // закроется раньше, чем поток узнает, что она кончилась мирно.
            session.deliver(header.sid, Msg::Eof).await;
            session.forget_stream(header.sid);
        }

        // Дополнение: прочитано и забыто.
        frame::CMD_WASTE => {}

        frame::CMD_ALERT => {
            let text: String = String::from_utf8_lossy(&data)
                .chars()
                .take(ALERT_LIMIT)
                .collect();
            return Err(format!("сервер отказал: {text}"));
        }

        frame::CMD_UPDATE_PADDING => {
            if session.padding().update(&data) {
                tracing::debug!(
                    md5 = session.padding().get().md5(),
                    "принята схема дополнения от сервера"
                );
            } else {
                // Не повод рвать сессию: прежняя схема рабочая, и хуже от
                // непринятой становится только сходство трафика с обычным.
                tracing::warn!("схема дополнения от сервера не разбирается");
            }
        }

        frame::CMD_SERVER_SETTINGS => {
            if let Some(version) = Map::parse(&data).get("v").and_then(|v| v.parse().ok()) {
                session.set_peer_version(version);
            }
        }

        frame::CMD_HEART_REQUEST => {
            if let Err(err) = session
                .write_frame(frame::CMD_HEART_RESPONSE, header.sid, &[])
                .await
            {
                return Err(format!("не отвечает проверка живости: {err}"));
            }
        }

        // Ответ на проверку, которую мы не шлём: сервер вправе её слать, мы —
        // молча принимать.
        frame::CMD_HEART_RESPONSE => {}

        // Команды сервера, пришедшие клиенту. Это не «новый протокол», а «на
        // том конце не то»: вести такую сессию дальше нельзя.
        frame::CMD_SYN | frame::CMD_SETTINGS => {
            return Err(format!(
                "сервер прислал команду {:#04x}, которую шлёт клиент",
                header.cmd
            ));
        }

        // Незнакомая команда. Данные её уже прочитаны и выброшены — этим мы
        // отличаемся от эталона, который длину пропускает и разъезжается на
        // первом же кадре с данными.
        other => {
            tracing::debug!(cmd = other, len = header.len, "неизвестная команда AnyTLS");
        }
    }
    Ok(())
}

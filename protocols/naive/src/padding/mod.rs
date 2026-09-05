//! Дополнение трафика — сверено с эталоном (`klzgrad/naiveproxy`, тег
//! `v150.0.7871.63-1`, файлы под `src/net/tools/naive/`).
//!
//! В эталоне это **два независимых механизма**, и путать их нельзя:
//!
//! 1. **Заголовки согласования** (этот модуль) — решают, будет ли вообще
//!    применяться дополнение, и уходят один раз, в самом запросе `CONNECT` и
//!    в ответе на него.
//! 2. **Дополнение байтового потока** ([`frame`]) — обрамляет первые восемь
//!    операций чтения и первые восемь операций записи уже после того, как
//!    туннель установлен.
//!
//! # Согласование
//!
//! Клиент шлёт заголовок `padding` **всегда**, независимо от того, поддержит
//! его сервер или нет: обычный прокси, не знающий об этой схеме, заголовок
//! просто проигнорирует (`naive_proxy_delegate.cc`, комментарий у места
//! отправки: «Sends client-side padding header regardless of server
//! support»). Рядом уходит `padding-type-request` со списком поддерживаемых
//! типов через запятую, в порядке предпочтения; этот клиент поддерживает
//! только [`PaddingType::Variant1`], и список у него из одного числа.
//!
//! Сервер отвечает `padding-type-reply` с выбранным типом. Ради обратной
//! совместимости с версиями до появления этого заголовка действует запасное
//! правило: если `padding-type-reply` нет, но заголовок `padding` в ответе
//! есть — считается [`PaddingType::Variant1`]; если нет и его — дополнения
//! не будет (`http_proxy_server_socket.cc`, `ParsePaddingHeaders`).
//!
//! Эти заголовки шлются и читаются одинаково для HTTP/2 и HTTP/3: оба
//! клиентских сокета эталона (`spdy_proxy_client_socket.cc` для HTTP/2,
//! `quic_proxy_client_socket.cc` для HTTP/3) вызывают один и тот же метод
//! `ProxyDelegate::OnBeforeTunnelRequest`/`OnTunnelHeadersReceived`. Это
//! противоречит собственному комментарию эталона в
//! `naive_proxy_delegate.h` — «This only affects h2 proxy client socket» —
//! но комментарию здесь верить нельзя: код обоих сокетов проходит через
//! этот путь одинаково, и официального объяснения расхождению найти не
//! удалось.
//!
//! # Что упрощено против эталона
//!
//! Значение заголовка `padding` эталон набирает не произвольными символами, а
//! кодами HPACK, не входящими в статическую таблицу и не сжимаемыми
//! Хаффманом (`padding_utils.cc`, `FillNonindexHeaderValue`) — так дополнение
//! не ужимается кодированием заголовков и не совпадает случайно с
//! проиндексированным именем. Сервер содержимое не проверяет, ему важно
//! только наличие заголовка, поэтому здесь используется обычный случайный
//! ASCII — на совместимость это не влияет, только на статистическую
//! неотличимость значения заголовка от настоящего клиента Chromium. Тем, кто
//! этого добивается, придётся повторить таблицу HPACK.
//!
//! Заголовок `fastopen` (посылается только после того, как тип дополнения для
//! этого сервера уже был согласован ранее) не реализован: это отдельная
//! оптимизация задержки на повторных соединениях, а не часть схемы
//! дополнения, и `plan.md` её не требует.
//!
//! # Чего нет в HTTP/3
//!
//! У HTTP/2 в эталоне есть третий, отдельный трюк: перед `RST_STREAM`
//! отправляется поддельный кадр `DATA` с `END_STREAM`, чтобы пара кадров по
//! размеру напоминала `HEADERS` (`net/spdy/spdy_session.cc`,
//! `EnqueueResetStreamFrame`, диапазон 48-72 байта). Это код самого
//! Chromium, а не `net/tools/naive/`, и относится к тому, как сессия HTTP/2
//! завершает **чужой** поток по инициативе стороны, которая его сбрасывает
//! (в основном сервер, отменяющий встречный трафик), а не к обмену данными
//! CONNECT-туннеля. Здесь он не реализован — как и в HTTP/3, где эталон
//! обходится общей схемой ниже безо всякого кадрового аналога (в
//! `quic_chromium_client_session.cc` на этот счёт стоит незакрытый `TODO`,
//! `crbug.com/515272365`).

pub mod frame;

use http::HeaderMap;

pub use frame::PaddedStream;

/// Заголовок, которым клиент заявляет о поддержке дополнения.
///
/// Значение не проверяется сервером — важно только наличие
/// (`http_proxy_server_socket.cc`, `ParsePaddingHeaders`).
pub const HEADER_PADDING: &str = "padding";

/// Заголовок запроса: список поддерживаемых типов через запятую, в порядке
/// предпочтения.
pub const HEADER_TYPE_REQUEST: &str = "padding-type-request";

/// Заголовок ответа: выбранный сервером тип, одним числом.
pub const HEADER_TYPE_REPLY: &str = "padding-type-reply";

/// Какое дополнение действует на соединении.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingType {
    /// Дополнения нет: сервер не поддерживает схему или отказался от неё.
    None,
    /// Единственная схема, которую понимает эталон — и этот клиент.
    Variant1,
}

impl PaddingType {
    /// Число, которым тип записывается в заголовках (`naive_protocol.h`).
    const fn wire(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Variant1 => 1,
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        match value.trim() {
            "0" => Some(Self::None),
            "1" => Some(Self::Variant1),
            _ => None,
        }
    }
}

/// Наименьшая длина значения заголовка `padding` в запросе.
const REQUEST_PADDING_MIN: usize = 16;
/// Наибольшая длина значения заголовка `padding` в запросе.
const REQUEST_PADDING_MAX: usize = 32;

/// Символы для значения заголовка `padding`.
///
/// Не таблица HPACK эталона (см. документацию модуля) — обычный безопасный
/// ASCII, который не значит ничего сверх своей длины.
const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Собирает заголовки запроса `CONNECT`, объявляющие поддержку дополнения.
///
/// Возвращает пары «имя, значение» — вызывающая сторона решает, как класть их
/// в `http::Request`: у `h2` и `h3` это разные builder'ы.
pub fn request_headers() -> [(&'static str, String); 2] {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let len = rng.gen_range(REQUEST_PADDING_MIN..=REQUEST_PADDING_MAX);
    let padding: String = (0..len)
        .map(|_| {
            let index = rng.gen_range(0..ALPHABET.len());
            char::from(ALPHABET[index])
        })
        .collect();

    [
        (HEADER_PADDING, padding),
        (
            HEADER_TYPE_REQUEST,
            PaddingType::Variant1.wire().to_string(),
        ),
    ]
}

/// Разбирает ответ сервера и решает, какой тип дополнения действует.
///
/// Порядок проверки — как в эталоне: явный `padding-type-reply`, а если его
/// нет — обратная совместимость по одному лишь присутствию `padding`.
pub fn negotiate(headers: &HeaderMap) -> PaddingType {
    if let Some(reply) = headers.get(HEADER_TYPE_REPLY) {
        if let Ok(text) = reply.to_str()
            && let Some(kind) = PaddingType::from_wire(text)
        {
            return kind;
        }
        // Заголовок есть, но не разбирается: сервер имел в виду что-то, чего
        // этот клиент не понимает. Безопаснее ничего не дополнять, чем
        // угадать не тот вариант и разойтись с сервером в формате кадра.
        return PaddingType::None;
    }
    if headers.contains_key(HEADER_PADDING) {
        return PaddingType::Variant1;
    }
    PaddingType::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_padding_is_within_bounds() {
        for _ in 0..50 {
            let headers = request_headers();
            let padding = &headers[0].1;
            assert!((REQUEST_PADDING_MIN..=REQUEST_PADDING_MAX).contains(&padding.len()));
            assert!(padding.bytes().all(|b| ALPHABET.contains(&b)));
            assert_eq!(headers[1].1, "1");
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("имя"),
                value.parse().expect("значение"),
            );
        }
        map
    }

    #[test]
    fn an_explicit_reply_wins() {
        assert_eq!(
            negotiate(&headers(&[(HEADER_TYPE_REPLY, "1")])),
            PaddingType::Variant1
        );
        assert_eq!(
            negotiate(&headers(&[(HEADER_TYPE_REPLY, "0")])),
            PaddingType::None
        );
    }

    #[test]
    fn without_a_reply_the_bare_header_means_variant1() {
        // Обратная совместимость с сервером, который ещё не знает про
        // `padding-type-reply`.
        assert_eq!(
            negotiate(&headers(&[(HEADER_PADDING, "xxxxxxxxxxxxxxxx")])),
            PaddingType::Variant1
        );
    }

    #[test]
    fn no_headers_at_all_means_no_padding() {
        // Обычный прокси, ничего не знающий про эту схему.
        assert_eq!(negotiate(&headers(&[])), PaddingType::None);
    }

    #[test]
    fn an_unreadable_reply_is_treated_as_no_padding() {
        // Лучше ничего не дополнять, чем угадать не тот формат кадра.
        assert_eq!(
            negotiate(&headers(&[(HEADER_TYPE_REPLY, "7")])),
            PaddingType::None
        );
    }
}

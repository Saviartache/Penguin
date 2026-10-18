//! Готовая к работе обфускация над уже собранными кадрами WireGuard: junk и
//! сигнатуры `I1`–`I5`, padding, магические заголовки, а в AWG 3 — защита
//! заголовков, хвосты и добавка к содержимому. Чистая логика над байтами — без
//! сокета и `tokio`, тестируется на записанных кадрах (`AGENTS.md` §2.3).
//!
//! Сверено с `amneziawg-go` (`device/send.go`, `device/receive.go`,
//! `DeterminePacketTypeAndPadding`). Без `header_protection_key` маска типа
//! (`typeHash`) нулевая, и первые четыре байта кадра — магический заголовок как есть.

use penguin_proto::random;

use crate::crypto::constants::{
    AEAD_TAG_LEN, INITIATION_MESSAGE_LEN, RESPONSE_MESSAGE_LEN, TRANSPORT_HEADER_LEN,
};
use crate::obfs::chain::Chain;
use crate::obfs::padding::UdpWindow;
use crate::obfs::protect::HeaderKey;

/// Наименьший пакет данных: заголовок и метка AEAD без содержимого
/// (`MessageTransportSize` в `device/noise-protocol.go`).
const TRANSPORT_MIN_LEN: usize = TRANSPORT_HEADER_LEN + AEAD_TAG_LEN;

/// Размер cookie-ответа (`MessageCookieReplySize`); клиент его не разбирает.
const COOKIE_MESSAGE_LEN: usize = 64;

/// Диапазон `[lo, hi]` включительно (`UintRange` эталона): заголовки `Hx` и
/// `content_padding_addition`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct UintRange {
    lo: u32,
    hi: u32,
}

impl UintRange {
    /// Диапазон из одного значения — как в конфигурациях Amnezia.
    pub(super) const fn single(value: u32) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    /// Диапазон `[lo, hi]`; вызывающий гарантирует `lo <= hi`.
    pub(super) const fn new(lo: u32, hi: u32) -> Self {
        Self { lo, hi }
    }

    /// Границы диапазона.
    pub(super) const fn bounds(self) -> (u32, u32) {
        (self.lo, self.hi)
    }

    /// Значение внутри диапазона (`Contains` эталона, включительно с обоих концов).
    fn contains(self, value: u32) -> bool {
        self.lo <= value && value <= self.hi
    }

    /// Случайное значение `[lo, hi]` (`PickOne` эталона).
    pub(super) fn pick_value(self) -> u32 {
        let span = u64::from(self.hi - self.lo) + 1;
        self.lo + random::range(0..span) as u32
    }

    /// Случайное значение как 4 байта LE — магический заголовок.
    fn pick(self) -> [u8; 4] {
        self.pick_value().to_le_bytes()
    }
}

/// Класс входящей датаграммы, которую получает клиент.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MsgKind {
    /// Ответ на рукопожатие (тип 2).
    Response,
    /// Cookie-ответ сервера (тип 3); не разбирается.
    Cookie,
    /// Пакет данных (тип 4).
    Transport,
}

/// Результат классификации: класс и границы кадра внутри датаграммы (padding снят).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Classified {
    /// Класс кадра.
    pub kind: MsgKind,
    /// Смещение начала кадра (длина переднего padding `Sx`).
    pub start: usize,
    /// Смещение конца кадра (хвост, если он есть, остаётся за ним).
    pub end: usize,
}

/// Добавки AmneziaWG 3; по умолчанию выключены — обфускация v1/v2.
#[derive(Clone, Default)]
pub(super) struct Awg3 {
    /// Защита заголовков.
    pub(super) protection: Option<HeaderKey>,
    /// Сигнатуры `I1`–`I5` по порядку, пустые пропущены.
    pub(super) signatures: Vec<Chain>,
    /// `content_padding_addition`.
    pub(super) content_padding: Option<UintRange>,
    /// `random_trailers`.
    pub(super) random_trailers: bool,
}

/// Разрешённые параметры обфускации AmneziaWG и окно UDP соединения
/// (`peer.udpWindow`): им меряются хвосты AWG 3. Владеет водитель.
#[derive(Clone)]
pub struct Obfuscation {
    jc: u32,
    jmin: u32,
    jmax: u32,
    s_init: usize,
    s_response: usize,
    s_cookie: usize,
    s_transport: usize,
    h_init: UintRange,
    h_response: UintRange,
    h_cookie: UintRange,
    h_transport: UintRange,
    v3: Awg3,
    window: UdpWindow,
}

impl Obfuscation {
    /// Собирает из разобранных полей (`Sx` в байтах, `Hx` — диапазоны) без добавок AWG 3.
    pub(super) fn new(jc: u32, jmin: u32, jmax: u32, s: [u16; 4], h: [UintRange; 4]) -> Self {
        Self {
            jc,
            jmin,
            jmax,
            s_init: s[0] as usize,
            s_response: s[1] as usize,
            s_cookie: s[2] as usize,
            s_transport: s[3] as usize,
            h_init: h[0],
            h_response: h[1],
            h_cookie: h[2],
            h_transport: h[3],
            v3: Awg3::default(),
            window: UdpWindow::default(),
        }
    }

    /// Включает добавки AWG 3; `Sx >= 12` при защите проверяет вызывающий.
    pub(super) fn with_v3(mut self, v3: Awg3) -> Self {
        self.v3 = v3;
        self
    }

    /// Магический заголовок инициации; ставится до расчёта `mac1`.
    pub fn init_header(&self) -> [u8; 4] {
        self.h_init.pick()
    }

    /// Пакеты перед инициацией: сигнатуры `I1`–`I5`, затем junk
    /// (`SendHandshakeInitiation`).
    pub fn prelude(&self) -> Vec<Vec<u8>> {
        let mut packets: Vec<Vec<u8>> = self.v3.signatures.iter().map(Chain::generate).collect();
        packets.extend(self.junk_packets());
        packets
    }

    /// Junk-пакеты: `Jc` штук длиной `[Jmin, Jmax)`
    /// (`JunkPackets` эталона: `min + fastrandn(max - min)`).
    fn junk_packets(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        let span = self.jmax.saturating_sub(self.jmin);
        (0..self.jc).map(move |_| {
            let extra = if span == 0 {
                0
            } else {
                random::range(0..u64::from(span)) as usize
            };
            let mut buf = vec![0u8; self.jmin as usize + extra];
            random::fill(&mut buf);
            buf
        })
    }

    /// Датаграмма инициации: `S1` случайных байт, кадр (под защитой, если она
    /// есть) и случайный хвост при `random_trailers`.
    pub fn wrap_initiation(&self, message: &[u8; INITIATION_MESSAGE_LEN]) -> Vec<u8> {
        let framed = self.s_init + message.len();
        let trailer = if self.v3.random_trailers {
            self.window.trailer(framed)
        } else {
            0
        };
        let mut out = vec![0u8; framed + trailer];
        random::fill(&mut out[..self.s_init]);
        out[self.s_init..framed].copy_from_slice(message);
        random::fill(&mut out[framed..]);
        self.protect(&mut out, self.s_init, framed);
        out
    }

    /// Сколько нулей дописать к открытому тексту пакета данных до шифрования
    /// (`RoutineEncryption`): `content_padding_addition`, иначе случайный хвост.
    /// Окно сперва учитывает сам пакет, как у эталона.
    pub fn transport_padding(&mut self, plaintext_len: usize) -> usize {
        let size = self.s_transport + TRANSPORT_MIN_LEN + plaintext_len;
        self.window.observe(size);
        match self.v3.content_padding {
            Some(range) => self.window.addition(range, size),
            None if self.v3.random_trailers => self.window.trailer(size),
            None => 0,
        }
    }

    /// Учитывает в окне принятый пакет данных: `padding + 16 + открытый текст`
    /// (`RoutineSequentialReceiver`).
    pub fn observe_received(&mut self, start: usize, plaintext_len: usize) {
        self.window
            .observe(start + TRANSPORT_HEADER_LEN + plaintext_len);
    }

    /// Оборачивает готовый пакет данных: заголовок `H4`, `S4` случайных байт
    /// спереди и защита 16 байт заголовка.
    pub fn wrap_transport(&self, sealed: &mut Vec<u8>) {
        sealed[..4].copy_from_slice(&self.h_transport.pick());
        prepend_random(self.s_transport, sealed);
        self.protect(
            sealed,
            self.s_transport,
            self.s_transport + TRANSPORT_HEADER_LEN,
        );
    }

    /// Распознаёт датаграмму и снимает защиту на месте: с ответа и cookie —
    /// целиком, с пакета данных — заголовок. Магический заголовок остаётся
    /// в первых четырёх байтах кадра; `None` — датаграмма не наша.
    pub fn open(&self, datagram: &mut [u8]) -> Option<Classified> {
        let mask = match &self.v3.protection {
            Some(key) => key.type_mask(datagram)?,
            None => [0; 4],
        };
        let found = self.classify(datagram, mask)?;
        if let Some(key) = &self.v3.protection {
            let protected_end = match found.kind {
                MsgKind::Transport => found.start + TRANSPORT_HEADER_LEN,
                MsgKind::Response | MsgKind::Cookie => found.end,
            };
            if !key.apply(datagram, found.start, protected_end) {
                return None;
            }
        }
        Some(found)
    }

    /// Класс по длине и диапазону заголовка, снятого маской
    /// (`DeterminePacketTypeAndPadding` эталона).
    fn classify(&self, datagram: &[u8], mask: [u8; 4]) -> Option<Classified> {
        let size = datagram.len();
        let header_at = |pad: usize| -> Option<u32> {
            let four = datagram.get(pad..pad + 4)?;
            let mut header = [0u8; 4];
            for (i, byte) in header.iter_mut().enumerate() {
                *byte = four[i] ^ mask[i];
            }
            Some(u32::from_le_bytes(header))
        };
        // Рукопожатие — точная длина, с хвостами — не короче; данные — не короче.
        let fixed = |pad: usize, msg_len: usize| {
            size == pad + msg_len || (self.v3.random_trailers && size > pad + msg_len)
        };
        let frame = |kind, start: usize, end: usize| Classified { kind, start, end };

        if fixed(self.s_response, RESPONSE_MESSAGE_LEN)
            && header_at(self.s_response).is_some_and(|h| self.h_response.contains(h))
        {
            let end = self.s_response + RESPONSE_MESSAGE_LEN;
            return Some(frame(MsgKind::Response, self.s_response, end));
        }
        if fixed(self.s_cookie, COOKIE_MESSAGE_LEN)
            && header_at(self.s_cookie).is_some_and(|h| self.h_cookie.contains(h))
        {
            let end = self.s_cookie + COOKIE_MESSAGE_LEN;
            return Some(frame(MsgKind::Cookie, self.s_cookie, end));
        }
        if size >= self.s_transport + TRANSPORT_MIN_LEN
            && header_at(self.s_transport).is_some_and(|h| self.h_transport.contains(h))
        {
            return Some(frame(MsgKind::Transport, self.s_transport, size));
        }
        None
    }

    /// Защита `datagram[start..end]`, если она включена.
    fn protect(&self, datagram: &mut [u8], start: usize, end: usize) {
        if let Some(key) = &self.v3.protection {
            // Не срабатывает: `Sx >= 12` проверено в `AmneziaParams::validate`.
            let applied = key.apply(datagram, start, end);
            debug_assert!(applied, "padding короче nonce защиты заголовков");
        }
    }
}

/// Вставляет `pad` случайных байт в начало буфера.
fn prepend_random(pad: usize, buf: &mut Vec<u8>) {
    if pad == 0 {
        return;
    }
    let body = buf.len();
    buf.resize(body + pad, 0);
    buf.copy_within(0..body, pad);
    random::fill(&mut buf[..pad]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::constants::{MESSAGE_RESPONSE, MESSAGE_TRANSPORT_DATA};
    use crate::obfs::protect::{KEY_LEN, NONCE_LEN};

    const H_RESPONSE: u32 = 0x7D21_93FE;
    const H_TRANSPORT: u32 = 0x5E6F_7A8B;

    fn headers() -> [UintRange; 4] {
        [
            UintRange::single(0x4C56_8A11),
            UintRange::single(H_RESPONSE),
            UintRange::single(0x1A2B_3C4D),
            UintRange::single(H_TRANSPORT),
        ]
    }

    /// Обфускация в духе выданной Amnezia: junk, небольшой padding, заголовки-одиночки.
    fn obfs() -> Obfuscation {
        Obfuscation::new(3, 40, 70, [15, 17, 0, 0], headers())
    }

    /// Нулевая обфускация = стандартный WireGuard: заголовки 1–4, без padding.
    fn plain() -> Obfuscation {
        Obfuscation::new(
            0,
            0,
            0,
            [0, 0, 0, 0],
            [
                UintRange::single(1),
                UintRange::single(2),
                UintRange::single(3),
                UintRange::single(4),
            ],
        )
    }

    /// Ключ 00..1f — тот же, что во внешнем векторе `protect`.
    fn key() -> HeaderKey {
        let mut bytes = [0u8; KEY_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        HeaderKey::new(bytes)
    }

    /// AWG 3: защита заголовков, все `Sx` не короче nonce.
    fn awg3() -> Obfuscation {
        Obfuscation::new(0, 0, 0, [12, 20, 12, 12], headers()).with_v3(Awg3 {
            protection: Some(key()),
            ..Awg3::default()
        })
    }

    /// Nonce RFC 8439 §2.3.2 — тот же, что во внешнем векторе `protect`.
    const NONCE: [u8; NONCE_LEN] = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];

    #[test]
    fn a_response_is_recognised_by_its_padded_length_and_header_range() {
        let o = obfs();
        let mut datagram = vec![0u8; 17 + RESPONSE_MESSAGE_LEN];
        datagram[17..21].copy_from_slice(&H_RESPONSE.to_le_bytes());
        let c = o.open(&mut datagram).expect("ответ распознан");
        assert_eq!(c.kind, MsgKind::Response);
        assert_eq!((c.start, c.end), (17, 17 + RESPONSE_MESSAGE_LEN));
    }

    #[test]
    fn a_response_with_a_header_outside_the_range_is_not_a_response() {
        let o = obfs();
        let mut datagram = vec![0u8; 17 + RESPONSE_MESSAGE_LEN];
        datagram[17..21].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        assert!(o.open(&mut datagram).is_none());
    }

    #[test]
    fn a_data_packet_is_recognised_by_minimum_length_and_header_range() {
        let o = obfs();
        let mut datagram = vec![9u8; TRANSPORT_MIN_LEN + 200];
        datagram[0..4].copy_from_slice(&H_TRANSPORT.to_le_bytes());
        let c = o.open(&mut datagram).expect("данные распознаны");
        assert_eq!(c.kind, MsgKind::Transport);
        assert_eq!((c.start, c.end), (0, datagram.len()));
    }

    #[test]
    fn standard_frames_classify_without_any_obfuscation() {
        let o = plain();

        let mut response = vec![0u8; RESPONSE_MESSAGE_LEN];
        response[0] = MESSAGE_RESPONSE;
        assert_eq!(
            o.open(&mut response).expect("ответ").kind,
            MsgKind::Response
        );

        let mut data = vec![0u8; TRANSPORT_MIN_LEN + 50];
        data[0] = MESSAGE_TRANSPORT_DATA;
        assert_eq!(o.open(&mut data).expect("данные").kind, MsgKind::Transport);
    }

    #[test]
    fn an_unrecognised_datagram_is_dropped() {
        assert!(obfs().open(&mut [1, 2, 3]).is_none());
        assert!(plain().open(&mut [7u8; 9]).is_none());
        assert!(awg3().open(&mut [7u8; 9]).is_none());
    }

    #[test]
    fn wrapping_an_initiation_prepends_exactly_s1_random_bytes_and_keeps_the_body() {
        let o = obfs();
        let message = [0xABu8; INITIATION_MESSAGE_LEN];
        let datagram = o.wrap_initiation(&message);
        assert_eq!(datagram.len(), 15 + INITIATION_MESSAGE_LEN);
        assert_eq!(&datagram[15..], &message[..]);
    }

    #[test]
    fn wrapping_a_data_packet_sets_the_header_and_leaves_room_for_padding() {
        let mut h = headers();
        h[0] = UintRange::single(1);
        let o = Obfuscation::new(0, 0, 0, [0, 0, 0, 3], h);
        let mut sealed = vec![MESSAGE_TRANSPORT_DATA, 0, 0, 0];
        sealed.extend_from_slice(&[0x11u8; TRANSPORT_MIN_LEN]);
        o.wrap_transport(&mut sealed);
        assert_eq!(sealed.len(), 3 + 4 + TRANSPORT_MIN_LEN);
        assert_eq!(&sealed[3..7], &H_TRANSPORT.to_le_bytes());
    }

    #[test]
    fn the_right_number_of_junk_packets_is_produced_within_the_length_window() {
        let packets = obfs().prelude();
        assert_eq!(packets.len(), 3);
        for packet in packets {
            assert!((40..70).contains(&packet.len()), "длина {}", packet.len());
        }
    }

    #[test]
    fn no_prelude_when_there_is_neither_junk_nor_a_signature() {
        assert!(plain().prelude().is_empty());
    }

    #[test]
    fn signatures_go_out_first_and_in_order_then_junk() {
        let chain = |spec| Chain::parse(spec).expect("разбор").expect("теги");
        let o = obfs().with_v3(Awg3 {
            signatures: vec![chain("<b 0x01>"), chain("<b 0x0202>")],
            ..Awg3::default()
        });
        let packets = o.prelude();
        assert_eq!(packets.len(), 2 + 3);
        assert_eq!(packets[0], vec![0x01]);
        assert_eq!(packets[1], vec![0x02, 0x02]);
        assert!(packets[2..].iter().all(|p| (40..70).contains(&p.len())));
    }

    #[test]
    fn a_recorded_protected_data_packet_is_recognised_and_its_header_revealed() {
        // Провод: nonce (он же `S4` = 12) ‖ заголовок под потоком ‖ шифротекст.
        // Байты заголовка — `openssl enc -chacha20` над `H4 ‖ получатель ‖ счётчик`.
        let mut datagram = NONCE.to_vec();
        datagram.extend_from_slice(&[
            0x01, 0xa6, 0xfe, 0xa3, 0xdb, 0xc7, 0xd2, 0xe4, 0x1c, 0x0f, 0xad, 0x50, 0xff, 0x15,
            0xd6, 0x37,
        ]);
        datagram.extend_from_slice(&[0xEE; AEAD_TAG_LEN + 8]);

        let c = awg3().open(&mut datagram).expect("данные распознаны");
        assert_eq!(c.kind, MsgKind::Transport);
        assert_eq!((c.start, c.end), (12, datagram.len()));
        assert_eq!(&datagram[12..16], &H_TRANSPORT.to_le_bytes());
        assert_eq!(&datagram[16..20], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&datagram[20..28], &7u64.to_le_bytes());
        assert_eq!(
            &datagram[28..],
            &[0xEE; AEAD_TAG_LEN + 8],
            "шифротекст не тронут"
        );
    }

    #[test]
    fn without_the_key_a_protected_packet_is_not_recognised() {
        let o = awg3();
        let mut sealed = H_TRANSPORT.to_le_bytes().to_vec();
        sealed.extend_from_slice(&[0x33; TRANSPORT_MIN_LEN]);
        o.wrap_transport(&mut sealed);
        let unprotected = Obfuscation::new(0, 0, 0, [12, 20, 12, 12], headers());
        assert!(unprotected.open(&mut sealed.clone()).is_none());
        assert!(o.open(&mut sealed).is_some());
    }

    #[test]
    fn a_wrapped_data_packet_opens_back_to_its_header() {
        let o = awg3();
        let mut sealed = vec![MESSAGE_TRANSPORT_DATA, 0, 0, 0];
        sealed.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        sealed.extend_from_slice(&42u64.to_le_bytes());
        sealed.extend_from_slice(&[0x77; AEAD_TAG_LEN + 5]);
        let tail = sealed[TRANSPORT_HEADER_LEN..].to_vec();
        o.wrap_transport(&mut sealed);
        assert_eq!(
            &sealed[12 + TRANSPORT_HEADER_LEN..],
            &tail[..],
            "шифротекст вне защиты"
        );

        let c = o.open(&mut sealed).expect("распознан");
        assert_eq!(c.kind, MsgKind::Transport);
        assert_eq!(&sealed[12..16], &H_TRANSPORT.to_le_bytes());
        assert_eq!(&sealed[16..20], &0xA1B2_C3D4u32.to_le_bytes());
        assert_eq!(&sealed[20..28], &42u64.to_le_bytes());
    }

    #[test]
    fn a_protected_initiation_hides_the_whole_message_and_the_key_reveals_it() {
        let o = awg3();
        let mut message = [0x5Au8; INITIATION_MESSAGE_LEN];
        message[..4].copy_from_slice(&0x4C56_8A11u32.to_le_bytes());
        let mut datagram = o.wrap_initiation(&message);
        assert_eq!(datagram.len(), 12 + INITIATION_MESSAGE_LEN);
        assert_ne!(&datagram[12..], &message[..]);
        assert!(key().apply(&mut datagram, 12, 12 + INITIATION_MESSAGE_LEN));
        assert_eq!(&datagram[12..], &message[..]);
    }

    #[test]
    fn a_protected_response_opens_whole() {
        // Сервер: `S2` случайных байт, ответ с `H2`, весь ответ под потоком.
        let mut datagram = vec![0u8; 20 + RESPONSE_MESSAGE_LEN];
        random::fill(&mut datagram[..20]);
        let mut response = [0x42u8; RESPONSE_MESSAGE_LEN];
        response[..4].copy_from_slice(&H_RESPONSE.to_le_bytes());
        datagram[20..].copy_from_slice(&response);
        assert!(key().apply(&mut datagram, 20, 20 + RESPONSE_MESSAGE_LEN));

        let c = awg3().open(&mut datagram).expect("ответ распознан");
        assert_eq!(c.kind, MsgKind::Response);
        assert_eq!(&datagram[c.start..c.end], &response[..]);
    }

    #[test]
    fn with_random_trailers_a_longer_response_is_still_a_response() {
        let mut datagram = vec![0u8; 17 + RESPONSE_MESSAGE_LEN + 30];
        datagram[17..21].copy_from_slice(&H_RESPONSE.to_le_bytes());
        assert!(
            obfs().open(&mut datagram.clone()).is_none(),
            "без хвостов длина точная"
        );

        let o = obfs().with_v3(Awg3 {
            random_trailers: true,
            ..Awg3::default()
        });
        let c = o.open(&mut datagram).expect("ответ с хвостом");
        assert_eq!((c.start, c.end), (17, 17 + RESPONSE_MESSAGE_LEN));
    }

    #[test]
    fn a_trailer_follows_the_initiation_only_when_asked_for() {
        let message = [0u8; INITIATION_MESSAGE_LEN];
        assert_eq!(
            obfs().wrap_initiation(&message).len(),
            15 + INITIATION_MESSAGE_LEN
        );

        let o = obfs().with_v3(Awg3 {
            random_trailers: true,
            ..Awg3::default()
        });
        for _ in 0..50 {
            // Не длиннее окна (500).
            assert!(o.wrap_initiation(&message).len() <= 500);
        }
    }

    #[test]
    fn data_padding_comes_from_the_content_range_and_the_window_grows_first() {
        let mut o = obfs().with_v3(Awg3 {
            content_padding: Some(UintRange::new(8, 8)),
            ..Awg3::default()
        });
        assert_eq!(o.transport_padding(100), 8);
        assert_eq!(obfs().transport_padding(100), 0, "без AWG 3 нет добавки");

        // Пакет больше окна сам расширяет окно, и места для добавки нет.
        assert_eq!(o.transport_padding(1000), 0);
        let mut expected = UdpWindow::default();
        expected.observe(TRANSPORT_MIN_LEN + 1000);
        assert_eq!(o.window, expected);
    }

    #[test]
    fn a_received_data_packet_widens_the_window_for_later_trailers() {
        let mut o = obfs();
        o.observe_received(23, 1200);
        let mut expected = UdpWindow::default();
        expected.observe(23 + TRANSPORT_HEADER_LEN + 1200);
        assert_eq!(o.window, expected);
    }
}

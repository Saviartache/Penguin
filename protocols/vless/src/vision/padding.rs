//! Конверт набивки Vision: `XtlsPadding`/`XtlsUnpadding` (`XTLS/Xray-core`,
//! `proxy/proxy.go`).
//!
//! ```text
//!  первый блок направления:
//! +----------+---------+---------------+---------------+---------+---------+
//! | UUID(16) | команда | длина содерж. | длина набивки | содерж. | набивка |
//! +----------+---------+---------------+---------------+---------+---------+
//!      16         1            2               2           …         …
//!
//!  остальные блоки: то же самое без UUID.
//! ```
//!
//! Набивка существует ради того, чтобы длина заголовка VLESS и первых
//! пакетов не была видна стороннему наблюдателю по размерам записей на
//! проводе; её содержимое приёмник просто отбрасывает
//! (`XtlsUnpadding`, `b.Advance(len)`) — значения байт набивки эталон нигде
//! не проверяет, и этот код тоже.

use ring::rand::{SecureRandom, SystemRandom};

/// Размер обычного буфера эталона (`common/buf.Size`) — от него считается
/// предел набивки, чтобы весь блок уместился в одну прикладную запись
/// внешнего TLS ([`crate::reality`] ограничивает запись 16384 байтами,
/// заведомо больше).
const BUF_SIZE: usize = 8192;

/// `UUID(16) + команда(1) + длина(2) + длина(2)` — резерв на заголовок
/// блока, который эталон вычитает из предела набивки независимо от того,
/// шлётся ли UUID на самом деле (`XtlsPadding`, `buf.Size-21-contentLen`).
const HEADER_RESERVE: usize = 21;

/// Умолчание `testseed` (`NewVisionWriter`, `proxy.go`:
/// `testseed = []uint32{900, 500, 900, 256}`) — у аккаунта VLESS в этом
/// клиенте нет своего поля под него, и сервер увидит ровно то умолчание,
/// которое сам использовал бы для аккаунта без настройки `Testseed`.
pub const DEFAULT_TESTSEED: [u32; 4] = [900, 500, 900, 256];

/// Наибольшее содержимое одного блока, при котором набивка не уходит в
/// отрицательную длину — предел, которым эталон добивается тем же числом
/// через `ReshapeMultiBuffer` перед вызовом `XtlsPadding`; здесь эта же
/// граница просто становится пределом одного вызова `poll_write`.
pub const MAX_CONTENT: usize = BUF_SIZE - HEADER_RESERVE;

/// Что означает байт команды (`CommandPaddingContinue/End/Direct`,
/// `proxy.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Больше блоков набивки в этом направлении будет.
    Continue = 0,
    /// Это последний блок набивки; дальше — без конверта, но канал остаётся
    /// шифрованным как был.
    End = 1,
    /// Как [`Self::End`], но вдобавок с этого места оба конца снимают
    /// внешнее шифрование — вот он, второй слой шифрования, о котором весь
    /// этот крейт.
    Direct = 2,
}

impl Command {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Continue),
            1 => Some(Self::End),
            2 => Some(Self::Direct),
            _ => None,
        }
    }
}

/// Собирает один блок конверта. `uuid` — `Some` только у первого блока
/// направления. `long_padding` — `XtlsPadding`'s `longPadding`: длиннее,
/// пока не увидели содержимое, похожее на настоящий TLS.
pub fn pad(
    uuid: Option<&[u8; 16]>,
    command: Command,
    content: &[u8],
    long_padding: bool,
    testseed: [u32; 4],
    mut random_below: impl FnMut(u32) -> u32,
) -> Vec<u8> {
    // Ответственность вызывающего — не эта функция подрезает содержимое
    // молча (см. `stream.rs::MAX_CONTENT`-зажим перед вызовом); превышение
    // здесь — ошибка в клиенте `pad`, а не законный повод обрезать байты.
    debug_assert!(
        content.len() <= MAX_CONTENT,
        "содержимое блока Vision длиннее предела набивки"
    );
    let content_len = content.len() as u32;
    let raw_padding = if content_len < testseed[0] && long_padding {
        random_below(testseed[1]) + testseed[2] - content_len
    } else {
        random_below(testseed[3])
    };
    let max_padding =
        (BUF_SIZE - HEADER_RESERVE) as u32 - content_len.min((BUF_SIZE - HEADER_RESERVE) as u32);
    let padding_len = raw_padding.min(max_padding) as usize;
    let content_len = content_len as usize;

    let mut out = Vec::with_capacity(16 + 5 + content_len + padding_len);
    if let Some(uuid) = uuid {
        out.extend_from_slice(uuid);
    }
    out.push(command as u8);
    out.extend_from_slice(&(content_len as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    out
}

/// Один разобранный блок конверта: где начинается и заканчивается
/// содержимое внутри разбираемого среза, и сколько байт целиком занял блок.
#[derive(Debug, Clone, Copy)]
pub struct Block {
    /// Что делать после этого блока: продолжать конверт, закончить его или
    /// закончить и переключиться в прямой режим.
    pub command: Command,
    /// С какого байта разбираемого среза начинается содержимое блока.
    pub content_start: usize,
    /// Сколько байт содержимого в блоке.
    pub content_len: usize,
    /// Сколько байт разбираемого среза занял блок целиком — ровно столько
    /// нужно снять с накопленного буфера ([`bytes::Buf::advance`]).
    pub total_len: usize,
}

/// Пытается разобрать один блок из уже накопленных байт. `Ok(None)` —
/// данных пока недостаточно, это обычное дело в потоке, а не ошибка.
/// `has_uuid` — это первый блок направления, и он обязан начинаться с
/// ожидаемого UUID.
///
/// Эталон при несовпадении UUID молча считает остаток буфера сырыми байтами
/// без конверта (`XtlsUnpadding`, ветка `else { return b }`) — здесь вместо
/// этого явная ошибка (`Ok(Err(..))` — вызывающий превращает её в
/// `io::Error`): сервер, действительно понимающий Vision, всегда
/// подставляет наш собственный UUID в первый блок обоих направлений;
/// несовпадение означает разошедшиеся настройки, а не законный случай,
/// который стоит пропускать молча (AGENTS.md §4).
pub fn parse_block(
    buf: &[u8],
    has_uuid: bool,
    expected_uuid: &[u8; 16],
) -> Result<Option<Block>, String> {
    let prefix = if has_uuid { 16 } else { 0 };
    if buf.len() < prefix + 5 {
        return Ok(None);
    }
    if has_uuid && &buf[..16] != expected_uuid.as_slice() {
        return Err(
            "первый блок Vision начинается не с ожидаемого UUID — сервер не подтвердил Vision"
                .to_owned(),
        );
    }

    let command_byte = buf[prefix];
    let command = Command::from_byte(command_byte)
        .ok_or_else(|| format!("Vision: неизвестная команда {command_byte:#04x}"))?;
    let content_len = usize::from(u16::from_be_bytes([buf[prefix + 1], buf[prefix + 2]]));
    let padding_len = usize::from(u16::from_be_bytes([buf[prefix + 3], buf[prefix + 4]]));
    let content_start = prefix + 5;
    let total_len = content_start + content_len + padding_len;
    if buf.len() < total_len {
        return Ok(None);
    }
    Ok(Some(Block {
        command,
        content_start,
        content_len,
        total_len,
    }))
}

/// Случайное число в `0..bound` (`rand.Int(rand.Reader, big.NewInt(bound))`)
/// — длина набивки только маскирует размер полезной нагрузки и не участвует
/// ни в одном ключе, так что источник случайности здесь тот же `ring`, что и
/// у остального крейта, без отдельного `CryptoRng`-обвеса.
pub fn random_below(bound: u32) -> u32 {
    if bound == 0 {
        return 0;
    }
    let mut bytes = [0u8; 4];
    // Набивка — маскировка длины, а не ключевой материал: если системный
    // генератор вдруг недоступен, безопаснее отправить пакет без набивки,
    // чем оборвать соединение из-за неё.
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return 0;
    }
    u32::from_be_bytes(bytes) % bound
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    #[test]
    fn a_block_with_no_padding_round_trips() {
        let block = pad(
            Some(&UUID),
            Command::Continue,
            b"hello",
            false,
            DEFAULT_TESTSEED,
            |_| 0,
        );
        assert_eq!(&block[..16], &UUID);
        assert_eq!(block[16], Command::Continue as u8);
        assert_eq!(&block[17..19], &5u16.to_be_bytes());
        assert_eq!(&block[19..21], &0u16.to_be_bytes());
        assert_eq!(&block[21..26], b"hello");
        assert_eq!(block.len(), 26);

        let parsed = parse_block(&block, true, &UUID)
            .expect("разбирается")
            .expect("данных хватает");
        assert_eq!(parsed.command, Command::Continue);
        assert_eq!(
            &block[parsed.content_start..parsed.content_start + parsed.content_len],
            b"hello"
        );
        assert_eq!(parsed.total_len, block.len());
    }

    #[test]
    fn later_blocks_have_no_uuid_prefix() {
        let block = pad(None, Command::End, b"x", false, DEFAULT_TESTSEED, |_| 0);
        assert_eq!(block[0], Command::End as u8);
        let parsed = parse_block(&block, false, &UUID)
            .expect("разбирается")
            .expect("данных хватает");
        assert_eq!(parsed.total_len, block.len());
    }

    #[test]
    fn padding_length_is_reported_exactly() {
        let block = pad(
            None,
            Command::Continue,
            b"abc",
            true,
            DEFAULT_TESTSEED,
            |bound| bound - 1,
        );
        let padding_len = u16::from_be_bytes([block[3], block[4]]) as usize;
        assert_eq!(block.len(), 5 + 3 + padding_len);
    }

    #[test]
    fn padding_never_pushes_the_block_past_the_reserved_size() {
        // Плохой генератор всегда просит максимум — блок обязан остаться в
        // пределах `MAX_CONTENT + HEADER_RESERVE` (=`BUF_SIZE`).
        let content = vec![7u8; 100];
        let block = pad(
            Some(&UUID),
            Command::Continue,
            &content,
            true,
            DEFAULT_TESTSEED,
            |bound| bound.saturating_sub(1),
        );
        assert!(block.len() <= BUF_SIZE);
    }

    #[test]
    fn a_short_buffer_is_not_an_error() {
        assert!(
            parse_block(&[1, 2, 3], true, &UUID)
                .expect("не сломано")
                .is_none()
        );
    }

    #[test]
    fn an_unknown_command_is_refused() {
        let mut block = pad(
            None,
            Command::Continue,
            b"x",
            false,
            DEFAULT_TESTSEED,
            |_| 0,
        );
        block[0] = 0x7F;
        assert!(parse_block(&block, false, &UUID).is_err());
    }

    #[test]
    fn a_mismatched_uuid_is_refused_not_silently_forwarded() {
        let block = pad(
            Some(&[0xFF; 16]),
            Command::Continue,
            b"x",
            false,
            DEFAULT_TESTSEED,
            |_| 0,
        );
        let err = parse_block(&block, true, &UUID).expect_err("не тот UUID");
        assert!(err.contains("UUID"), "{err}");
    }

    #[test]
    fn random_below_zero_is_always_zero() {
        assert_eq!(random_below(0), 0);
    }

    #[test]
    fn random_below_stays_in_range() {
        for _ in 0..64 {
            assert!(random_below(10) < 10);
        }
    }
}

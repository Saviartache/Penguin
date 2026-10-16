//! Конверт набивки Vision (`XtlsPadding`/`XtlsUnpadding`, `XTLS/Xray-core`, `proxy/proxy.go`).
//!
//! Блок: `[UUID(16), только первый блок направления] команда(1) длина содержимого(2)
//! длина набивки(2) содержимое набивка`. Байты набивки приёмник отбрасывает не проверяя.

use penguin_proto::random;

/// Размер буфера эталона (`common/buf.Size`): от него считается предел набивки.
const BUF_SIZE: usize = 8192;

/// `UUID(16) + команда(1) + длины(4)`: резерв, вычитаемый эталоном всегда (`buf.Size-21-contentLen`).
const HEADER_RESERVE: usize = 21;

/// Умолчание `testseed` (`NewVisionWriter`, `proxy.go`).
pub const DEFAULT_TESTSEED: [u32; 4] = [900, 500, 900, 256];

/// Наибольшее содержимое блока; предел одного `poll_write`.
pub const MAX_CONTENT: usize = BUF_SIZE - HEADER_RESERVE;

/// Байт команды (`CommandPaddingContinue/End/Direct`, `proxy.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Будут ещё блоки набивки.
    Continue = 0,
    /// Последний блок; канал остаётся зашифрованным.
    End = 1,
    /// Как `End`, и оба конца снимают внешнее шифрование.
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

/// Собирает блок конверта; `uuid` — только у первого блока направления,
/// `long_padding` (`longPadding` эталона) — пока виден TLS.
pub fn pad(
    uuid: Option<&[u8; 16]>,
    command: Command,
    content: &[u8],
    long_padding: bool,
    testseed: [u32; 4],
    mut random_below: impl FnMut(u32) -> u32,
) -> Vec<u8> {
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

/// Разобранный блок конверта.
#[derive(Debug, Clone, Copy)]
pub struct Block {
    /// Что делать после блока.
    pub command: Command,
    /// Начало содержимого в разбираемом срезе.
    pub content_start: usize,
    /// Длина содержимого.
    pub content_len: usize,
    /// Длина блока целиком.
    pub total_len: usize,
}

/// Разбирает один блок; `Ok(None)` — байт не хватает. `has_uuid` — первый блок направления.
///
/// Чужой UUID — ошибка, а не сырые байты, как у эталона (`XtlsUnpadding`): это разошедшиеся настройки.
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

/// Случайное число в `0..bound`; длина набивки не ключевой материал.
pub fn random_below(bound: u32) -> u32 {
    random::range(0..u64::from(bound)) as u32
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

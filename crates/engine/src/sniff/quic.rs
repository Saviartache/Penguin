//! SNI из QUIC Initial.
//!
//! В QUIC имя тоже есть — в том же ClientHello, — но добраться до него
//! заметно труднее: пакет Initial зашифрован. Ключ при этом не секретный, он
//! выводится из идентификатора соединения по фиксированной формуле
//! (RFC 9001, §5.2), поэтому расшифровать Initial может кто угодно, включая
//! наблюдателя. Защиты от чтения там и не предполагалось — только от
//! вмешательства.
//!
//! # Что здесь реализовано
//!
//! Разбор заголовка и проверка, что это действительно QUIC Initial. Снятие
//! защиты заголовка и расшифровка полезной нагрузки — **нет**: для этого
//! нужен AEAD с выводом ключей по HKDF, то есть криптографическая
//! зависимость в крейте, который сейчас обходится без неё.
//!
//! # Почему это приемлемо
//!
//! Имя для QUIC-трафика достаётся другим путём и раньше: приложение сначала
//! спрашивает адрес у DNS, а DNS у нас свой ([`penguin_dns::fakeip`]), и
//! обратное отображение возвращает имя по подставному адресу в момент
//! соединения. Опознание в потоке — запасной способ, и для QUIC он нужен
//! только там, где приложение пришло с готовым адресом, минуя наш DNS.

/// Первый байт пакета с длинным заголовком: бит `0x80` взведён, `0x40` тоже.
const LONG_HEADER_MASK: u8 = 0xC0;

/// Тип пакета `Initial` в битах 4–5 первого байта (QUIC v1).
const PACKET_TYPE_INITIAL: u8 = 0x00;

/// Версия QUIC v1.
const QUIC_V1: u32 = 0x0000_0001;

/// Похоже ли это на пакет QUIC Initial.
///
/// Отдельная функция с собственным смыслом: по ней движок понимает, что
/// датаграмма — начало QUIC-соединения, даже когда имя достать не удалось.
pub fn is_initial(data: &[u8]) -> bool {
    let Some(&first) = data.first() else {
        return false;
    };

    // Длинный заголовок: старший бит — форма, следующий — фиксированный и
    // всегда единица (RFC 9000, §17.2).
    if first & LONG_HEADER_MASK != LONG_HEADER_MASK {
        return false;
    }
    if (first >> 4) & 0x03 != PACKET_TYPE_INITIAL {
        return false;
    }

    let Some(version) = data.get(1..5) else {
        return false;
    };
    let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);
    version == QUIC_V1
}

/// Достаёт имя сервера из пакета QUIC Initial.
///
/// Сейчас всегда `None`: расшифровка Initial не реализована — см. заголовок
/// модуля. Функция существует, чтобы вызывающий код не знал об этом ничего и
/// не пришлось бы его менять, когда расшифровка появится.
pub fn extract_sni(data: &[u8]) -> Option<&str> {
    if !is_initial(data) {
        return None;
    }

    tracing::trace!(
        "QUIC Initial опознан, но имя из него не читается; \
         для правил по доменам полагаемся на fake-IP"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Заголовок пакета Initial: форма, версия, длины идентификаторов.
    fn initial_header() -> Vec<u8> {
        let mut packet = vec![0xC0];
        packet.extend_from_slice(&QUIC_V1.to_be_bytes());
        packet.push(8); // длина идентификатора назначения
        packet.extend_from_slice(&[0xAB; 8]);
        packet.push(0); // длина идентификатора источника
        packet
    }

    #[test]
    fn recognises_an_initial_packet() {
        assert!(is_initial(&initial_header()));
    }

    #[test]
    fn rejects_short_header_packets() {
        // Пакеты установившегося соединения идут с коротким заголовком —
        // рукопожатия в них нет.
        assert!(!is_initial(&[0x40, 1, 2, 3, 4, 5]));
    }

    #[test]
    fn rejects_other_versions() {
        let mut packet = initial_header();
        packet[1..5].copy_from_slice(&0xFACE_FEED_u32.to_be_bytes());
        assert!(!is_initial(&packet));
    }

    #[test]
    fn rejects_truncated_input() {
        let packet = initial_header();
        for cut in 0..5 {
            assert!(!is_initial(&packet[..cut]));
        }
    }

    #[test]
    fn extraction_is_honest_about_not_working() {
        // Возвращать выдуманное имя было бы хуже, чем не возвращать ничего:
        // правило сработало бы не на том соединении.
        assert_eq!(extract_sni(&initial_header()), None);
        assert_eq!(extract_sni(&[0u8; 32]), None);
    }
}

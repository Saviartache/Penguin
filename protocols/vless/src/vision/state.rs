//! Досмотр внутреннего TLS и решение о переключении в прямой режим.
//!
//! Повторяет `TrafficState` и `XtlsFilterTls` (`XTLS/Xray-core`,
//! `proxy/proxy.go`): досматривает байты, которые VLESS всё равно несёт
//! насквозь, ищет в них признаки TLS 1.3 самого приложения (не Reality —
//! Reality уже открыта, это TLS **внутри** неё), и включает
//! [`VisionState::enable_xtls`] только тогда, когда сервер этого внутреннего
//! TLS согласовал версию 1.3 и не самый слабый из перечисленных шифров.
//!
//! **Здесь ошибка не видна сразу**: до срабатывания условия канал работает
//! как обычный Reality/VLESS, и только с этого места начинается снятие
//! второго слоя шифрования — оттого на записанных байтах у этого файла и
//! `padding.rs` отдельные тесты (`stream.rs`), а не только круговой прогон.

/// Сколько первых пакетов в каждом направлении вообще стоит осматривать —
/// `NewTrafficState` (`proxy.go`): `NumberOfPacketToFilter: 8`.
pub const INITIAL_PACKETS_TO_FILTER: u32 = 8;

/// Начало записи `ClientHello` — тип записи `handshake` (`0x16`), версия
/// записи `0x03, 0x03` не проверяется здесь настолько строго, но эталон
/// сверяет только первые два байта (`TlsClientHandShakeStart`).
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
/// Начало записи `ServerHello` (`TlsServerHandShakeStart`).
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
/// Начало записи `application_data` TLS 1.3 (`TlsApplicationDataStart`).
pub const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

/// Тип сообщения `ClientHello` (`TlsHandshakeTypeClientHello`).
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Тип сообщения `ServerHello` (`TlsHandshakeTypeServerHello`).
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// `supported_versions` со значением TLS 1.3 внутри расширений `ServerHello`
/// (`Tls13SupportedVersions`).
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// Шифры TLS 1.3, которые `ServerHello` вообще может назвать
/// (`Tls13CipherSuiteDic`, ключи словаря).
const KNOWN_TLS13_CIPHERS: [u16; 5] = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305];
/// `TLS_AES_128_CCM_8_SHA256` — единственный из них, при котором эталон
/// сознательно не включает прямой режим (короткий тег MAC, аргумент из
/// `proxy.go`: `else if v != "TLS_AES_128_CCM_8_SHA256" { EnableXtls = true }`).
const CIPHER_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// Состояние одного направления Vision-канала — то, что в эталоне разложено
/// по `TrafficState` и `OutboundState` (полей `InboundState` здесь нет: они
/// нужны только серверу, принимающему реального клиента, а этот клиент сам
/// всегда только исходящая сторона).
#[derive(Debug)]
pub struct VisionState {
    /// Сколько ещё пакетов досматривать в обе стороны вместе — общий
    /// бюджет, как в эталоне.
    pub packets_to_filter: u32,
    /// Хоть что-то похожее на `ClientHello`/`ServerHello` уже видели.
    pub is_tls: bool,
    /// `ServerHello` уже видели, и версия записи была TLS 1.2 или новее.
    pub is_tls12_or_above: bool,
    /// TLS 1.3 внутри согласован, и шифр не самый слабый из перечисленных —
    /// единственное условие, разрешающее направлению отправить `Direct`.
    pub enable_xtls: bool,
    cipher: u16,
    /// Сколько байт `ServerHello` ещё осталось досмотреть в поисках
    /// `supported_versions`; отрицательного значения быть не может у самого
    /// счётчика (`i64`, а не `i32`, только чтобы вычитание не переполнялось
    /// без явной проверки на каждом шаге — как `int32` в Go).
    remaining_server_hello: i64,
}

impl Default for VisionState {
    fn default() -> Self {
        Self {
            packets_to_filter: INITIAL_PACKETS_TO_FILTER,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }
}

impl VisionState {
    /// Досматривает один пакет содержимого (уже без конверта набивки) —
    /// `XtlsFilterTls`. Вызывается из обоих направлений на одном и том же
    /// состоянии: `ClientHello` обычно виден на встречном (для сервера —
    /// входящем) направлении, `ServerHello` — на исходящем от сервера, но
    /// эталон не различает их по направлению, и этот код тоже.
    pub fn filter(&mut self, data: &[u8]) {
        self.packets_to_filter = self.packets_to_filter.saturating_sub(1);

        if data.len() >= 6 {
            if data.starts_with(&TLS_SERVER_HANDSHAKE_START)
                && data[5] == HANDSHAKE_TYPE_SERVER_HELLO
            {
                let declared = (u32::from(data[3]) << 8) | u32::from(data[4]);
                self.remaining_server_hello = i64::from(declared) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if data.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = usize::from(data[43]);
                    let cipher_start = 43 + session_id_len + 1;
                    if let Some(cipher_bytes) = data.get(cipher_start..cipher_start + 2) {
                        self.cipher = u16::from_be_bytes([cipher_bytes[0], cipher_bytes[1]]);
                    }
                }
            } else if data.starts_with(&TLS_CLIENT_HANDSHAKE_START)
                && data[5] == HANDSHAKE_TYPE_CLIENT_HELLO
            {
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let end = usize::try_from(self.remaining_server_hello)
                .unwrap_or(data.len())
                .min(data.len());
            self.remaining_server_hello -= data.len() as i64;
            let window = &data[..end];
            if contains(window, &TLS13_SUPPORTED_VERSIONS) {
                if KNOWN_TLS13_CIPHERS.contains(&self.cipher)
                    && self.cipher != CIPHER_AES_128_CCM_8_SHA256
                {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

/// `bytes.Contains` — здесь нет своей семантики сверх `slice::windows`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// `IsCompleteRecord` (`proxy.go`): весь срез — одна или несколько целых
/// записей `application_data` (`0x17 0x03 0x03 <длина>`), без остатка.
/// Только при этом условии эталон вообще рассматривает переключение в
/// прямой режим на этом вызове — иначе разрезал бы запись внутреннего TLS
/// пополам, и вторая сторона получила бы половину записи как есть, без
/// внешнего шифрования, которое её раньше склеивало с остальным потоком.
pub fn is_complete_tls_records(data: &[u8]) -> bool {
    let mut offset = 0;
    while offset < data.len() {
        let Some(header) = data.get(offset..offset + 5) else {
            return false;
        };
        if !header.starts_with(&TLS_APPLICATION_DATA_START) {
            return false;
        }
        let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        offset += 5;
        if data.len() < offset + record_len {
            return false;
        }
        offset += record_len;
    }
    true
}

/// `ServerHello`, версия записи и тип верны, `supported_versions` внутри
/// того же пакета называет TLS 1.3, шифр — параметр. Общая для тестов этого
/// файла и `vision::stream`: там нужен тот же байтовый образец, чтобы
/// довести до переключения в прямой режим не только досмотр, но и запись
/// целиком.
#[cfg(test)]
pub(crate) fn server_hello_tls13(cipher: [u8; 2]) -> Vec<u8> {
    let mut packet = vec![0u8; 90];
    packet[0..3].copy_from_slice(&TLS_SERVER_HANDSHAKE_START);
    let record_len = (packet.len() - 5) as u16;
    packet[3..5].copy_from_slice(&record_len.to_be_bytes());
    packet[5] = HANDSHAKE_TYPE_SERVER_HELLO;
    packet[43] = 0; // session_id пуст
    packet[44] = cipher[0];
    packet[45] = cipher[1];
    packet[60..66].copy_from_slice(&TLS13_SUPPORTED_VERSIONS);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_packets_are_ignored_without_panicking() {
        let mut state = VisionState::default();
        for len in 0..6 {
            state.filter(&vec![0xAA; len]);
        }
        assert!(!state.is_tls);
    }

    #[test]
    fn a_client_hello_start_marks_the_stream_as_tls() {
        let mut state = VisionState::default();
        let mut packet = vec![0x16, 0x03, 0x01, 0x00, 0x00, 0x01];
        packet.resize(16, 0);
        state.filter(&packet);
        assert!(state.is_tls);
        assert!(!state.is_tls12_or_above);
        assert!(!state.enable_xtls);
    }

    #[test]
    fn tls13_with_an_accepted_cipher_enables_xtls() {
        let mut state = VisionState::default();
        state.filter(&server_hello_tls13([0x13, 0x01])); // TLS_AES_128_GCM_SHA256
        assert!(state.is_tls12_or_above);
        assert!(state.enable_xtls);
        assert_eq!(state.packets_to_filter, 0);
    }

    #[test]
    fn tls13_with_the_short_tag_cipher_does_not_enable_xtls() {
        // Условие переключения — самое хрупкое место всего механизма: этот
        // шифр (`TLS_AES_128_CCM_8_SHA256`) эталон сознательно исключает
        // (`proxy.go`, `else if v != "TLS_AES_128_CCM_8_SHA256"`), а ошибка
        // здесь не оборвала бы соединение сразу — тоннель просто остался бы
        // без снятия второго слоя, что не видно на глаз.
        let mut state = VisionState::default();
        state.filter(&server_hello_tls13([0x13, 0x05]));
        assert!(state.is_tls12_or_above);
        assert!(!state.enable_xtls);
    }

    #[test]
    fn an_unknown_cipher_does_not_enable_xtls() {
        let mut state = VisionState::default();
        state.filter(&server_hello_tls13([0xC0, 0x2F])); // TLS 1.2-стиля номер, не из словаря
        assert!(!state.enable_xtls);
    }

    #[test]
    fn a_tls12_server_hello_never_enables_xtls() {
        // `supported_versions` не найден за весь `ServerHello` — TLS 1.2 или
        // старше, прямой режим невозможен в принципе.
        let mut state = VisionState::default();
        let mut packet = vec![0u8; 90];
        packet[0..3].copy_from_slice(&TLS_SERVER_HANDSHAKE_START);
        let record_len = (packet.len() - 5) as u16;
        packet[3..5].copy_from_slice(&record_len.to_be_bytes());
        packet[5] = HANDSHAKE_TYPE_SERVER_HELLO;
        packet[44] = 0x13;
        packet[45] = 0x01;
        state.filter(&packet);
        assert!(state.is_tls12_or_above);
        assert!(!state.enable_xtls);
        assert_eq!(state.packets_to_filter, 0);
    }

    #[test]
    fn the_budget_runs_out_after_eight_packets() {
        let mut state = VisionState::default();
        for _ in 0..8 {
            state.filter(b"not tls at all, just data");
        }
        assert_eq!(state.packets_to_filter, 0);
    }

    #[test]
    fn empty_input_is_a_complete_set_of_zero_records() {
        assert!(is_complete_tls_records(&[]));
    }

    #[test]
    fn one_complete_record_is_recognized() {
        let mut data = vec![0x17, 0x03, 0x03, 0x00, 0x03];
        data.extend_from_slice(b"abc");
        assert!(is_complete_tls_records(&data));
    }

    #[test]
    fn two_complete_records_back_to_back_are_recognized() {
        let mut data = vec![0x17, 0x03, 0x03, 0x00, 0x01, b'a'];
        data.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02, b'b', b'c']);
        assert!(is_complete_tls_records(&data));
    }

    #[test]
    fn a_trailing_partial_record_is_not_complete() {
        let mut data = vec![0x17, 0x03, 0x03, 0x00, 0x03];
        data.extend_from_slice(b"ab"); // на байт короче объявленного
        assert!(!is_complete_tls_records(&data));
    }

    #[test]
    fn content_that_is_not_a_tls_record_at_all_is_not_complete() {
        assert!(!is_complete_tls_records(b"GET / HTTP/1.1\r\n"));
    }
}

//! Расширения с постоянным, никогда не меняющимся телом. Ни у одного нет
//! параметра, который отличался бы между тремя нашими отпечатками, —
//! поэтому у каждой функции здесь нет аргументов вовсе.

/// `status_request` (5) — заявка на OCSP-прикрепление, RFC 4366 §3.6.
///
/// Тело всегда одно и то же: тип запроса `OCSP` (1) и два нулевых поля
/// длины, которые по спецификации можно было бы заполнить, но клиенты этого
/// не делают.
pub fn status_request() -> Vec<u8> {
    vec![0, 5, 0, 5, 1, 0, 0, 0, 0]
}

/// `renegotiation_info` (`0xff01`) — RFC 5746.
///
/// Тело — однобайтная длина «информации о предыдущем согласовании». Для
/// самого первого согласования эта информация пуста, и длина — ноль: тело
/// всегда четыре байта заголовка плюс один байт нулевой длины, итого пять.
pub fn renegotiation_info() -> Vec<u8> {
    vec![0xff, 0x01, 0, 1, 0]
}

/// `record_size_limit` (28), RFC 8449 — но не по-настоящему: uTLS шлёт его
/// как заявку с фиксированным значением и никак не реагирует на согласование
/// в ответ. Часть отпечатка Firefox; сам смысл поля этому крейту не важен —
/// он ничего не режет на записи, это дело будущего разбора XTLS Vision.
pub fn record_size_limit(limit: u16) -> Vec<u8> {
    let mut out = vec![0, 28, 0, 2];
    out.extend_from_slice(&limit.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_request_is_nine_fixed_bytes() {
        assert_eq!(status_request(), vec![0, 5, 0, 5, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn renegotiation_info_carries_a_zero_length_history() {
        assert_eq!(renegotiation_info(), vec![0xff, 0x01, 0, 1, 0]);
    }

    #[test]
    fn record_size_limit_carries_the_given_value() {
        assert_eq!(record_size_limit(0x4001), vec![0, 28, 0, 2, 0x40, 0x01]);
    }
}

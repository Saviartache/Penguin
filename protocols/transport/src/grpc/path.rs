//! Путь запроса gRPC из `serviceName` — как у Xray
//! (`transport/internet/grpc/config.go`: `getServiceName`, `getTunStreamName`).
//!
//! - Обычное имя: `/<имя>/Tun`, имя экранируется как сегмент пути.
//! - Имя, начинающееся с `/`: свой путь. Всё до последнего `/` — служба
//!   (каждый сегмент экранируется отдельно), после него — имя потока до `|`.

/// Путь `POST` для потока `Tun`.
pub fn tun_path(service_name: &str) -> String {
    if !service_name.starts_with('/') {
        return format!("/{}/Tun", escape_segment(service_name));
    }
    let last = service_name.rfind('/').unwrap_or(0);
    let service: Vec<String> = service_name[1..last.max(1)]
        .split('/')
        .map(escape_segment)
        .collect();
    let ending = &service_name[last + 1..];
    let stream = ending.split('|').next().unwrap_or_default();
    format!("/{}/{}", service.join("/"), escape_segment(stream))
}

/// `url.PathEscape` из Go: всё, кроме букв, цифр, `-_.~` и
/// `$&+:=@`, — в `%XX` заглавными.
fn escape_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+:=@".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_name_gets_the_tun_stream() {
        assert_eq!(tun_path("grpc-name"), "/grpc-name/Tun");
        assert_eq!(tun_path(""), "//Tun");
    }

    #[test]
    fn a_plain_name_is_escaped_as_one_segment() {
        assert_eq!(tun_path("a b/c"), "/a%20b%2Fc/Tun");
        assert_eq!(tun_path("x;y,z?"), "/x%3By%2Cz%3F/Tun");
        assert_eq!(tun_path("$&+:=@"), "/$&+:=@/Tun");
    }

    #[test]
    fn a_custom_path_names_the_service_and_the_stream() {
        assert_eq!(tun_path("/my/service/Stream"), "/my/service/Stream");
        assert_eq!(tun_path("/svc/Tun|TunMulti"), "/svc/Tun");
        assert_eq!(tun_path("/a b/Tun"), "/a%20b/Tun");
        // Один `/` в начале: служба пустая, как у Xray.
        assert_eq!(tun_path("/Tun"), "//Tun");
    }
}

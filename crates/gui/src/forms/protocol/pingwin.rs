//! Pingwin — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Чьим приветствием TLS притворяться.
///
/// `chrome` первым: это самый обычный клиент в любой сети, и приветствие,
/// похожее на него, не выделяется ничем.
const FINGERPRINTS: &[&str] = &["chrome", "firefox", "safari"];

/// Шифр записей.
///
/// `aes-256-gcm` первым: на всех современных процессорах он аппаратный.
/// `chacha20-poly1305` быстрее там, где ускорителя AES нет, — на старых
/// телефонах и мелких маршрутизаторах.
const CIPHERS: &[&str] = &["aes-256-gcm", "chacha20-poly1305"];

/// Способ обхода DPI в первой посылке.
///
/// `none` первым, и он не значит «никогда»: не пройдя без обхода, направление
/// пробует ещё раз с ложной посылкой само и запоминает, что помогло. Выбор
/// здесь — это «делать так всегда», а не «разрешить»; нужен он тому, кто свою
/// сеть уже знает и не хочет платить лишней попыткой на первом подключении.
///
/// Порядок остальных — от безобиднейшего к самому действенному: разрез, потом
/// разрез с перестановкой, потом ложная посылка, потом всё сразу. Что каждое
/// из них делает — в документе `penguin_transport::desync`.
const DESYNC: &[&str] = &["none", "multisplit", "disorder", "fake", "fakedsplit"];

/// Поля формы в том порядке, в каком они показываются.
///
/// Точек разреза (`desync.split_pos`), TTL ложной посылки и паузы между
/// кусками в форме нет намеренно: у поля выбора нет пустого значения, а
/// список строк форма показать не умеет вовсе (`FieldKind`, см. `spec.rs`).
/// Умолчания при этом рабочие — разрез считается от середины имени прикрытия,
/// — а тонкая настройка под конкретную сеть подбирается не в окне, а
/// перебором, и живёт в файле настроек.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // Имя поля в форме и его место в настройках нарочно разные: в профиле
    // ключ лежит коротко (`key`), а в форме зовётся так же, как у WireGuard,
    // — и тем самым берёт готовый образец из тестов редактора.
    FieldSpec::text("server_public_key", &["key"], |s| s.server_public_key)
        .example(|s| s.pingwin_key_example)
        .required(|s| s.need_server_public_key),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::text("sni", &["sni"], |s| s.cover_name).example(|s| s.cover_name_example),
    FieldSpec::choice(
        "fingerprint",
        &["fingerprint"],
        |s| s.browser_fingerprint,
        FINGERPRINTS,
    ),
    FieldSpec::choice("cipher", &["cipher"], |s| s.method, CIPHERS),
    FieldSpec::flag("zero_rtt", &["zero_rtt"], |s| s.zero_rtt).on(),
    FieldSpec::choice(
        "desync",
        &["desync", "strategy"],
        |s| s.desync_strategy,
        DESYNC,
    ),
];

/// Как ссылка-приглашение ложится в поля.
///
/// ```text
/// pingwin://<пароль>@<хост>:<порт>?key=<ключ>&sni=<прикрытие>#<имя>
/// ```
///
/// Собирает её сервер (`pingwin-server link`), и формат описан на его
/// стороне — `penguin_pingwin::link`. Разбор здесь свой, а не общий с ним, и
/// иначе быть не может: окно не вправе зависеть от крейта протокола
/// (`AGENTS.md` §1). Связывает две стороны образец — одна и та же строка
/// стоит в тесте здесь и в тесте там.
///
/// Всё, чего в ссылке нет, остаётся умолчанием формы: отпечаток браузера,
/// шифр, 0-RTT. Обход DPI из ссылки не берётся тем более — его подбирают под
/// сеть, в которой сидит клиент, а не под сервер, который выдал ссылку.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let password = link.userinfo();
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }
    let key = link
        .query
        .get("key")
        .ok_or_else(|| crate::i18n::s().need_server_public_key.to_owned())?;

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("server_public_key", key),
        ("password", password),
    ];
    if let Some(sni) = link.query.get("sni") {
        values.push(("sni", sni));
    }
    Ok(values)
}

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "pingwin",
    label: "Pingwin",
    fields: FIELDS,
    schemes: &["pingwin://"],
    from_link: Some(from_link),
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;

    /// Образец, по которому сверяются обе стороны.
    ///
    /// Ровно эта строка стоит в тесте `penguin_pingwin::link`, который её и
    /// собирает. Правка формата ломает оба теста сразу — в этом и смысл.
    const SAMPLE: &str = "pingwin://s3cret@example.com:443\
?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\
&sni=www.microsoft.com#%D0%94%D0%BE%D0%BC%D0%B0";

    #[test]
    fn the_sample_link_from_the_server_fills_the_form() {
        // Ссылку выдаёт `pingwin-server link`, и человек вставляет её как
        // есть. Разойтись сборке и разбору нельзя: профиль сохранится и не
        // подключится, а виновата будет «служба».
        let draft = link::parse(SAMPLE).expect("ссылка разбирается");
        assert_eq!(draft.spec().map(|spec| spec.id), Some("pingwin"));
        assert_eq!(draft.text("server"), "example.com:443");
        assert_eq!(draft.text("password"), "s3cret");
        assert_eq!(draft.text("sni"), "www.microsoft.com");
        assert_eq!(
            draft.text("server_public_key"),
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        );
        assert_eq!(draft.name, "Дома");
    }

    #[test]
    fn a_link_without_the_server_key_is_refused() {
        // Ключ — единственное, без чего профиль заведомо не подключится, и
        // сказать об этом надо при вставке, а не через минуту молчания.
        let raw = "pingwin://s3cret@example.com:443#Дома";
        assert!(link::parse(raw).is_err());
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let raw = "pingwin://example.com:443?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
        assert!(link::parse(raw).is_err());
    }

    #[test]
    fn a_link_without_a_port_gets_the_usual_one() {
        // 443 — то, на чём сервер стоит почти всегда: TLS там никого не
        // удивляет, а ссылка без порта короче на четыре символа.
        let raw = "pingwin://s3cret@example.com\
?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
        let draft = link::parse(raw).expect("ссылка разбирается");
        assert_eq!(draft.text("server"), "example.com:443");
    }

    #[test]
    fn what_the_link_does_not_say_stays_at_the_default() {
        // Отпечаток, шифр и 0-RTT в ссылку не входят: у них рабочие
        // умолчания, и молча менять их ссылкой значило бы менять поведение
        // профиля тем, чего в нём не видно.
        let draft = link::parse(SAMPLE).expect("ссылка разбирается");
        assert_eq!(draft.text("fingerprint"), "chrome");
        assert_eq!(draft.text("cipher"), "aes-256-gcm");
        assert_eq!(draft.text("desync"), "none");
    }

    #[test]
    fn the_server_key_is_required_because_everything_stands_on_it() {
        // Без него нет ни опознания сервера, ни устойчивости к активной
        // проверке: пустой ключ — это профиль, который не подключится.
        let key = FIELDS
            .iter()
            .find(|field| field.key == "server_public_key")
            .expect("поле есть");
        assert!(key.required.is_some());
        assert_eq!(key.path, &["key"], "ключ ложится в настройки не туда");
    }

    #[test]
    fn the_password_is_hidden_and_required() {
        let password = FIELDS
            .iter()
            .find(|field| field.key == "password")
            .expect("поле есть");
        assert!(password.is_secret());
        assert!(password.required.is_some());
    }

    #[test]
    fn zero_rtt_is_on_in_a_new_profile() {
        // Умолчание формы обязано совпасть с умолчанием протокола
        // (`PingwinConfig::default`), иначе снятый флажок в новом профиле
        // означал бы не то, что записано в файле.
        let flag = FIELDS
            .iter()
            .find(|field| field.key == "zero_rtt")
            .expect("поле есть");
        assert!(flag.is_flag());
        assert!(flag.default_on);
    }

    #[test]
    fn a_new_profile_does_not_bypass_dpi_by_itself() {
        // Обход включают намеренно: сам по себе он лишние пакеты.
        let desync = FIELDS
            .iter()
            .find(|field| field.key == "desync")
            .expect("поле есть");
        assert_eq!(desync.default_text(), "none");
    }

    #[test]
    fn the_choices_match_the_ones_the_protocol_knows() {
        // Опечатка здесь означала бы не «сервер отказал», а «сервер молчит».
        assert_eq!(FINGERPRINTS, ["chrome", "firefox", "safari"]);
        assert_eq!(CIPHERS, ["aes-256-gcm", "chacha20-poly1305"]);
        assert_eq!(
            DESYNC,
            ["none", "multisplit", "disorder", "fake", "fakedsplit"]
        );
    }
}

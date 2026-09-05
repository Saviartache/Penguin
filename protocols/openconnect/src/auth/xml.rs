//! Тела `config-auth`: что клиент шлёт и что разбирает в ответе.
//!
//! Формат сверен с `openconnect/auth.c` (сборка запроса,
//! `xmlpost_new_query`/`xmlpost_append_form_opts`) и с `ocserv/src/worker-auth.c`
//! (форма, которую присылает сервер, — литеральные строки в коде,
//! `get_auth_handler2`).
//!
//! ```text
//! запрос, первый шаг (type="init"):
//!   <config-auth client="vpn" type="init">
//!     <version who="vpn">...</version>
//!     <group-access>https://host[:port]/</group-access>
//!   </config-auth>
//!
//! ответ сервера — форма или успех:
//!   <config-auth client="vpn" type="auth-request">
//!     <auth id="main">
//!       <form method="post" action="/auth">
//!         <input type="text" name="username" label="Username:" />
//!         <input type="password" name="password" label="Password:" />
//!       </form>
//!     </auth>
//!   </config-auth>
//!
//!   <config-auth ...><auth id="success">...</auth></config-auth>
//!
//! запрос, ответ на форму (type="auth-reply"):
//!   <config-auth client="vpn" type="auth-reply">
//!     <version who="vpn">...</version>
//!     <auth>
//!       <username>ivan</username>
//!       <password>секрет</password>
//!     </auth>
//!   </config-auth>
//! ```
//!
//! `id="success"` — единственный сигнал успеха в теле XML
//! (`auth.c: handle_auth_form`, `OC_FORM_RESULT_LOGGEDIN`). Отказ по паролю
//! сюда не попадает вовсе: `ocserv` отвечает на него `401` с пустым телом
//! (`worker-auth.c`), и это разбирает [`super::http`], а не этот модуль.

use quick_xml::escape::{escape, unescape};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use crate::error::{OpenConnectError, OpenConnectResult};

/// Что клиент называет серверу в поле `<version who="vpn">`.
///
/// Не влияет на разбор: `ocserv` эту строку только пишет в свой журнал.
/// Ставится не пустой, потому что пустое поле в форме, которую человек видит
/// в журнале сервера, выглядит поломкой, а не решением.
const VERSION: &str = "Penguin OpenConnect client";

/// Тип поля формы входа. `Other` — то, что сервер прислал, а протокол не
/// знает: не молчим о нём, а называем как есть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    /// Обычный текст: `<input type="text">`, `type` не задан — тоже текст.
    Text,
    /// Пароль или код: символы не должны отображаться при вводе.
    Password,
    /// Поле, которое сервер заполнил сам и ждёт назад без изменений.
    Hidden,
    /// Список вариантов: `<select>` и его `<option>` — значение и подпись.
    Select(Vec<(String, String)>),
    /// Тип поля, которого нет в списке выше.
    Other(String),
}

/// Одно поле формы входа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Имя поля — под ним же оно уходит назад в `<auth>`.
    pub name: String,
    /// Тип поля.
    pub kind: FieldKind,
    /// Подпись, которую сервер печатает рядом с полем. Идёт в текст ошибки,
    /// если поле нечем заполнить: человек должен узнать в нём то, что видел
    /// бы в веб-форме.
    pub label: String,
    /// Значение по умолчанию (`value="..."` у `<input>`).
    ///
    /// Для скрытых полей это единственное, чем их можно заполнить: у Penguin
    /// нет своего значения для поля, которого он не знает, и правильный ответ
    /// — вернуть то же, что прислал сервер, не трогая.
    pub value: Option<String>,
}

/// Разобранный ответ сервера на `config-auth`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    /// `id` корневого `<auth>`. `"success"` — вход выполнен.
    pub id: String,
    /// Путь, на который слать следующий `auth-reply` (`<form action="...">`).
    /// Не задан — используется путь предыдущего запроса.
    pub action: Option<String>,
    /// Поля формы, если сервер прислал форму, а не успех.
    pub fields: Vec<Field>,
    /// Текст `<error>`, если он был.
    pub error: Option<String>,
    /// Текст `<banner>`/`<message>`, если он был — только для журнала.
    pub banner: Option<String>,
}

impl Response {
    /// Вход выполнен: дальше можно забирать cookie и открывать `CONNECT`.
    pub fn is_success(&self) -> bool {
        self.id == "success"
    }
}

/// Тело первого запроса: назвать себя и адрес, на который просимся.
///
/// `group_access_url` — тот же адрес, на который уходит сам запрос
/// (`auth.c`: `<group-access>` повторяет URL запроса). Группа выбором
/// (`<group-select>`) сюда не входит: на первом шаге сервер её ещё не
/// предлагал.
pub fn init_request(group_access_url: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <config-auth client=\"vpn\" type=\"init\">\n\
         <version who=\"vpn\">{}</version>\n\
         <group-access>{}</group-access>\n\
         </config-auth>",
        escape(VERSION),
        escape(group_access_url)
    )
}

/// Тело ответа на форму: значения полей под их собственными именами.
///
/// Порядок пар — порядок полей в форме: значения не влияют на порядок разбора
/// на стороне сервера, но сохранённый порядок легче читается в отладочном
/// журнале, если он туда когда-нибудь попадёт.
pub fn auth_reply(answers: &[(String, String)]) -> OpenConnectResult<String> {
    let mut auth_body = String::new();
    for (name, value) in answers {
        if !is_valid_tag_name(name) {
            return Err(OpenConnectError::malformed(format!(
                "поле формы `{name}` не годится в имя тега XML"
            )));
        }
        auth_body.push_str(&format!("<{name}>{}</{name}>", escape(value.as_str())));
    }

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <config-auth client=\"vpn\" type=\"auth-reply\">\n\
         <version who=\"vpn\">{}</version>\n\
         <auth>{auth_body}</auth>\n\
         </config-auth>",
        escape(VERSION)
    ))
}

/// Имя поля годится как имя тега XML: буквы, цифры, `_` и `-`, не с цифры.
///
/// Сервер называет поля сам; проверка — не защита от чужого XML (мы и так
/// экранируем значения), а гарантия, что из имени вообще получится тег, а не
/// оборванная строка вида `<secondary password>`.
fn is_valid_tag_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Разбирает ответ сервера.
pub fn parse_response(body: &[u8]) -> OpenConnectResult<Response> {
    let text = std::str::from_utf8(body)
        .map_err(|_| OpenConnectError::malformed("ответ сервера не UTF-8"))?;

    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut response = Response::default();
    let mut found_id = false;

    // Что сейчас копится: текст, который надо положить в поле `Response`, или
    // список вариантов открытого `<select>`.
    let mut pending_text: Option<PendingText> = None;
    let mut open_select: Option<(String, Vec<(String, String)>)> = None;
    let mut pending_option_value: Option<String> = None;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| OpenConnectError::malformed(format!("XML не разбирается: {e}")))?;

        match event {
            Event::Eof => break,
            Event::Start(tag) | Event::Empty(tag) => {
                let name = tag.name().as_ref().to_owned();
                match name.as_str() {
                    "auth" => {
                        if let Some(id) = attribute(&tag, "id")? {
                            response.id = id;
                            found_id = true;
                        }
                    }
                    "form" => {
                        response.action = attribute(&tag, "action")?;
                    }
                    "input" => {
                        let Some(field_name) = attribute(&tag, "name")? else {
                            continue;
                        };
                        let kind = match attribute(&tag, "type")?.as_deref() {
                            Some("password") => FieldKind::Password,
                            Some("hidden") => FieldKind::Hidden,
                            None | Some("text") => FieldKind::Text,
                            Some(other) => FieldKind::Other(other.to_owned()),
                        };
                        let label = attribute(&tag, "label")?.unwrap_or_default();
                        let value = attribute(&tag, "value")?;
                        response.fields.push(Field {
                            name: field_name,
                            kind,
                            label,
                            value,
                        });
                    }
                    "select" => {
                        let select_name = attribute(&tag, "name")?.unwrap_or_default();
                        open_select = Some((select_name, Vec::new()));
                    }
                    "option" => {
                        pending_option_value = attribute(&tag, "value")?;
                    }
                    "error" => pending_text = Some(PendingText::Error),
                    "banner" | "message" => pending_text = Some(PendingText::Banner),
                    _ => {}
                }
            }
            Event::Text(text) => {
                let content = unescape(text.as_ref())
                    .map_err(|e| OpenConnectError::malformed(format!("текст в XML: {e}")))?;
                let content = content.trim();
                if content.is_empty() {
                    continue;
                }
                if let Some(value) = pending_option_value.take() {
                    if let Some((_, options)) = open_select.as_mut() {
                        options.push((value, content.to_owned()));
                    }
                } else if let Some(target) = pending_text.take() {
                    let field = match target {
                        PendingText::Error => &mut response.error,
                        PendingText::Banner => &mut response.banner,
                    };
                    *field = Some(content.to_owned());
                }
            }
            Event::End(tag) => {
                let name = tag.name();
                if name.as_ref() == "select"
                    && let Some((name, options)) = open_select.take()
                {
                    response.fields.push(Field {
                        name,
                        kind: FieldKind::Select(options),
                        label: String::new(),
                        value: None,
                    });
                }
            }
            _ => {}
        }
    }

    if !found_id {
        return Err(OpenConnectError::malformed(
            "в ответе нет `<auth id=\"...\">`: это не форма OpenConnect",
        ));
    }
    Ok(response)
}

/// Что копится в текстовом узле между открывающим и закрывающим тегом.
enum PendingText {
    Error,
    Banner,
}

/// Значение атрибута, если он есть, с раскрытыми `&amp;`-подобными сущностями.
fn attribute(
    tag: &quick_xml::events::BytesStart<'_>,
    name: &str,
) -> OpenConnectResult<Option<String>> {
    for attr in tag.attributes() {
        let attr = attr.map_err(|e| OpenConnectError::malformed(format!("атрибут в XML: {e}")))?;
        if attr.key.as_ref() != name {
            continue;
        }
        let decoded = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|e| OpenConnectError::malformed(format!("атрибут в XML: {e}")))?;
        return Ok(Some(decoded.into_owned()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_init_request_names_the_client_and_the_url() {
        let body = init_request("https://vpn.example.com/");
        assert!(body.contains("type=\"init\""));
        assert!(body.contains("<group-access>https://vpn.example.com/</group-access>"));
    }

    #[test]
    fn credentials_are_escaped_before_they_become_xml() {
        // Пароль с `<` и `&` не должен сломать тело запроса или, того хуже,
        // добавить в него посторонний тег.
        let body = auth_reply(&[
            ("username".to_owned(), "ivan".to_owned()),
            ("password".to_owned(), "a&b<c>".to_owned()),
        ])
        .expect("собирается");
        assert!(body.contains("<username>ivan</username>"));
        assert!(body.contains("<password>a&amp;b&lt;c&gt;</password>"));
    }

    #[test]
    fn a_field_name_that_cannot_be_a_tag_is_refused() {
        let err =
            auth_reply(&[("secondary password".to_owned(), "x".to_owned())]).expect_err("не тег");
        assert!(err.to_string().contains("secondary password"), "{err}");
    }

    #[test]
    fn a_login_form_is_parsed_field_by_field() {
        // Форма `ocserv` для обычного входа (`worker-auth.c`, `id="main"`).
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
            <config-auth client="sg" type="auth-request">
            <auth id="main">
            <form method="post" action="/auth">
            <input type="text" name="username" label="Username:" />
            <input type="password" name="password" label="Password:" />
            </form>
            </auth>
            </config-auth>"#;

        let response = parse_response(xml).expect("разбирается");
        assert_eq!(response.id, "main");
        assert_eq!(response.action.as_deref(), Some("/auth"));
        assert_eq!(response.fields.len(), 2);
        assert_eq!(response.fields[0].name, "username");
        assert_eq!(response.fields[0].kind, FieldKind::Text);
        assert_eq!(response.fields[1].kind, FieldKind::Password);
        assert!(!response.is_success());
    }

    #[test]
    fn success_is_signalled_by_the_id_attribute_alone() {
        let xml = br#"<config-auth client="sg" type="auth-request">
            <auth id="success"><title>SSL VPN Service</title></auth>
            </config-auth>"#;
        let response = parse_response(xml).expect("разбирается");
        assert!(response.is_success());
    }

    #[test]
    fn a_group_selector_is_read_as_a_field_with_options() {
        let xml = br#"<config-auth><auth id="main"><form action="/auth">
            <select name="group_list" label="Group:">
            <option value="staff">Staff</option>
            <option value="guests">Guests</option>
            </select>
            </form></auth></config-auth>"#;
        let response = parse_response(xml).expect("разбирается");
        let FieldKind::Select(options) = &response.fields[0].kind else {
            panic!("ждали список вариантов");
        };
        assert_eq!(
            options,
            &vec![
                ("staff".to_owned(), "Staff".to_owned()),
                ("guests".to_owned(), "Guests".to_owned())
            ]
        );
    }

    #[test]
    fn a_response_without_an_auth_id_is_refused() {
        let err = parse_response(b"<config-auth><foo/></config-auth>").expect_err("не форма");
        assert!(err.to_string().contains("auth"), "{err}");
    }

    #[test]
    fn an_unrecognised_field_type_is_named_not_dropped() {
        let xml = r#"<config-auth><auth id="main"><form action="/auth">
            <input type="fingerprint" name="token" label="Отпечаток:" />
            </form></auth></config-auth>"#;
        let response = parse_response(xml.as_bytes()).expect("разбирается");
        assert_eq!(
            response.fields[0].kind,
            FieldKind::Other("fingerprint".to_owned())
        );
    }

    #[test]
    fn a_hidden_field_keeps_its_default_value() {
        // Единственное, чем скрытое поле можно заполнить, — то же значение,
        // что прислал сервер: своего значения у Penguin для него нет.
        let xml = br#"<config-auth><auth id="main"><form action="/auth">
            <input type="hidden" name="csrf" value="abc123" />
            </form></auth></config-auth>"#;
        let response = parse_response(xml).expect("разбирается");
        assert_eq!(response.fields[0].value.as_deref(), Some("abc123"));
    }

    #[test]
    fn the_error_text_survives_surrounding_whitespace() {
        let xml = "<config-auth><auth id=\"main\"><error>\n  неверный формат имени  \n</error></auth></config-auth>";
        let response = parse_response(xml.as_bytes()).expect("разбирается");
        assert_eq!(response.error.as_deref(), Some("неверный формат имени"));
    }
}

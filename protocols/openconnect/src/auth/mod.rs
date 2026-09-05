//! Вход: обмен HTTPS/XML, пока сервер не примет, не откажет или не спросит
//! то, чего у Penguin нет.
//!
//! ```text
//!  POST /  init        ──►  <auth id="main"><form>username, password</form>
//!  POST action=".."     ──►  <auth id="success">  или снова форма
//!  ...
//! ```
//!
//! `ocserv` иногда просит имя и пароль одной формой, а иногда — двумя
//! подряд: сначала имя, потом отдельным шагом пароль (`worker-auth.c`,
//! `id="main"` → `id="passwd"`). Обе формы разбирает один и тот же код: имя и
//! пароль расходуются каждый ровно один раз за вход, независимо от того, в
//! каком шаге их спросили. Форма, попросившая пароль **второй** раз (или что
//! угодно ещё, чего в настройках нет), — это не тот же вопрос, повторённый
//! сервером, а другой секрет: второй фактор. [`OpenConnectError::SecondFactorRequired`]
//! — честный ответ на этот случай, а не попытка угадать код.
//!
//! Отказ по паролю сюда не доходит формой вовсе: `ocserv` отвечает `401` с
//! пустым телом (`worker-auth.c`), и это ловится до разбора XML.

pub mod http;
pub mod xml;

use penguin_core::address::Address;
use penguin_proto::dialer::Dialer;
use penguin_transport::tls::TlsClient;

use crate::config::OpenConnectConfig;
use crate::error::{OpenConnectError, OpenConnectResult};
use xml::{Field, FieldKind};

/// User-Agent, под которым Penguin представляется `ocserv`.
///
/// Начало строки — не для вида: `ocserv` (`src/worker-http.c`) определяет тип
/// клиента через `strncasecmp` по началу этого заголовка и по нему решает,
/// присылать ли маршруты и DNS для IPv6, а также в каком виде — раздельно
/// (`X-CSTP-DNS-IP6`) или как для `openconnect` (`worker-vpn.c`). Совпадать
/// должно именно начало, `"OpenConnect VPN Agent"`; версия после него ни на
/// что не влияет.
pub const USER_AGENT: &str = "OpenConnect VPN Agent (Penguin)";

/// Имя куки, в которой `ocserv` отдаёт результат входа.
///
/// Не поле `<session-token>` в теле XML — его `ocserv` не присылает вовсе;
/// кука ставится заголовком `Set-Cookie` (`worker-auth.c: post_common_handler`).
pub(crate) const COOKIE_NAME: &str = "webvpn";

/// Сколько обменов формой допускается, прежде чем считать, что дальше
/// ничего не изменится.
///
/// Обычный вход укладывается в один-два обмена (имя и пароль сразу либо по
/// одному на форму). Число взято с запасом на форму с выбором группы перед
/// именем и паролем; больше — это либо петля на стороне сервера, либо форма,
/// которую этот клиент не понимает и не пытается угадать.
const MAX_ROUNDS: u32 = 6;

/// Результат успешного входа.
pub struct LoginResult {
    /// Кука `webvpn` для запроса `CONNECT`.
    pub cookie: String,
}

/// Проходит вход и возвращает куку сессии.
pub async fn login(
    dialer: &dyn Dialer,
    tls: &TlsClient,
    host: &Address,
    port: u16,
    host_header: &str,
    config: &OpenConnectConfig,
) -> OpenConnectResult<LoginResult> {
    let group_access_url = format!("https://{host_header}/");
    let mut path = "/".to_owned();
    let mut body = xml::init_request(&group_access_url);
    let mut username_used = false;
    let mut password_used = false;

    for _ in 0..MAX_ROUNDS {
        let (head, response_body) = http::post(
            dialer,
            tls,
            host,
            port,
            host_header,
            USER_AGENT,
            &path,
            None,
            &body,
        )
        .await?;

        // Отказ по паролю у `ocserv` — это код ответа с пустым телом, а не
        // содержимое XML: до его разбора дело не доходит вовсе.
        if head.status == 401 || head.status == 403 {
            return Err(OpenConnectError::AuthRejected);
        }
        if head.status != 200 {
            return Err(OpenConnectError::malformed(format!(
                "сервер ответил на вход кодом {}",
                head.status
            )));
        }

        let response = xml::parse_response(&response_body)?;
        if let Some(banner) = &response.banner {
            tracing::info!(%banner, "сообщение сервера при входе");
        }

        if response.is_success() {
            let cookie = http::cookie(&head, COOKIE_NAME).ok_or_else(|| {
                OpenConnectError::malformed(
                    "сервер подтвердил вход, но не прислал куку сессии `webvpn`",
                )
            })?;
            return Ok(LoginResult { cookie });
        }

        if let Some(next) = &response.action {
            path = next.clone();
        }
        let answers = answer(
            &response.fields,
            config,
            &mut username_used,
            &mut password_used,
        )?;
        body = xml::auth_reply(&answers)?;
    }

    Err(OpenConnectError::malformed(format!(
        "вход не завершился успехом или отказом за {MAX_ROUNDS} обменов с сервером"
    )))
}

/// Заполняет поля формы тем, что есть в настройках.
///
/// Возвращает ошибку [`OpenConnectError::SecondFactorRequired`] на первом
/// поле, которое не сводится к имени, паролю, выбору группы или заранее
/// известному скрытому значению, — форма при этом не отправляется: лучше
/// сказать прямо, что спросил сервер, чем угадывать и получить путаницу
/// вместо ответа.
fn answer(
    fields: &[Field],
    config: &OpenConnectConfig,
    username_used: &mut bool,
    password_used: &mut bool,
) -> OpenConnectResult<Vec<(String, String)>> {
    let mut answers = Vec::with_capacity(fields.len());

    for field in fields {
        match &field.kind {
            FieldKind::Text if field.name == "username" && !*username_used => {
                answers.push((field.name.clone(), config.username.clone()));
                *username_used = true;
            }
            FieldKind::Password if !*password_used => {
                answers.push((field.name.clone(), config.password.clone()));
                *password_used = true;
            }
            FieldKind::Select(options) if field.name == "group_list" => {
                answers.push((field.name.clone(), choose_group(config, options)?));
            }
            FieldKind::Hidden if field.value.is_some() => {
                let value = field.value.clone().unwrap_or_default();
                answers.push((field.name.clone(), value));
            }
            _ => {
                let hint = if field.label.is_empty() {
                    format!("поле `{}`", field.name)
                } else {
                    field.label.clone()
                };
                return Err(OpenConnectError::SecondFactorRequired(hint));
            }
        }
    }
    Ok(answers)
}

/// Выбирает значение для `<select name="group_list">`.
///
/// Настройка [`OpenConnectConfig::group`] сравнивается и со значением
/// варианта, и с его подписью — человек мог переписать в настройки то, что
/// видел в браузере (подпись), а не то, что уходит на провод (значение). Не
/// задана — берётся первый вариант, как это делает форма браузера при
/// отправке без выбора.
fn choose_group(
    config: &OpenConnectConfig,
    options: &[(String, String)],
) -> OpenConnectResult<String> {
    if let Some(wanted) = &config.group {
        return options
            .iter()
            .find(|(value, label)| value == wanted || label == wanted)
            .map(|(value, _)| value.clone())
            .ok_or_else(|| {
                let available: Vec<&str> =
                    options.iter().map(|(_, label)| label.as_str()).collect();
                OpenConnectError::config(format!(
                    "группа `{wanted}` не найдена среди предложенных сервером: {}",
                    available.join(", ")
                ))
            });
    }
    options
        .first()
        .map(|(value, _)| value.clone())
        .ok_or_else(|| OpenConnectError::malformed("сервер прислал пустой список групп для входа"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OpenConnectConfig {
        OpenConnectConfig {
            server: "vpn.example.com:443".to_owned(),
            username: "ivan".to_owned(),
            password: "secret".to_owned(),
            ..OpenConnectConfig::default()
        }
    }

    fn text_field(name: &str) -> Field {
        Field {
            name: name.to_owned(),
            kind: FieldKind::Text,
            label: String::new(),
            value: None,
        }
    }

    fn password_field(name: &str, label: &str) -> Field {
        Field {
            name: name.to_owned(),
            kind: FieldKind::Password,
            label: label.to_owned(),
            value: None,
        }
    }

    #[test]
    fn username_and_password_in_one_form_are_both_answered() {
        let fields = vec![
            text_field("username"),
            password_field("password", "Password:"),
        ];
        let mut username_used = false;
        let mut password_used = false;
        let answers =
            answer(&fields, &config(), &mut username_used, &mut password_used).expect("отвечается");
        assert_eq!(
            answers,
            vec![
                ("username".to_owned(), "ivan".to_owned()),
                ("password".to_owned(), "secret".to_owned())
            ]
        );
        assert!(username_used && password_used);
    }

    #[test]
    fn a_password_asked_for_twice_is_a_second_factor_not_a_repeat() {
        // Первый раз пароль уходит как обычно; второй запрос того же типа
        // поля — это уже не переспрошенный пароль, а другой секрет.
        let mut username_used = true;
        let mut password_used = true;
        let err = answer(
            &[password_field("secondary_password", "Password2:")],
            &config(),
            &mut username_used,
            &mut password_used,
        )
        .expect_err("второй фактор");
        assert!(
            matches!(err, OpenConnectError::SecondFactorRequired(hint) if hint == "Password2:")
        );
    }

    #[test]
    fn an_unrecognised_field_names_itself_in_the_error() {
        let field = Field {
            name: "otp".to_owned(),
            kind: FieldKind::Other("token".to_owned()),
            label: String::new(),
            value: None,
        };
        let mut username_used = true;
        let mut password_used = true;
        let err = answer(&[field], &config(), &mut username_used, &mut password_used)
            .expect_err("нечем заполнить");
        assert!(
            matches!(err, OpenConnectError::SecondFactorRequired(hint) if hint.contains("otp"))
        );
    }

    #[test]
    fn a_hidden_field_with_a_default_is_echoed_back_unchanged() {
        let field = Field {
            name: "csrf".to_owned(),
            kind: FieldKind::Hidden,
            label: String::new(),
            value: Some("abc123".to_owned()),
        };
        let mut username_used = true;
        let mut password_used = true;
        let answers = answer(&[field], &config(), &mut username_used, &mut password_used)
            .expect("отвечается");
        assert_eq!(answers, vec![("csrf".to_owned(), "abc123".to_owned())]);
    }

    #[test]
    fn the_first_group_is_chosen_when_none_is_configured() {
        let options = vec![
            ("staff".to_owned(), "Staff".to_owned()),
            ("guests".to_owned(), "Guests".to_owned()),
        ];
        assert_eq!(
            choose_group(&config(), &options).expect("выбирается"),
            "staff"
        );
    }

    #[test]
    fn a_configured_group_is_matched_by_value_or_by_label() {
        let options = vec![
            ("staff".to_owned(), "Staff".to_owned()),
            ("guests".to_owned(), "Guests".to_owned()),
        ];
        let by_value = OpenConnectConfig {
            group: Some("guests".to_owned()),
            ..config()
        };
        assert_eq!(
            choose_group(&by_value, &options).expect("выбирается"),
            "guests"
        );

        let by_label = OpenConnectConfig {
            group: Some("Staff".to_owned()),
            ..config()
        };
        assert_eq!(
            choose_group(&by_label, &options).expect("выбирается"),
            "staff"
        );
    }

    #[test]
    fn an_unknown_configured_group_names_the_real_choices() {
        let options = vec![("staff".to_owned(), "Staff".to_owned())];
        let config = OpenConnectConfig {
            group: Some("marketing".to_owned()),
            ..config()
        };
        let err = choose_group(&config, &options).expect_err("такой группы нет");
        assert!(err.to_string().contains("Staff"), "{err}");
    }

    #[test]
    fn the_user_agent_starts_with_what_ocserv_matches() {
        // `worker-http.c` определяет тип клиента по началу заголовка;
        // отступить от буквального `"OpenConnect VPN Agent"` — значит стать
        // для сервера безымянным клиентом без IPv6-маршрутов.
        assert!(USER_AGENT.starts_with("OpenConnect VPN Agent"));
    }
}

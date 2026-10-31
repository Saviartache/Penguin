//! Вызов системного `ssh`: аргументы, окружение и команда на сервере.

use std::path::Path;

use super::request::Request;
use crate::askpass;

/// Архив исходников той же версии, что у клиента: сервер собирается из них.
pub fn source_url() -> String {
    format!(
        "{}/archive/refs/tags/v{}.tar.gz",
        env!("CARGO_PKG_REPOSITORY"),
        env!("CARGO_PKG_VERSION")
    )
}

/// Слово для оболочки в одинарных кавычках.
pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Аргументы и окружение `ssh`. `Debug` нет: в окружении пароль.
pub struct Invocation {
    /// Аргументы `ssh`.
    pub args: Vec<String>,
    /// Добавочное окружение `ssh`.
    pub env: Vec<(&'static str, String)>,
}

/// Собирает вызов `ssh`; `askpass` — этот же исполняемый файл.
pub fn invocation(request: &Request, askpass: &Path, source: &str) -> Invocation {
    let mut args = words(&[
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=20",
        "-o",
        "ServerAliveInterval=15",
        "-p",
    ]);
    args.push(request.ssh_port.to_string());

    let mut env = Vec::new();
    if let Some(password) = &request.password {
        args.extend(words(&[
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "PreferredAuthentications=password,keyboard-interactive",
        ]));
        env.push(("SSH_ASKPASS", askpass.display().to_string()));
        env.push(("SSH_ASKPASS_REQUIRE", "force".to_owned()));
        env.push((askpass::VARIABLE, password.clone()));
    } else if let Some(key) = &request.key_file {
        args.extend(["-i".to_owned(), key.clone()]);
        args.extend(words(&["-o", "IdentitiesOnly=yes"]));
    }

    args.push(format!("{}@{}", request.ssh_user, request.host));
    args.push(remote_command(request, source));
    Invocation { args, env }
}

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// `env` вместо `ИМЯ=…` перед командой: так работает и под `sudo`, и в любой оболочке.
fn remote_command(request: &Request, source: &str) -> String {
    let mut assignments = vec![
        ("PINGWIN_MODE", "full".to_owned()),
        ("PINGWIN_SOURCE", source.to_owned()),
        ("PINGWIN_DOMAIN", request.domain.clone()),
        ("PINGWIN_PORT", request.port.to_string()),
        ("PINGWIN_USER", request.user.clone()),
    ];
    if let Some(email) = &request.email {
        assignments.push(("PINGWIN_EMAIL", email.clone()));
    }
    if let Some(profile) = &request.profile {
        assignments.push(("PINGWIN_PROFILE", profile.clone()));
    }

    // Не root — нужен sudo без пароля: спросить его некому.
    let mut command = if request.ssh_user == "root" {
        "env".to_owned()
    } else {
        "sudo -n env".to_owned()
    };
    for (name, value) in assignments {
        command.push(' ');
        command.push_str(&quote(&format!("{name}={value}")));
    }
    command.push_str(" bash -s");
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(json: &str) -> Request {
        serde_json::from_str(json).expect("запрос разбирается")
    }

    #[test]
    fn quote_survives_apostrophes() {
        assert_eq!(quote("abc"), "'abc'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn source_is_the_client_version_tag() {
        let url = source_url();
        assert!(url.starts_with("https://github.com/"));
        assert!(url.ends_with(&format!(
            "/archive/refs/tags/v{}.tar.gz",
            env!("CARGO_PKG_VERSION")
        )));
    }

    #[test]
    fn password_goes_through_askpass_not_arguments() {
        let request = request(
            r#"{"host":"203.0.113.5","ssh_port":2222,"password":"s3cret","domain":"vpn.example.com","profile":"Мой"}"#,
        );
        let call = invocation(&request, Path::new("/bin/penguin"), "https://x/y.tar.gz");
        assert!(!call.args.iter().any(|arg| arg.contains("s3cret")));
        assert_eq!(
            call.args[..8],
            [
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=20",
                "-o",
                "ServerAliveInterval=15",
                "-p",
                "2222"
            ]
        );
        assert!(call.args.contains(&"NumberOfPasswordPrompts=1".to_owned()));
        assert_eq!(
            call.env,
            [
                ("SSH_ASKPASS", "/bin/penguin".to_owned()),
                ("SSH_ASKPASS_REQUIRE", "force".to_owned()),
                (askpass::VARIABLE, "s3cret".to_owned()),
            ]
        );
        let n = call.args.len();
        assert_eq!(call.args[n - 2], "root@203.0.113.5");
        assert_eq!(
            call.args[n - 1],
            "env 'PINGWIN_MODE=full' 'PINGWIN_SOURCE=https://x/y.tar.gz' \
             'PINGWIN_DOMAIN=vpn.example.com' 'PINGWIN_PORT=443' 'PINGWIN_USER=client' \
             'PINGWIN_PROFILE=Мой' bash -s"
        );
    }

    #[test]
    fn key_file_and_sudo_for_other_users() {
        let request = request(
            r#"{"host":"h","ssh_user":"ubuntu","key_file":"/k/id","domain":"vpn.example.com","email":"a@b.c"}"#,
        );
        let call = invocation(&request, Path::new("/p"), "s");
        assert!(call.env.is_empty());
        assert!(
            call.args
                .windows(4)
                .any(|w| w == ["-i", "/k/id", "-o", "IdentitiesOnly=yes"])
        );
        let command = call.args.last().expect("команда");
        assert!(command.starts_with("sudo -n env "));
        assert!(command.contains("'PINGWIN_EMAIL=a@b.c'"));
        assert!(command.ends_with(" bash -s"));
    }

    #[test]
    fn the_agent_needs_nothing_extra() {
        let call = invocation(
            &request(r#"{"host":"h","domain":"vpn.example.com"}"#),
            Path::new("/p"),
            "s",
        );
        assert!(call.env.is_empty());
        assert!(!call.args.iter().any(|arg| arg == "-i"));
    }
}

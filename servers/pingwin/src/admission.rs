//! Допуск: опознание запроса — одно для HTTP/3 и HTTP/2, `GET /` с `authorization`.

use http::{Method, Request};
use penguin_pingwin::wire::auth;
use penguin_pingwin::wire::keys::KEY_LEN;

use crate::server::Server;

/// Опознанный клиент.
pub(crate) struct Admission {
    /// Имя для журнала.
    pub(crate) user: String,
    /// Значение `pingwin-proof`.
    pub(crate) proof: String,
}

/// Проверяет опознание; `None` — запрос не опознания или клиент чужой.
pub(crate) fn admit<T>(
    server: &Server,
    exporter: &[u8; KEY_LEN],
    request: &Request<T>,
) -> Option<Admission> {
    if request.method() != Method::GET || request.uri().path() != auth::PATH {
        return None;
    }
    let header = request
        .headers()
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let policy = &server.policy;
    let admitted = auth::verify(header, exporter, &server.keys, |user| policy.password(user))?;
    Some(Admission {
        user: policy.name(&admitted.user).unwrap_or("?").to_owned(),
        proof: admitted.proof,
    })
}

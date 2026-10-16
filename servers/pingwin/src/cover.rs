//! Прикрытие: статический сайт, который видит тот, кого сервер не узнал.
//!
//! Не отказ и не разрыв, а обычный сервер файлов: `GET` и `HEAD` отдают
//! файл или `index.html` каталога, остальное — `404`, чужие методы — `405`.
//! Опознание, не прошедшее проверку, неотличимо от запроса без него.

use std::path::{Component, Path, PathBuf};

use bytes::Bytes;
use h3::server::RequestStream;
use http::{Method, Request, Response, StatusCode, header};

/// Поток запроса сервера.
pub type Stream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

const NOT_FOUND: &str = "<html><head><title>404 Not Found</title></head>\
<body><h1>404 Not Found</h1></body></html>\n";

const NOT_ALLOWED: &str = "<html><head><title>405 Not Allowed</title></head>\
<body><h1>405 Not Allowed</h1></body></html>\n";

/// Отвечает на запрос как сайт из каталога `root`.
pub async fn serve(root: Option<&Path>, request: &Request<()>, mut stream: Stream) {
    let (status, content_type, body) = answer(root, request).await;
    let response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len())
        .body(());
    let Ok(response) = response else {
        return;
    };
    let head = request.method() == Method::HEAD;
    let sent = async {
        stream.send_response(response).await?;
        if !head && !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await
    };
    if let Err(err) = sent.await {
        tracing::trace!(%err, "ответ прикрытия не ушёл");
    }
}

async fn answer(root: Option<&Path>, request: &Request<()>) -> (StatusCode, &'static str, Bytes) {
    let page =
        |status, text: &'static str| (status, "text/html", Bytes::from_static(text.as_bytes()));
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return page(StatusCode::METHOD_NOT_ALLOWED, NOT_ALLOWED);
    }
    let Some(path) = root.and_then(|root| resolve(root, request.uri().path())) else {
        return page(StatusCode::NOT_FOUND, NOT_FOUND);
    };
    match read(&path).await {
        Some(body) => (StatusCode::OK, content_type(&path), body),
        None => page(StatusCode::NOT_FOUND, NOT_FOUND),
    }
}

/// Файл внутри корня; каталог — его `index.html`.
async fn read(path: &Path) -> Option<Bytes> {
    let path = if tokio::fs::metadata(path).await.ok()?.is_dir() {
        path.join("index.html")
    } else {
        path.to_owned()
    };
    tokio::fs::read(path).await.ok().map(Bytes::from)
}

/// Путь запроса внутри корня. `None` — путь выходит за корень.
///
/// Скрытые файлы (`.env`, `.git`) не отдаются: у обычного сайта их снаружи
/// не видно.
fn resolve(root: &Path, request_path: &str) -> Option<PathBuf> {
    let mut path = root.to_owned();
    for part in Path::new(request_path).components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) if !name.to_string_lossy().starts_with('.') => path.push(name),
            _ => return None,
        }
    }
    Some(path)
}

/// Тип содержимого по расширению.
fn content_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    match extension.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "json" => "application/json",
        "txt" => "text/plain",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside_the_root() {
        let root = Path::new("/srv/cover");
        assert_eq!(resolve(root, "/"), Some(root.to_owned()));
        assert_eq!(
            resolve(root, "/css/site.css"),
            Some(root.join("css").join("site.css"))
        );
        for escape in ["/../etc/passwd", "/a/../../b", "/.env", "/.git/config"] {
            assert_eq!(resolve(root, escape), None, "{escape}");
        }
    }

    #[test]
    fn the_type_follows_the_extension() {
        assert_eq!(content_type(Path::new("index.HTML")), "text/html");
        assert_eq!(content_type(Path::new("a.woff2")), "font/woff2");
        assert_eq!(
            content_type(Path::new("README")),
            "application/octet-stream"
        );
    }
}

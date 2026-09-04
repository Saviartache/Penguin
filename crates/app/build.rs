//! Иконка в собранном файле.
//!
//! На Windows иконку программы хранит не каталог рядом с ней, а она сама:
//! проводник, панель задач и ярлык читают её из ресурсов `penguin.exe`.
//! Поэтому `assets/icon.ico` попадает в файл здесь, при сборке, а не в
//! `scripts/package.sh` — копировать в поставку нечего.

fn main() {
    // Путь от каталога крейта: сборочный скрипт запускается в нём.
    println!("cargo:rerun-if-changed=../../assets/icon.ico");

    // Цель, а не машина сборки. `#[cfg(windows)]` здесь означал бы «собираем
    // на Windows», и обе кросс-сборки ломались бы: поставка для Windows,
    // собранная с macOS, осталась бы без иконки, а сборка для Linux с Windows
    // попыталась бы встроить ресурс в файл, который его не носит.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_icon();
    }
}

/// Кладёт `assets/icon.ico` в ресурсы `penguin.exe`.
fn embed_icon() {
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("../../assets/icon.ico");

    // Имя в свойствах файла и в диспетчере задач. Без этого туда попадают
    // `penguin-app` и описание крейта из `Cargo.toml` — слова для нас, а не
    // для того, кто открыл список процессов.
    resource.set("ProductName", "Penguin");
    resource.set("FileDescription", "Penguin");

    if let Err(error) = resource.compile() {
        // Тихо собранный файл без иконки хуже упавшей сборки: поставка
        // выглядит готовой, а в проводнике у неё чужое лицо.
        panic!("иконка не встроена: {error}");
    }
}

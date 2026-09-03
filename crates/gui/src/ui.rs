//! Основа экранов: страница, раздел, строка, пустое состояние.
//!
//! Не набор помощников для красоты. Здесь собрано то, что в `iced 0.12`
//! разъезжается само собой, если каждый экран решает это заново.
//!
//! # Размер задаётся явно и до конца
//!
//! Растянутый ребёнок внутри группы «по содержимому» **схлопывается в ноль**;
//! ноль означает квад нулевого размера, а его рендерер не принимает. Отсюда
//! правило: растягивается ровно один элемент на каждом уровне — страница по
//! обеим осям, всё внутри неё по содержимому. Экрану остаётся сказать, из
//! каких разделов он состоит.
//!
//! # Прокрутка по правилам кита
//!
//! `iced` рисует полосу прокрутки **поверх** содержимого, поэтому отступы
//! задаёт содержимое, а не контейнер вокруг (правило 4.6 кита). Соблюдать это
//! в каждом экране отдельно — значит однажды не соблюсти.
//!
//! # Три уровня иерархии и ни одним больше
//!
//! Заголовок экрана, заголовок раздела, строка. Разделяются кеглем и
//! непрозрачностью, а не рамками: рамка вокруг каждого блока превращает экран
//! в таблицу, где всё одинаково важно.
//!
//! Палитра приходит параметром, потому что в `iced 0.12` цвет текста задаётся
//! конкретным значением, а `view` темы не получает.

use iced::theme::Palette;
use iced::widget::{Space, container, scrollable, text};
use iced::{Alignment, Element, Length};
use uikit::layout::{Flex, gap, grow};
use uikit::style::scrollbar;
use uikit::style::tokens::{ink, type_scale};
use uikit::widgets::{Button, ButtonVariant, Card};

use crate::app::PAGE_PADDING;

/// Страница без заголовка — там, где он ничего не добавляет.
///
/// Заголовок повторяет подпись вкладки, по которой сюда и пришли. Когда на
/// экране одно действие и один список, это второе «Серверы» подряд, съедающее
/// строку в самом видном месте.
pub fn page_bare<'a, Message: 'a>(sections: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    build_page(sections)
}

/// Общая часть страницы: прокрутка, отступы, воздух снизу.
fn build_page<'a, Message: 'a>(sections: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    let body = Flex::col()
        .extend(sections)
        // Воздух снизу: последний раздел не должен упираться в край окна.
        .push_auto(Space::new().height(Length::Fixed(PAGE_PADDING)))
        .gap(gap::LG)
        .build();

    // Отступ — на содержимом прокрутки, а не на обёртке: иначе полоса ляжет
    // поверх текста у правого края (правило 4.6 кита).
    scrollable(
        container(body)
            .padding(scrollbar::safe(PAGE_PADDING))
            .width(Length::Fill),
    )
    .direction(scrollbar::vertical())
    .style(scrollbar::style())
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

/// Раздел страницы: заголовок, необязательная подсказка, содержимое.
pub fn section<'a, Message: 'a>(
    palette: &Palette,
    title: &'a str,
    hint: Option<&'a str>,
    content: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    let head = Flex::col()
        .push_auto(text(title).size(type_scale::LEAD))
        .push_maybe(hint.map(|hint| faint(palette, hint, type_scale::MICRO)))
        .gap(gap::XS)
        .build();

    let body = Flex::col()
        .push_auto(head)
        .push_auto(content)
        .gap(gap::MD)
        .build();

    Card::new(body)
        .padding(gap::LG)
        .width(Length::Fill)
        .build()
        .into()
}

/// сузить поле вдвое ради пустоты.
pub fn form_row<'a, Message: 'a>(
    label: &'a str,
    control: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    Flex::row()
        .push_sized(text(label).size(type_scale::LEAD), grow(2))
        .push_sized(control, grow(3))
        .gap(gap::LG)
        .align(Alignment::Center)
        .build()
}

/// Строка, у которой элемент управления сам несёт подпись, — флажок.
pub fn switch<'a, Message: 'a>(
    palette: &Palette,
    control: impl Into<Element<'a, Message>>,
    hint: Option<&'a str>,
) -> Element<'a, Message> {
    Flex::col()
        .push_auto(control)
        .push_maybe(hint.map(|hint| faint(palette, hint, type_scale::MICRO)))
        .gap(gap::XS)
        .build()
}

/// Пустое состояние: почему здесь ничего нет.
///
/// Отдельным элементом, потому что пустой экран без объяснения читается как
/// «не загрузилось», и человек ждёт. Причина всегда одна из двух — «ещё не
/// пришло» или «нечего показывать», — и они требуют разных действий.
pub fn empty<'a, Message: 'a>(palette: &Palette, reason: &'a str) -> Element<'a, Message> {
    container(muted(palette, reason, type_scale::BODY))
        .width(Length::Fill)
        .padding(gap::SM)
        .into()
}

/// Приглушённый текст — второй уровень иерархии.
pub fn muted<'a, Message: 'a>(
    palette: &Palette,
    value: impl ToString,
    size: f32,
) -> Element<'a, Message> {
    text(value.to_string())
        .size(size)
        .color(ink::level(palette, ink::SECONDARY))
        .into()
}

/// Ещё тише: подсказка, счётчик, прочерк на месте пустого значения.
pub fn faint<'a, Message: 'a>(
    palette: &Palette,
    value: impl ToString,
    size: f32,
) -> Element<'a, Message> {
    text(value.to_string())
        .size(size)
        .color(ink::level(palette, ink::TERTIARY))
        .into()
}

/// Кнопка для ряда: подпись по содержимому, а не во всю ширину.
///
/// У кита подпись кнопки по умолчанию растянута на всю ширину — так у кнопок в
/// **столбце** совпадают размеры. В ряду это означает другое: кнопка забирает
/// всё свободное место, сосед схлопывается в ноль и пропадает с экрана
/// (`Button::hug` в ките описывает ровно этот случай).
///
/// В окне кнопки почти всегда стоят в ряду, поэтому здесь `hug` — умолчание, а
/// не исключение, о котором надо помнить в каждом месте.
pub fn button<'a, Message: Clone + 'a>(
    variant: ButtonVariant,
    label: &'a str,
) -> Button<'a, Message> {
    let button = match variant {
        ButtonVariant::Primary => Button::primary(label),
        ButtonVariant::Secondary => Button::secondary(label),
        ButtonVariant::Positive => Button::positive(label),
        ButtonVariant::Danger => Button::danger(label),
        ButtonVariant::Neutral => Button::neutral(label),
    };
    button.hug()
}

/// Распорка, отжимающая соседей к краям ряда.
pub fn spring<'a, Message: 'a>() -> Element<'a, Message> {
    Space::new().width(Length::Fill).into()
}

/// Прокручиваемый список внутри раздела.
///
/// Своя высота обязательна: список запущенных приложений — это полторы сотни
/// строк, и без ограничения он выдавливает с экрана всё остальное.
pub fn scroll_box<'a, Message: 'a>(
    content: impl Into<Element<'a, Message>>,
    height: f32,
) -> Element<'a, Message> {
    scrollable(
        container(content)
            .padding(scrollbar::safe(0.0))
            .width(Length::Fill),
    )
    .direction(scrollbar::vertical())
    .style(scrollbar::style())
    .width(Length::Fill)
    .height(Length::Fixed(height))
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    type Message = ();

    fn palette() -> Palette {
        uikit::ThemeType::Dark.to_iced_theme().palette()
    }

    #[test]
    fn a_page_declares_itself_stretched() {
        // Растянутый ребёнок в группе «по содержимому» схлопывается в ноль, а
        // квад нулевого размера рендерер не принимает. Страница обязана
        // объявить размер сама, иначе это придётся помнить каждому экрану.
        let page: Element<'_, Message> = page_bare(Vec::new());
        let size = page.as_widget().size();

        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn sections_fill_the_page_width() {
        // Раздел уже колонки читается как обрезанный, а не как отдельный блок.
        let section: Element<'_, Message> = section(&palette(), "Раздел", None, text("тело"));
        assert_eq!(section.as_widget().size().width, Length::Fill);
    }

    #[test]
    fn a_section_takes_only_the_height_it_needs() {
        // Иначе два раздела на странице делили бы её высоту поровну, и
        // короткий раздел растягивался бы на пол-экрана.
        let section: Element<'_, Message> = section(&palette(), "Раздел", None, text("тело"));
        assert_ne!(section.as_widget().size().height, Length::Fill);
    }

    #[test]
    fn a_scroll_box_keeps_the_height_it_was_given() {
        let list: Element<'_, Message> = scroll_box(text("строка"), 180.0);
        assert_eq!(list.as_widget().size().height, Length::Fixed(180.0));
    }

    #[test]
    fn the_two_muted_levels_differ() {
        // Иначе иерархии нет: подпись и подсказка читаются как один уровень.
        let palette = palette();
        assert_ne!(
            ink::level(&palette, ink::SECONDARY).a,
            ink::level(&palette, ink::TERTIARY).a
        );
    }

    #[test]
    fn everything_composes() {
        let palette = palette();
        let _: Element<'_, Message> = page_bare(vec![
            section(&palette, "Раздел", Some("подсказка"), text("тело")),
            section(
                &palette,
                "Со строками",
                None,
                Flex::col()
                    .push_auto(form_row("Поле", text("значение")))
                    .push_auto(switch(&palette, text("флажок"), Some("что делает")))
                    .push_auto(empty(&palette, "пусто"))
                    .push_auto(scroll_box(text("список"), 120.0))
                    .gap(gap::SM)
                    .build(),
            ),
        ]);
    }
}

//! Сборка сопоставителей из конфигурации. Дорогая работа делается один раз, а
//! не на каждое соединение.
//!
//! Здесь текст превращается в готовые структуры: регулярные выражения
//! компилируются, подсети складываются в дерево, подстроки — в автомат
//! Ахо — Корасик. На горячем пути остаётся только поиск.
//!
//! Второе назначение файла — проверка. Ошибка в правиле («не разбирается
//! подсеть `10.0.0.0/99`») обязана прийти при сохранении настроек, а не при
//! первом соединении: во втором случае пользователь узнает о ней из молча
//! неработающего правила.

use penguin_config::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};
use penguin_core::id::{OutboundId, RuleId};
use penguin_core::network::{IpFamily, Network};
use penguin_match::address::{DomainSet, IpSet, PortSet};
use penguin_match::logic::{All, Any, Not};
use penguin_match::matcher::Matcher;
use penguin_match::network::{IpFamilySet, NetworkSet};
use penguin_match::process::name::NameSet;
use penguin_match::process::path::{GlobPathSet, PathSet};

use super::rule::Rule;
use crate::decision::Decision;
use crate::error::{RouterError, RouterResult};

/// Что доступно сборщику сверх самого правила.
#[derive(Default)]
pub struct CompileContext {
    /// База GeoIP, если она загружена.
    #[cfg(feature = "geo")]
    pub geoip: Option<penguin_match::address::geo::GeoIpDatabase>,
}

/// Собирает правило из конфигурации.
pub fn compile_rule(config: &RuleConfig, ctx: &CompileContext) -> RouterResult<Rule> {
    let condition = compile_condition(&config.when, ctx)
        .map_err(|e| RouterError::rule(&config.id, e.to_string()))?;

    let action = match &config.action {
        RuleAction::Tunnel {
            profile: Some(profile),
        } => Decision::Tunnel(OutboundId::new(profile)),
        // Без указания профиля — в активный. Какой он, знает движок:
        // подставлять его здесь значило бы пересобирать правила при каждом
        // переключении сервера.
        RuleAction::Tunnel { profile: None } => Decision::ActiveTunnel,
        RuleAction::Direct => Decision::Direct,
        RuleAction::Block => Decision::Block,
    };

    Ok(Rule {
        id: RuleId::new(&config.id),
        name: if config.name.is_empty() {
            config.id.clone()
        } else {
            config.name.clone()
        },
        priority: config.priority,
        condition,
        action,
    })
}

/// Собирает условие целиком, включая вложенные.
pub fn compile_condition(
    condition: &Condition,
    ctx: &CompileContext,
) -> RouterResult<Box<dyn Matcher>> {
    match condition {
        Condition::All { all } => {
            let parts = all
                .iter()
                .map(|c| compile_condition(c, ctx))
                .collect::<RouterResult<Vec<_>>>()?;
            Ok(Box::new(All(parts)))
        }
        Condition::Any { any } => {
            let parts = any
                .iter()
                .map(|c| compile_condition(c, ctx))
                .collect::<RouterResult<Vec<_>>>()?;
            Ok(Box::new(Any(parts)))
        }
        Condition::Not { not } => Ok(Box::new(Not(compile_condition(not, ctx)?))),
        Condition::Leaf(leaf) => compile_leaf(leaf, ctx),
    }
}

/// Собирает элементарное условие.
fn compile_leaf(leaf: &Leaf, ctx: &CompileContext) -> RouterResult<Box<dyn Matcher>> {
    let matcher: Box<dyn Matcher> = match leaf {
        Leaf::ProcessPath(paths) => Box::new(PathSet::new(paths)),
        Leaf::ProcessName(names) => Box::new(NameSet::new(names)),
        Leaf::ProcessPathGlob(globs) => Box::new(GlobPathSet::new(globs).map_err(invalid)?),

        Leaf::Domain(names) => Box::new(DomainSet::exact(names)),
        Leaf::DomainSuffix(names) => Box::new(DomainSet::suffix(names)),
        Leaf::DomainKeyword(names) => Box::new(DomainSet::keyword(names).map_err(invalid)?),
        Leaf::DomainRegex(patterns) => Box::new(DomainSet::regex(patterns).map_err(invalid)?),

        Leaf::DestIp(nets) => Box::new(IpSet::parse(nets).map_err(invalid)?),
        Leaf::DestPort(ports) => Box::new(PortSet::from_ports(ports.iter().copied())),
        Leaf::DestPortRange(ranges) => Box::new(PortSet::from_ranges(ranges.iter().copied())),

        Leaf::Network(names) => {
            let networks = names
                .iter()
                .map(|n| n.parse::<Network>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid(e.to_string()))?;
            Box::new(NetworkSet(networks))
        }
        Leaf::IpVersion(names) => {
            let families = names
                .iter()
                .map(|n| n.parse::<IpFamily>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid(e.to_string()))?;
            Box::new(IpFamilySet(families))
        }

        Leaf::GeoIp(countries) => compile_geoip(countries, ctx)?,
        Leaf::GeoSite(_) => {
            // Наборы доменов по категориям — отдельная работа с собственным
            // форматом базы. Молча пропускать такое правило нельзя: трафик
            // ушёл бы не туда, а пользователь считал бы, что правило работает.
            return Err(RouterError::Unsupported("geosite"));
        }
    };
    Ok(matcher)
}

#[cfg(feature = "geo")]
fn compile_geoip(countries: &[String], ctx: &CompileContext) -> RouterResult<Box<dyn Matcher>> {
    let Some(database) = ctx.geoip.clone() else {
        return Err(RouterError::MissingGeoIp);
    };
    Ok(Box::new(penguin_match::address::geo::GeoIpSet::new(
        database, countries,
    )))
}

#[cfg(not(feature = "geo"))]
fn compile_geoip(_countries: &[String], _ctx: &CompileContext) -> RouterResult<Box<dyn Matcher>> {
    Err(RouterError::Unsupported(
        "geoip: клиент собран без поддержки GeoIP",
    ))
}

fn invalid(message: impl Into<String>) -> RouterError {
    RouterError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn condition(value: serde_json::Value) -> Condition {
        serde_json::from_value(value).expect("условие разбирается")
    }

    fn compile(value: serde_json::Value) -> RouterResult<Box<dyn Matcher>> {
        compile_condition(&condition(value), &CompileContext::default())
    }

    #[test]
    fn compiles_every_leaf_kind() {
        let leaves = [
            json!({ "process_path": ["c:/app/app.exe"] }),
            json!({ "process_name": ["app.exe"] }),
            json!({ "process_path_glob": ["c:/games/**/*.exe"] }),
            json!({ "domain": ["example.com"] }),
            json!({ "domain_suffix": ["example.com"] }),
            json!({ "domain_keyword": ["example"] }),
            json!({ "domain_regex": ["^ads?\\."] }),
            json!({ "dest_ip": ["10.0.0.0/8"] }),
            json!({ "dest_port": [443] }),
            json!({ "dest_port_range": [[8000, 8100]] }),
            json!({ "network": ["tcp"] }),
            json!({ "ip_version": ["v4"] }),
        ];
        for leaf in leaves {
            compile(leaf.clone()).unwrap_or_else(|e| panic!("не собралось {leaf}: {e}"));
        }
    }

    #[test]
    fn compiles_nested_conditions() {
        let matcher = compile(json!({
            "all": [
                { "any": [ { "process_name": ["chrome.exe"] }, { "process_name": ["firefox.exe"] } ] },
                { "not": { "dest_ip": ["10.0.0.0/8"] } }
            ]
        }))
        .expect("собирается");

        // Описание должно читаться человеком: его показывает экран проверки.
        let described = matcher.describe();
        assert!(described.contains(" и "));
        assert!(described.contains(" или "));
        assert!(described.contains("не "));
    }

    #[test]
    fn reports_broken_regex_at_compile_time() {
        // Ошибка обязана прийти при сохранении настроек, а не при первом
        // соединении.
        let Err(err) = compile(json!({ "domain_regex": ["(unclosed"] })) else {
            panic!("сломанное выражение собралось");
        };
        assert!(matches!(err, RouterError::Invalid(_)));
    }

    #[test]
    fn reports_broken_cidr_at_compile_time() {
        assert!(compile(json!({ "dest_ip": ["10.0.0.0/99"] })).is_err());
    }

    #[test]
    fn refuses_unsupported_leaf_instead_of_ignoring_it() {
        // Молча пропустить правило значило бы увести трафик не туда, оставив
        // пользователя в уверенности, что правило работает.
        let Err(err) = compile(json!({ "geo_site": ["category-ads"] })) else {
            panic!("неподдержанное условие собралось");
        };
        assert!(matches!(err, RouterError::Unsupported(_)));
    }

    #[test]
    fn rule_without_profile_targets_the_active_one() {
        let config: RuleConfig = serde_json::from_value(json!({
            "id": "r1",
            "when": { "dest_port": [443] },
            "action": { "tunnel": {} }
        }))
        .expect("правило разбирается");

        let rule = compile_rule(&config, &CompileContext::default()).expect("собирается");
        assert_eq!(rule.action, Decision::ActiveTunnel);
        // Имя по умолчанию — идентификатор: в списке правил пустая строка
        // выглядела бы потерянной строкой.
        assert_eq!(rule.name, "r1");
    }

    #[test]
    fn rule_with_profile_targets_it() {
        let config: RuleConfig = serde_json::from_value(json!({
            "id": "r1",
            "name": "Банк",
            "when": { "domain_suffix": ["bank.ru"] },
            "action": { "tunnel": { "profile": "office" } }
        }))
        .expect("правило разбирается");

        let rule = compile_rule(&config, &CompileContext::default()).expect("собирается");
        assert_eq!(rule.action, Decision::Tunnel(OutboundId::new("office")));
        assert_eq!(rule.name, "Банк");
    }

    #[test]
    fn compile_error_names_the_rule() {
        let config: RuleConfig = serde_json::from_value(json!({
            "id": "плохое-правило",
            "when": { "dest_ip": ["не адрес"] },
            "action": "direct"
        }))
        .expect("правило разбирается");

        let err = compile_rule(&config, &CompileContext::default()).expect_err("сломано");
        assert!(
            err.to_string().contains("плохое-правило"),
            "не назвал правило: {err}"
        );
    }
}

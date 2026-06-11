//! Build a [`NetworkConfig`] from raw JunOS hierarchical config text.

use crate::ipv4::Ipv4Network;
use crate::models::{
    Address, AddressBook, AddressSet, Application, ApplicationSet, Interface, InterfaceUnit,
    NetworkConfig, PolicyMatch, PolicyRule, SecurityPolicy, SecurityZone,
};
use crate::parser::{parse_config, Statement};

// ---------------------------------------------------------------------------
// Helpers for navigating the statement list
// ---------------------------------------------------------------------------

fn find<'a>(stmts: &'a [Statement], keyword: &str) -> Vec<&'a Statement> {
    stmts.iter().filter(|s| s.keyword == keyword).collect()
}

fn find_one<'a>(stmts: &'a [Statement], keyword: &str) -> Option<&'a Statement> {
    stmts.iter().find(|s| s.keyword == keyword)
}

fn child_stmts(stmt: Option<&Statement>) -> &[Statement] {
    match stmt.and_then(|s| s.children.as_ref()) {
        Some(children) => children,
        None => &[],
    }
}

fn leaf_value<'a>(stmts: &'a [Statement], keyword: &str) -> Option<&'a str> {
    find_one(stmts, keyword).and_then(|s| s.args.first().map(String::as_str))
}

// ---------------------------------------------------------------------------
// Section parsers
// ---------------------------------------------------------------------------

fn parse_interfaces(stmts: &[Statement]) -> Vec<Interface> {
    let mut interfaces = Vec::new();

    let iface_block = find_one(stmts, "interfaces");
    for iface_stmt in child_stmts(iface_block) {
        let iface_children = match &iface_stmt.children {
            Some(c) => c,
            None => continue,
        };
        let mut iface = Interface {
            name: iface_stmt.keyword.clone(),
            ..Default::default()
        };

        if let Some(desc) = find_one(iface_children, "description") {
            if !desc.args.is_empty() {
                iface.description = Some(desc.args.join(" "));
            }
        }

        for unit_stmt in find(iface_children, "unit") {
            let (unit_args, unit_children) = match (&unit_stmt.args, &unit_stmt.children) {
                (args, Some(children)) if !args.is_empty() => (args, children),
                _ => continue,
            };
            let unit_id = unit_args[0].clone();
            let mut unit = InterfaceUnit {
                unit_id: unit_id.clone(),
                ipv4_addresses: Vec::new(),
            };

            let family_stmt = match find_one(unit_children, "family") {
                Some(s) => s,
                None => continue,
            };
            let family_children = child_stmts(Some(family_stmt));
            // "family inet { ... }" -> 'inet' is an arg, addresses are direct children.
            // "family { inet { ... } }" -> 'inet' is a nested block.
            let addr_container: &[Statement] = if family_stmt.args.iter().any(|a| a == "inet") {
                family_children
            } else {
                child_stmts(find_one(family_children, "inet"))
            };
            for addr_stmt in find(addr_container, "address") {
                if let Some(arg) = addr_stmt.args.first() {
                    if let Ok(net) = Ipv4Network::parse(arg) {
                        unit.ipv4_addresses.push(net);
                    }
                }
            }

            iface.insert_unit(unit);
        }

        interfaces.push(iface);
    }

    interfaces
}

fn parse_address_book(book_stmts: &[Statement]) -> AddressBook {
    let mut book = AddressBook::default();

    for addr_stmt in find(book_stmts, "address") {
        if addr_stmt.args.len() >= 2 {
            let name = addr_stmt.args[0].clone();
            if let Ok(prefix) = Ipv4Network::parse(&addr_stmt.args[1]) {
                book.addresses.insert(
                    name.clone(),
                    Address {
                        name: name.clone(),
                        prefix,
                    },
                );
            }
        }
    }

    for set_stmt in find(book_stmts, "address-set") {
        let set_name = match set_stmt.args.first() {
            Some(n) => n.clone(),
            None => continue,
        };
        let member_stmts = set_stmt.children.as_deref().unwrap_or(&[]);
        let members = member_stmts
            .iter()
            .filter(|s| s.keyword == "address" && !s.args.is_empty())
            .map(|s| s.args[0].clone())
            .collect();
        book.address_sets.insert(
            set_name.clone(),
            AddressSet {
                name: set_name,
                members,
            },
        );
    }

    book
}

fn parse_security_zones(security_children: &[Statement]) -> Vec<SecurityZone> {
    let mut zones = Vec::new();

    let zones_stmt = find_one(security_children, "zones");
    for zone_stmt in child_stmts(zones_stmt) {
        if zone_stmt.keyword != "security-zone" || zone_stmt.args.is_empty() {
            continue;
        }
        let zone_children = match &zone_stmt.children {
            Some(c) => c,
            None => continue,
        };
        let zone_name = zone_stmt.args[0].clone();
        let mut zone = SecurityZone {
            name: zone_name.clone(),
            ..Default::default()
        };

        let ifaces_stmt = find_one(zone_children, "interfaces");
        for iface in child_stmts(ifaces_stmt) {
            // Interfaces inside a zone are listed as bare statements: ge-0/0/0.0;
            zone.interfaces.push(iface.keyword.clone());
        }

        if let Some(book_stmt) = find_one(zone_children, "address-book") {
            zone.address_book = parse_address_book(child_stmts(Some(book_stmt)));
        }

        zones.push(zone);
    }

    zones
}

fn parse_policy_match(match_children: &[Statement]) -> PolicyMatch {
    let mut pm = PolicyMatch::default();
    for stmt in match_children {
        match stmt.keyword.as_str() {
            "source-address" => pm.source_addresses.extend(stmt.args.iter().cloned()),
            "destination-address" => pm.destination_addresses.extend(stmt.args.iter().cloned()),
            "application" => pm.applications.extend(stmt.args.iter().cloned()),
            _ => {}
        }
    }
    pm
}

fn parse_security_policies(security_children: &[Statement]) -> Vec<SecurityPolicy> {
    let mut policies = Vec::new();

    let policies_stmt = find_one(security_children, "policies");
    for dir_stmt in child_stmts(policies_stmt) {
        if dir_stmt.keyword != "from-zone" {
            continue;
        }
        let dir_children = match &dir_stmt.children {
            Some(c) => c,
            None => continue,
        };
        // direction args: ['trust', 'to-zone', 'untrust']
        let from_zone = dir_stmt.args.first().cloned().unwrap_or_default();
        let to_zone = dir_stmt.args.get(2).cloned().unwrap_or_default();

        let mut sp = SecurityPolicy {
            from_zone,
            to_zone,
            rules: Vec::new(),
        };

        for rule_stmt in dir_children {
            if rule_stmt.keyword != "policy" || rule_stmt.args.is_empty() {
                continue;
            }
            let rule_children = match &rule_stmt.children {
                Some(c) => c,
                None => continue,
            };
            let mut rule = PolicyRule {
                name: rule_stmt.args[0].clone(),
                ..Default::default()
            };

            if let Some(match_stmt) = find_one(rule_children, "match") {
                rule.r#match = parse_policy_match(child_stmts(Some(match_stmt)));
            }

            if let Some(then_stmt) = find_one(rule_children, "then") {
                for action in child_stmts(Some(then_stmt)) {
                    if matches!(action.keyword.as_str(), "permit" | "deny" | "reject") {
                        rule.action = action.keyword.clone();
                        break;
                    }
                }
            }

            sp.rules.push(rule);
        }

        policies.push(sp);
    }

    policies
}

fn parse_applications(
    app_stmts: &[Statement],
) -> (Vec<Application>, Vec<ApplicationSet>) {
    let mut applications = Vec::new();
    let mut application_sets = Vec::new();

    let apps_block = find_one(app_stmts, "applications");
    for stmt in child_stmts(apps_block) {
        let children = match &stmt.children {
            Some(c) => c,
            None => continue,
        };
        if stmt.keyword == "application" && !stmt.args.is_empty() {
            let name = stmt.args[0].clone();
            applications.push(Application {
                name: name.clone(),
                protocol: leaf_value(children, "protocol").map(str::to_string),
                dst_port: leaf_value(children, "destination-port").map(str::to_string),
            });
        } else if stmt.keyword == "application-set" && !stmt.args.is_empty() {
            let name = stmt.args[0].clone();
            let members = children
                .iter()
                .filter(|s| s.keyword == "application" && !s.args.is_empty())
                .map(|s| s.args[0].clone())
                .collect();
            application_sets.push(ApplicationSet { name, members });
        }
    }

    (applications, application_sets)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse JunOS config text and return a fully populated [`NetworkConfig`].
pub fn build_network_config(text: &str) -> NetworkConfig {
    let stmts = parse_config(text);
    let mut nc = NetworkConfig::default();

    for iface in parse_interfaces(&stmts) {
        nc.insert_interface(iface);
    }

    if let Some(security_stmt) = find_one(&stmts, "security") {
        let sec = child_stmts(Some(security_stmt));
        for zone in parse_security_zones(sec) {
            nc.security_zones.insert(zone.name.clone(), zone);
        }
        nc.security_policies = parse_security_policies(sec);

        // Global address book: security { address-book { global { ... } } }
        if let Some(global_ab_stmt) = find_one(sec, "address-book") {
            let global_children = child_stmts(Some(global_ab_stmt));
            nc.global_address_book = match find_one(global_children, "global") {
                Some(global_block) => parse_address_book(child_stmts(Some(global_block))),
                None => parse_address_book(global_children),
            };
        }
    }

    let (applications, application_sets) = parse_applications(&stmts);
    for app in applications {
        nc.applications.insert(app.name.clone(), app);
    }
    for set in application_sets {
        nc.application_sets.insert(set.name.clone(), set);
    }

    nc
}

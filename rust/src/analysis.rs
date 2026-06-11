//! Analysis queries over a parsed [`NetworkConfig`].

use crate::applications::junos_applications;
use crate::ipv4::{Ipv4Addr, Ipv4Network};
use crate::models::{Application, NetworkConfig, PolicyRule, SecurityPolicy};

/// Outcome of a reachability query.
#[derive(Clone, Debug)]
pub struct ReachabilityResult {
    pub action: String, // "permit" | "deny" | "unknown"
    pub from_zone: Option<String>,
    pub to_zone: Option<String>,
    pub matching_rule: Option<PolicyRule>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn zone_for_interface(nc: &NetworkConfig, iface_unit: &str) -> Option<String> {
    for zone in nc.security_zones.values() {
        if zone.interfaces.iter().any(|i| i == iface_unit) {
            return Some(zone.name.clone());
        }
    }
    None
}

fn lookup_app<'a>(
    nc: &'a NetworkConfig,
    builtins: &'a std::collections::HashMap<String, Application>,
    name: &str,
) -> Option<&'a Application> {
    nc.applications.get(name).or_else(|| builtins.get(name))
}

fn resolve_app_names<'a>(
    nc: &'a NetworkConfig,
    builtins: &'a std::collections::HashMap<String, Application>,
    names: &[String],
) -> Vec<&'a Application> {
    let mut result = Vec::new();
    for name in names {
        if let Some(set) = nc.application_sets.get(name) {
            for member in &set.members {
                if let Some(app) = lookup_app(nc, builtins, member) {
                    result.push(app);
                }
            }
        } else if let Some(app) = lookup_app(nc, builtins, name) {
            result.push(app);
        }
    }
    result
}

fn port_matches(rule_port: Option<&str>, pkt_port: Option<u16>) -> bool {
    let rule_port = match rule_port {
        Some(p) => p,
        None => return true,
    };
    let pkt_port = match pkt_port {
        Some(p) => p,
        None => return true,
    };
    if let Some((lo, hi)) = rule_port.split_once('-') {
        match (lo.parse::<u32>(), hi.parse::<u32>()) {
            (Ok(lo), Ok(hi)) => (lo..=hi).contains(&(pkt_port as u32)),
            _ => false,
        }
    } else {
        rule_port.parse::<u32>().ok() == Some(pkt_port as u32)
    }
}

fn app_matches(app: &Application, protocol: Option<&str>, dst_port: Option<u16>) -> bool {
    if app.name == "any" || app.protocol.is_none() {
        return true;
    }
    if let Some(proto) = protocol {
        if app.protocol.as_deref() != Some(proto) {
            return false;
        }
    }
    port_matches(app.dst_port.as_deref(), dst_port)
}

fn resolve_addresses_for_zone(
    nc: &NetworkConfig,
    zone_name: Option<&str>,
    addr_names: &[String],
) -> Vec<Ipv4Network> {
    let mut networks = Vec::new();
    let zone = zone_name.and_then(|z| nc.security_zones.get(z));
    for name in addr_names {
        if name == "any" {
            return vec![Ipv4Network::any()];
        }
        let mut resolved = Vec::new();
        if let Some(zone) = zone {
            resolved = zone.address_book.resolve(name);
        }
        if resolved.is_empty() {
            resolved = nc.global_address_book.resolve(name);
        }
        networks.extend(resolved);
    }
    networks
}

fn ip_matches_addresses(
    ip: Ipv4Addr,
    nc: &NetworkConfig,
    zone_name: Option<&str>,
    addr_names: &[String],
) -> bool {
    if addr_names.iter().any(|n| n == "any") {
        return true;
    }
    resolve_addresses_for_zone(nc, zone_name, addr_names)
        .iter()
        .any(|net| net.contains(ip))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return the security zone name that contains `src_ip`, or `None`.
///
/// Membership is determined by checking whether the IP falls within any
/// subnet of an interface that belongs to the zone.
pub fn zone_of_ip(nc: &NetworkConfig, src_ip: &str) -> Result<Option<String>, String> {
    let addr = Ipv4Addr::parse(src_ip)?;
    for iface in nc.interfaces_ordered() {
        for (unit_id, net) in iface.all_addresses() {
            if net.contains(addr) {
                let iface_unit = format!("{}.{}", iface.name, unit_id);
                if let Some(zone) = zone_for_interface(nc, &iface_unit) {
                    return Ok(Some(zone));
                }
            }
        }
    }
    Ok(None)
}

/// Evaluate whether traffic from `src_ip` to `dst_ip` is permitted.
pub fn reachability(
    nc: &NetworkConfig,
    src_ip: &str,
    dst_ip: &str,
    protocol: &str,
    dst_port: Option<u16>,
) -> Result<ReachabilityResult, String> {
    let from_zone = zone_of_ip(nc, src_ip)?;
    let to_zone = zone_of_ip(nc, dst_ip)?;

    if from_zone.is_none() || to_zone.is_none() {
        return Ok(ReachabilityResult {
            action: "unknown".to_string(),
            from_zone,
            to_zone,
            matching_rule: None,
        });
    }

    if from_zone == to_zone {
        return Ok(ReachabilityResult {
            action: "permit".to_string(),
            from_zone,
            to_zone,
            matching_rule: None,
        });
    }

    let from = from_zone.clone().unwrap();
    let to = to_zone.clone().unwrap();
    let src_addr = Ipv4Addr::parse(src_ip)?;
    let dst_addr = Ipv4Addr::parse(dst_ip)?;
    let builtins = junos_applications();

    for sp in &nc.security_policies {
        if sp.from_zone != from || sp.to_zone != to {
            continue;
        }
        for rule in &sp.rules {
            if !ip_matches_addresses(src_addr, nc, Some(&from), &rule.r#match.source_addresses) {
                continue;
            }
            if !ip_matches_addresses(dst_addr, nc, Some(&to), &rule.r#match.destination_addresses) {
                continue;
            }
            let apps = resolve_app_names(nc, &builtins, &rule.r#match.applications);
            if apps.is_empty() || apps.iter().any(|a| app_matches(a, Some(protocol), dst_port)) {
                return Ok(ReachabilityResult {
                    action: rule.action.clone(),
                    from_zone,
                    to_zone,
                    matching_rule: Some(rule.clone()),
                });
            }
        }
    }

    // No policy matched -> implicit deny
    Ok(ReachabilityResult {
        action: "deny".to_string(),
        from_zone,
        to_zone,
        matching_rule: None,
    })
}

/// Find policy rules that can never be reached because an earlier catch-all
/// rule (source `any`, destination `any`, application `any`) precedes them.
///
/// Returns `(policy_index, rule_index)` pairs into `nc.security_policies`.
pub fn shadowed_rules(nc: &NetworkConfig) -> Vec<(usize, usize)> {
    let mut result = Vec::new();
    for (pi, sp) in nc.security_policies.iter().enumerate() {
        let mut catchall_seen = false;
        for (ri, rule) in sp.rules.iter().enumerate() {
            if catchall_seen {
                result.push((pi, ri));
            }
            let m = &rule.r#match;
            if m.source_addresses == ["any"]
                && m.destination_addresses == ["any"]
                && m.applications == ["any"]
            {
                catchall_seen = true;
            }
        }
    }
    result
}

/// Convenience view returning references for each shadowed rule.
pub fn shadowed_rule_refs(nc: &NetworkConfig) -> Vec<(&SecurityPolicy, &PolicyRule)> {
    shadowed_rules(nc)
        .into_iter()
        .map(|(pi, ri)| (&nc.security_policies[pi], &nc.security_policies[pi].rules[ri]))
        .collect()
}

/// Return all configured IPv4 addresses as `(interface_name, unit_id, network)`.
pub fn interface_ips(nc: &NetworkConfig) -> Vec<(String, String, Ipv4Network)> {
    let mut result = Vec::new();
    for iface in nc.interfaces_ordered() {
        for (unit_id, net) in iface.all_addresses() {
            result.push((iface.name.clone(), unit_id, net));
        }
    }
    result
}

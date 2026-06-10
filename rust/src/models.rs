//! Domain model types for Juniper firewall configuration.

use std::collections::{HashMap, HashSet};

use crate::ipv4::Ipv4Network;

/// A logical unit (sub-interface) with its configured IPv4 addresses.
#[derive(Clone, Debug, Default)]
pub struct InterfaceUnit {
    pub unit_id: String,
    pub ipv4_addresses: Vec<Ipv4Network>,
}

/// A physical/logical interface and its units.
#[derive(Clone, Debug, Default)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    /// Units keyed by unit id, plus insertion order for stable iteration.
    pub units: HashMap<String, InterfaceUnit>,
    pub unit_order: Vec<String>,
}

impl Interface {
    /// Return `(unit_id, network)` for every configured address across all units.
    pub fn all_addresses(&self) -> Vec<(String, Ipv4Network)> {
        let mut result = Vec::new();
        for uid in &self.unit_order {
            if let Some(unit) = self.units.get(uid) {
                for addr in &unit.ipv4_addresses {
                    result.push((uid.clone(), *addr));
                }
            }
        }
        result
    }

    pub fn insert_unit(&mut self, unit: InterfaceUnit) {
        if !self.units.contains_key(&unit.unit_id) {
            self.unit_order.push(unit.unit_id.clone());
        }
        self.units.insert(unit.unit_id.clone(), unit);
    }
}

/// A named address-book entry resolving to a single prefix.
#[derive(Clone, Debug)]
pub struct Address {
    pub name: String,
    pub prefix: Ipv4Network,
}

/// A named group of addresses or other address-sets.
#[derive(Clone, Debug)]
pub struct AddressSet {
    pub name: String,
    pub members: Vec<String>,
}

/// A zone-level or global address book.
#[derive(Clone, Debug, Default)]
pub struct AddressBook {
    pub addresses: HashMap<String, Address>,
    pub address_sets: HashMap<String, AddressSet>,
}

impl AddressBook {
    /// Expand a name to its constituent prefixes, following address-set nesting.
    pub fn resolve(&self, name: &str) -> Vec<Ipv4Network> {
        let mut seen = HashSet::new();
        self.resolve_inner(name, &mut seen)
    }

    fn resolve_inner(&self, name: &str, seen: &mut HashSet<String>) -> Vec<Ipv4Network> {
        if seen.contains(name) {
            return Vec::new();
        }
        seen.insert(name.to_string());

        if name == "any" {
            return vec![Ipv4Network::any()];
        }

        if let Some(addr) = self.addresses.get(name) {
            return vec![addr.prefix];
        }

        if let Some(set) = self.address_sets.get(name) {
            let mut result = Vec::new();
            for member in &set.members {
                result.extend(self.resolve_inner(member, seen));
            }
            return result;
        }

        Vec::new()
    }
}

/// A security zone, its member interfaces, and zone-scoped address book.
#[derive(Clone, Debug, Default)]
pub struct SecurityZone {
    pub name: String,
    pub interfaces: Vec<String>,
    pub address_book: AddressBook,
}

/// An application definition (protocol + optional destination port spec).
#[derive(Clone, Debug)]
pub struct Application {
    pub name: String,
    pub protocol: Option<String>,
    pub dst_port: Option<String>,
}

/// A named group of applications or application-sets.
#[derive(Clone, Debug)]
pub struct ApplicationSet {
    pub name: String,
    pub members: Vec<String>,
}

/// Match criteria for a policy rule.
#[derive(Clone, Debug, Default)]
pub struct PolicyMatch {
    pub source_addresses: Vec<String>,
    pub destination_addresses: Vec<String>,
    pub applications: Vec<String>,
}

/// A single ordered security-policy rule.
#[derive(Clone, Debug)]
pub struct PolicyRule {
    pub name: String,
    pub r#match: PolicyMatch,
    pub action: String,
}

impl Default for PolicyRule {
    fn default() -> Self {
        PolicyRule {
            name: String::new(),
            r#match: PolicyMatch::default(),
            action: "deny".to_string(),
        }
    }
}

/// All rules governing one `from-zone`/`to-zone` direction.
#[derive(Clone, Debug)]
pub struct SecurityPolicy {
    pub from_zone: String,
    pub to_zone: String,
    pub rules: Vec<PolicyRule>,
}

/// Complete parsed representation of a Juniper firewall configuration.
#[derive(Clone, Debug, Default)]
pub struct NetworkConfig {
    pub interfaces: HashMap<String, Interface>,
    pub interface_order: Vec<String>,
    pub security_zones: HashMap<String, SecurityZone>,
    pub security_policies: Vec<SecurityPolicy>,
    pub applications: HashMap<String, Application>,
    pub application_sets: HashMap<String, ApplicationSet>,
    pub global_address_book: AddressBook,
}

impl NetworkConfig {
    pub fn insert_interface(&mut self, iface: Interface) {
        if !self.interfaces.contains_key(&iface.name) {
            self.interface_order.push(iface.name.clone());
        }
        self.interfaces.insert(iface.name.clone(), iface);
    }

    /// Interfaces in configuration order.
    pub fn interfaces_ordered(&self) -> impl Iterator<Item = &Interface> {
        self.interface_order
            .iter()
            .filter_map(move |name| self.interfaces.get(name))
    }
}

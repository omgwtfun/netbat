//! Tests for the domain model types.

use netbat::ipv4::Ipv4Network;
use netbat::models::{Address, AddressBook, AddressSet, Interface, InterfaceUnit};

fn net(s: &str) -> Ipv4Network {
    Ipv4Network::parse(s).unwrap()
}

fn sample_book() -> AddressBook {
    let mut book = AddressBook::default();
    for (name, prefix) in [
        ("web", "10.0.0.1/32"),
        ("db", "10.0.0.2/32"),
        ("net", "10.0.0.0/24"),
    ] {
        book.addresses.insert(
            name.to_string(),
            Address {
                name: name.to_string(),
                prefix: net(prefix),
            },
        );
    }
    book.address_sets.insert(
        "servers".to_string(),
        AddressSet {
            name: "servers".to_string(),
            members: vec!["web".to_string(), "db".to_string()],
        },
    );
    book.address_sets.insert(
        "all".to_string(),
        AddressSet {
            name: "all".to_string(),
            members: vec!["servers".to_string()],
        },
    );
    book
}

#[test]
fn resolve_single_address() {
    assert_eq!(sample_book().resolve("web"), vec![net("10.0.0.1/32")]);
}

#[test]
fn resolve_address_set_expands_members() {
    let result = sample_book().resolve("servers");
    assert!(result.contains(&net("10.0.0.1/32")));
    assert!(result.contains(&net("10.0.0.2/32")));
    assert_eq!(result.len(), 2);
}

#[test]
fn resolve_nested_address_set() {
    let result = sample_book().resolve("all");
    assert!(result.contains(&net("10.0.0.1/32")));
    assert!(result.contains(&net("10.0.0.2/32")));
}

#[test]
fn resolve_any_returns_quad_zero() {
    assert_eq!(sample_book().resolve("any"), vec![net("0.0.0.0/0")]);
}

#[test]
fn resolve_unknown_name_returns_empty() {
    assert!(sample_book().resolve("nonexistent").is_empty());
}

#[test]
fn resolve_does_not_infinite_loop_on_cycle() {
    let mut book = sample_book();
    book.address_sets.insert(
        "cyclic".to_string(),
        AddressSet {
            name: "cyclic".to_string(),
            members: vec!["cyclic".to_string()],
        },
    );
    assert!(book.resolve("cyclic").is_empty());
}

#[test]
fn resolve_prefix_network() {
    assert_eq!(sample_book().resolve("net"), vec![net("10.0.0.0/24")]);
}

#[test]
fn all_addresses_returns_unit_and_network() {
    let mut iface = Interface {
        name: "ge-0/0/0".to_string(),
        ..Default::default()
    };
    iface.insert_unit(InterfaceUnit {
        unit_id: "0".to_string(),
        ipv4_addresses: vec![net("192.168.1.0/24")],
    });
    let pairs = iface.all_addresses();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "0");
    assert_eq!(pairs[0].1, net("192.168.1.0/24"));
}

#[test]
fn all_addresses_aggregates_multiple_units() {
    let mut iface = Interface {
        name: "lo0".to_string(),
        ..Default::default()
    };
    for (i, prefix) in ["10.0.0.1/32", "10.0.0.2/32"].iter().enumerate() {
        iface.insert_unit(InterfaceUnit {
            unit_id: i.to_string(),
            ipv4_addresses: vec![net(prefix)],
        });
    }
    assert_eq!(iface.all_addresses().len(), 2);
}

#[test]
fn all_addresses_empty_when_no_units() {
    let iface = Interface {
        name: "ge-0/0/0".to_string(),
        ..Default::default()
    };
    assert!(iface.all_addresses().is_empty());
}

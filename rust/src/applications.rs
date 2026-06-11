//! Built-in Junos application definitions used for policy matching.

use std::collections::HashMap;

use crate::models::Application;

fn app(name: &str, protocol: Option<&str>, port: Option<&str>) -> Application {
    Application {
        name: name.to_string(),
        protocol: protocol.map(str::to_string),
        dst_port: port.map(str::to_string),
    }
}

/// Map of built-in `junos-*` application names to their definitions.
pub fn junos_applications() -> HashMap<String, Application> {
    let entries = [
        ("junos-http", Some("tcp"), Some("80")),
        ("junos-https", Some("tcp"), Some("443")),
        ("junos-ssh", Some("tcp"), Some("22")),
        ("junos-telnet", Some("tcp"), Some("23")),
        ("junos-ftp", Some("tcp"), Some("21")),
        ("junos-smtp", Some("tcp"), Some("25")),
        ("junos-dns-udp", Some("udp"), Some("53")),
        ("junos-dns-tcp", Some("tcp"), Some("53")),
        ("junos-ping", Some("icmp"), None),
        ("junos-icmp-all", Some("icmp"), None),
        ("junos-ntp", Some("udp"), Some("123")),
        ("junos-snmp", Some("udp"), Some("161")),
        ("junos-syslog", Some("udp"), Some("514")),
        ("junos-bgp", Some("tcp"), Some("179")),
        ("junos-ldap", Some("tcp"), Some("389")),
        ("junos-mysql", Some("tcp"), Some("3306")),
        ("junos-rdp", Some("tcp"), Some("3389")),
        ("any", None, None),
    ];
    entries
        .into_iter()
        .map(|(name, proto, port)| (name.to_string(), app(name, proto, port)))
        .collect()
}

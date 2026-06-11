//! Tests for the analysis / query layer.

use netbat::analysis::{
    interface_ips, reachability, shadowed_rule_refs, zone_of_ip,
};
use netbat::builder::build_network_config;
use netbat::models::NetworkConfig;

const FULL_CONFIG: &str = r#"
interfaces {
    ge-0/0/0 {
        description "LAN";
        unit 0 { family inet { address 192.168.1.1/24; } }
    }
    ge-0/0/1 {
        description "WAN";
        unit 0 { family inet { address 203.0.113.1/30; } }
    }
    lo0 {
        unit 0 { family inet { address 127.0.0.1/32; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { ge-0/0/0.0; }
            address-book {
                address web-server 192.168.1.100/32;
                address db-server  192.168.1.200/32;
                address-set internal-servers {
                    address web-server;
                    address db-server;
                }
            }
        }
        security-zone untrust {
            interfaces { ge-0/0/1.0; }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-http {
                match { source-address any; destination-address any; application junos-http; }
                then { permit; }
            }
            policy allow-https {
                match { source-address any; destination-address any; application junos-https; }
                then { permit; }
            }
            policy allow-dns {
                match { source-address any; destination-address any; application junos-dns-udp; }
                then { permit; }
            }
            policy deny-rest {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
        from-zone untrust to-zone trust {
            policy allow-to-web {
                match { source-address any; destination-address web-server; application junos-http; }
                then { permit; }
            }
            policy deny-inbound {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
    }
}
"#;

fn nc() -> NetworkConfig {
    build_network_config(FULL_CONFIG)
}

// --- zone_of_ip ------------------------------------------------------------

#[test]
fn ip_in_trust_zone() {
    assert_eq!(zone_of_ip(&nc(), "192.168.1.50").unwrap().as_deref(), Some("trust"));
}

#[test]
fn ip_in_untrust_zone() {
    assert_eq!(zone_of_ip(&nc(), "203.0.113.2").unwrap().as_deref(), Some("untrust"));
}

#[test]
fn interface_ip_itself_in_trust() {
    assert_eq!(zone_of_ip(&nc(), "192.168.1.1").unwrap().as_deref(), Some("trust"));
}

#[test]
fn unknown_ip_returns_none() {
    assert_eq!(zone_of_ip(&nc(), "10.99.99.99").unwrap(), None);
}

#[test]
fn loopback_not_in_any_named_zone() {
    assert_eq!(zone_of_ip(&nc(), "127.0.0.1").unwrap(), None);
}

// --- reachability ----------------------------------------------------------

#[test]
fn http_trust_to_untrust_permitted() {
    let r = reachability(&nc(), "192.168.1.50", "203.0.113.2", "tcp", Some(80)).unwrap();
    assert_eq!(r.action, "permit");
    assert_eq!(r.from_zone.as_deref(), Some("trust"));
    assert_eq!(r.to_zone.as_deref(), Some("untrust"));
}

#[test]
fn https_trust_to_untrust_permitted() {
    let r = reachability(&nc(), "192.168.1.50", "203.0.113.2", "tcp", Some(443)).unwrap();
    assert_eq!(r.action, "permit");
}

#[test]
fn dns_udp_trust_to_untrust_permitted() {
    let r = reachability(&nc(), "192.168.1.50", "203.0.113.2", "udp", Some(53)).unwrap();
    assert_eq!(r.action, "permit");
}

#[test]
fn ssh_trust_to_untrust_denied() {
    let r = reachability(&nc(), "192.168.1.50", "203.0.113.2", "tcp", Some(22)).unwrap();
    assert_eq!(r.action, "deny");
}

#[test]
fn matching_rule_name_returned() {
    let r = reachability(&nc(), "192.168.1.50", "203.0.113.2", "tcp", Some(80)).unwrap();
    assert_eq!(r.matching_rule.map(|m| m.name), Some("allow-http".to_string()));
}

#[test]
fn http_untrust_to_web_server_permitted() {
    let r = reachability(&nc(), "203.0.113.2", "192.168.1.100", "tcp", Some(80)).unwrap();
    assert_eq!(r.action, "permit");
}

#[test]
fn http_untrust_to_db_server_denied() {
    let r = reachability(&nc(), "203.0.113.2", "192.168.1.200", "tcp", Some(80)).unwrap();
    assert_eq!(r.action, "deny");
}

#[test]
fn no_policy_returns_deny() {
    let r = reachability(&nc(), "203.0.113.2", "192.168.1.200", "tcp", Some(443)).unwrap();
    assert_eq!(r.action, "deny");
}

#[test]
fn unknown_src_zone_returns_unknown() {
    let r = reachability(&nc(), "10.99.99.1", "203.0.113.2", "tcp", Some(80)).unwrap();
    assert_eq!(r.action, "unknown");
}

#[test]
fn unknown_dst_zone_returns_unknown() {
    let r = reachability(&nc(), "192.168.1.50", "10.99.99.1", "tcp", Some(80)).unwrap();
    assert_eq!(r.action, "unknown");
}

#[test]
fn same_zone_traffic_returns_permit() {
    let r = reachability(&nc(), "192.168.1.10", "192.168.1.20", "tcp", Some(80)).unwrap();
    assert_eq!(r.action, "permit");
}

// --- shadowed_rules --------------------------------------------------------

#[test]
fn rule_after_catchall_deny_is_shadowed() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy catch-all {
                    match { source-address any; destination-address any; application any; }
                    then { deny; }
                }
                policy never-matches {
                    match { source-address any; destination-address any; application junos-http; }
                    then { permit; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let names: Vec<_> = shadowed_rule_refs(&nc).iter().map(|(_, r)| r.name.clone()).collect();
    assert!(names.contains(&"never-matches".to_string()));
    assert!(!names.contains(&"catch-all".to_string()));
}

#[test]
fn rule_after_catchall_permit_is_shadowed() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy permit-all {
                    match { source-address any; destination-address any; application any; }
                    then { permit; }
                }
                policy unreachable {
                    match { source-address any; destination-address any; application junos-ssh; }
                    then { deny; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let names: Vec<_> = shadowed_rule_refs(&nc).iter().map(|(_, r)| r.name.clone()).collect();
    assert!(names.contains(&"unreachable".to_string()));
}

#[test]
fn no_shadowed_rules_in_normal_policy() {
    assert!(shadowed_rule_refs(&nc()).is_empty());
}

#[test]
fn returns_policy_alongside_rule() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy any-permit {
                    match { source-address any; destination-address any; application any; }
                    then { permit; }
                }
                policy shadowed {
                    match { source-address any; destination-address any; application junos-http; }
                    then { deny; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let refs = shadowed_rule_refs(&nc);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].0.from_zone, "trust");
    assert_eq!(refs[0].1.name, "shadowed");
}

// --- interface_ips ---------------------------------------------------------

#[test]
fn returns_all_configured_addresses() {
    let prefixes: Vec<_> = interface_ips(&nc())
        .iter()
        .map(|(_, _, net)| net.to_string())
        .collect();
    assert!(prefixes.contains(&"192.168.1.0/24".to_string()));
    assert!(prefixes.contains(&"203.0.113.0/30".to_string()));
    assert!(prefixes.contains(&"127.0.0.1/32".to_string()));
}

#[test]
fn returns_interface_and_unit_names() {
    let names: Vec<_> = interface_ips(&nc()).iter().map(|(i, _, _)| i.clone()).collect();
    assert!(names.contains(&"ge-0/0/0".to_string()));
    assert!(names.contains(&"ge-0/0/1".to_string()));
}

#[test]
fn empty_when_no_interfaces() {
    let nc = build_network_config("");
    assert!(interface_ips(&nc).is_empty());
}

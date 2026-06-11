//! Tests for the config builder (AST -> domain model).

use netbat::builder::build_network_config;
use netbat::ipv4::Ipv4Network;

fn net(s: &str) -> Ipv4Network {
    Ipv4Network::parse(s).unwrap()
}

// --- interfaces ------------------------------------------------------------

#[test]
fn single_interface_single_ip() {
    let config = r#"
    interfaces {
        ge-0/0/0 { unit 0 { family inet { address 192.168.1.1/24; } } }
    }
    "#;
    let nc = build_network_config(config);
    assert!(nc.interfaces.contains_key("ge-0/0/0"));
    let unit = &nc.interfaces["ge-0/0/0"].units["0"];
    assert!(unit.ipv4_addresses.contains(&net("192.168.1.0/24")));
}

#[test]
fn interface_description_quoted() {
    let config = r#"
    interfaces {
        ge-0/0/0 {
            description "LAN interface";
            unit 0 { family inet { address 10.0.0.1/30; } }
        }
    }
    "#;
    let nc = build_network_config(config);
    assert_eq!(
        nc.interfaces["ge-0/0/0"].description.as_deref(),
        Some("LAN interface")
    );
}

#[test]
fn multiple_interfaces_parsed() {
    let config = r#"
    interfaces {
        ge-0/0/0 { unit 0 { family inet { address 192.168.1.1/24; } } }
        ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/30; } } }
    }
    "#;
    let nc = build_network_config(config);
    assert!(nc.interfaces.contains_key("ge-0/0/0"));
    assert!(nc.interfaces.contains_key("ge-0/0/1"));
}

#[test]
fn multiple_addresses_on_same_unit() {
    let config = r#"
    interfaces {
        ge-0/0/0 {
            unit 0 { family inet { address 192.168.1.1/24; address 10.0.0.1/30; } }
        }
    }
    "#;
    let nc = build_network_config(config);
    assert_eq!(nc.interfaces["ge-0/0/0"].units["0"].ipv4_addresses.len(), 2);
}

#[test]
fn no_interfaces_section() {
    let nc = build_network_config("security { }");
    assert!(nc.interfaces.is_empty());
}

// --- security zones --------------------------------------------------------

#[test]
fn zone_has_correct_name_and_membership() {
    let config = r#"
    security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
    "#;
    let nc = build_network_config(config);
    assert!(nc.security_zones.contains_key("trust"));
    assert!(nc.security_zones["trust"]
        .interfaces
        .contains(&"ge-0/0/0.0".to_string()));
}

#[test]
fn zone_address_book_addresses() {
    let config = r#"
    security {
        zones {
            security-zone trust {
                address-book { address web-server 192.168.1.100/32; }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let book = &nc.security_zones["trust"].address_book;
    assert!(book.addresses.contains_key("web-server"));
    assert_eq!(book.addresses["web-server"].prefix, net("192.168.1.100/32"));
}

#[test]
fn zone_address_book_address_sets() {
    let config = r#"
    security {
        zones {
            security-zone trust {
                address-book {
                    address web 192.168.1.100/32;
                    address db  192.168.1.200/32;
                    address-set servers { address web; address db; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let book = &nc.security_zones["trust"].address_book;
    assert!(book.address_sets.contains_key("servers"));
    let members = &book.address_sets["servers"].members;
    assert!(members.contains(&"web".to_string()));
    assert!(members.contains(&"db".to_string()));
}

// --- security policies -----------------------------------------------------

#[test]
fn permit_rule_parsed() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy allow-web {
                    match { source-address any; destination-address any; application junos-http; }
                    then { permit; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    assert_eq!(nc.security_policies.len(), 1);
    let sp = &nc.security_policies[0];
    assert_eq!(sp.from_zone, "trust");
    assert_eq!(sp.to_zone, "untrust");
    assert_eq!(sp.rules.len(), 1);
    assert_eq!(sp.rules[0].name, "allow-web");
    assert_eq!(sp.rules[0].action, "permit");
}

#[test]
fn deny_rule_parsed() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy deny-all {
                    match { source-address any; destination-address any; application any; }
                    then { deny; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    assert_eq!(nc.security_policies[0].rules[0].action, "deny");
}

#[test]
fn match_source_and_destination_addresses() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy test {
                    match { source-address src-addr; destination-address dst-addr; application any; }
                    then { permit; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let m = &nc.security_policies[0].rules[0].r#match;
    assert!(m.source_addresses.contains(&"src-addr".to_string()));
    assert!(m.destination_addresses.contains(&"dst-addr".to_string()));
}

#[test]
fn bracketed_application_list() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy allow-web {
                    match { source-address any; destination-address any; application [junos-http junos-https]; }
                    then { permit; }
                }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let apps = &nc.security_policies[0].rules[0].r#match.applications;
    assert!(apps.contains(&"junos-http".to_string()));
    assert!(apps.contains(&"junos-https".to_string()));
}

#[test]
fn multiple_rules_preserve_order() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy first  { match { source-address any; destination-address any; application junos-http;  } then { permit; } }
                policy second { match { source-address any; destination-address any; application junos-https; } then { permit; } }
                policy last   { match { source-address any; destination-address any; application any;         } then { deny;   } }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    let names: Vec<_> = nc.security_policies[0]
        .rules
        .iter()
        .map(|r| r.name.clone())
        .collect();
    assert_eq!(names, vec!["first", "second", "last"]);
}

#[test]
fn multiple_policy_directions() {
    let config = r#"
    security {
        policies {
            from-zone trust to-zone untrust {
                policy outbound { match { source-address any; destination-address any; application any; } then { permit; } }
            }
            from-zone untrust to-zone trust {
                policy inbound  { match { source-address any; destination-address any; application any; } then { deny;   } }
            }
        }
    }
    "#;
    let nc = build_network_config(config);
    assert_eq!(nc.security_policies.len(), 2);
    let dirs: Vec<_> = nc
        .security_policies
        .iter()
        .map(|sp| (sp.from_zone.clone(), sp.to_zone.clone()))
        .collect();
    assert!(dirs.contains(&("trust".to_string(), "untrust".to_string())));
    assert!(dirs.contains(&("untrust".to_string(), "trust".to_string())));
}

// --- applications ----------------------------------------------------------

#[test]
fn custom_application_parsed() {
    let config = r#"
    applications {
        application custom-app { protocol tcp; destination-port 8080; }
    }
    "#;
    let nc = build_network_config(config);
    assert!(nc.applications.contains_key("custom-app"));
    let app = &nc.applications["custom-app"];
    assert_eq!(app.protocol.as_deref(), Some("tcp"));
    assert_eq!(app.dst_port.as_deref(), Some("8080"));
}

#[test]
fn application_set_parsed() {
    let config = r#"
    applications {
        application-set web-apps { application junos-http; application junos-https; }
    }
    "#;
    let nc = build_network_config(config);
    assert!(nc.application_sets.contains_key("web-apps"));
    let members = &nc.application_sets["web-apps"].members;
    assert!(members.contains(&"junos-http".to_string()));
    assert!(members.contains(&"junos-https".to_string()));
}

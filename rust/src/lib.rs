//! netbat — pure-Rust Juniper firewall configuration analysis.
//!
//! A dependency-free port of the Python `netbat` tool: parse JunOS
//! hierarchical configs and answer reachability, zone-membership, and
//! policy-correctness questions.

pub mod analysis;
pub mod applications;
pub mod builder;
pub mod ipv4;
pub mod models;
pub mod parser;

pub use analysis::{
    interface_ips, reachability, shadowed_rule_refs, shadowed_rules, zone_of_ip,
    ReachabilityResult,
};
pub use builder::build_network_config;
pub use ipv4::{Ipv4Addr, Ipv4Network};
pub use models::NetworkConfig;

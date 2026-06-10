//! Command-line interface for netbat.

use std::process::ExitCode;

use netbat::analysis::{interface_ips, reachability, shadowed_rule_refs, zone_of_ip};
use netbat::builder::build_network_config;
use netbat::models::NetworkConfig;

const USAGE: &str = "\
usage: netbat <command> [args]

commands:
  reachability CONFIG SRC DST [--protocol PROTO] [--port PORT] [--json]
  zone-of      CONFIG IP                                       [--json]
  shadowed     CONFIG                                          [--json]
  interfaces   CONFIG                                          [--json]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = match args.first() {
        Some(c) => c.as_str(),
        None => return Err(format!("error: missing command\n\n{USAGE}")),
    };
    let rest = &args[1..];

    match command {
        "reachability" => cmd_reachability(rest),
        "zone-of" => cmd_zone_of(rest),
        "shadowed" => cmd_shadowed(rest),
        "interfaces" => cmd_interfaces(rest),
        "-h" | "--help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("error: unknown command: {other}\n\n{USAGE}")),
    }
}

// ---------------------------------------------------------------------------
// Argument parsing helpers
// ---------------------------------------------------------------------------

struct ParsedArgs {
    positionals: Vec<String>,
    json: bool,
    protocol: String,
    port: Option<u16>,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    let mut positionals = Vec::new();
    let mut json = false;
    let mut protocol = "tcp".to_string();
    let mut port = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--protocol" => {
                i += 1;
                protocol = args
                    .get(i)
                    .ok_or("error: --protocol requires a value")?
                    .clone();
            }
            "--port" => {
                i += 1;
                let raw = args.get(i).ok_or("error: --port requires a value")?;
                port = Some(
                    raw.parse::<u16>()
                        .map_err(|_| format!("error: invalid port: {raw}"))?,
                );
            }
            other => positionals.push(other.to_string()),
        }
        i += 1;
    }

    Ok(ParsedArgs {
        positionals,
        json,
        protocol,
        port,
    })
}

fn load(path: &str) -> Result<NetworkConfig, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(build_network_config(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("error: config file not found: {path}"))
        }
        Err(e) => Err(format!("error: failed to read config: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Minimal JSON serialization (string escaping + nullable strings)
// ---------------------------------------------------------------------------

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt(s: Option<&str>) -> String {
    match s {
        Some(v) => json_str(v),
        None => "null".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_reachability(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args)?;
    if parsed.positionals.len() < 3 {
        return Err("error: reachability requires CONFIG SRC DST".to_string());
    }
    let nc = load(&parsed.positionals[0])?;
    let result = reachability(
        &nc,
        &parsed.positionals[1],
        &parsed.positionals[2],
        &parsed.protocol,
        parsed.port,
    )
    .map_err(|e| format!("error: {e}"))?;

    let rule_name = result.matching_rule.as_ref().map(|r| r.name.as_str());

    if parsed.json {
        println!(
            "{{\"action\": {}, \"from_zone\": {}, \"to_zone\": {}, \"matching_rule\": {}}}",
            json_str(&result.action),
            json_opt(result.from_zone.as_deref()),
            json_opt(result.to_zone.as_deref()),
            json_opt(rule_name),
        );
    } else {
        println!("Action:  {}", result.action.to_uppercase());
        if let Some(z) = &result.from_zone {
            println!("From:    {z}");
        }
        if let Some(z) = &result.to_zone {
            println!("To:      {z}");
        }
        if let Some(name) = rule_name {
            println!("Rule:    {name}");
        }
    }
    Ok(())
}

fn cmd_zone_of(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args)?;
    if parsed.positionals.len() < 2 {
        return Err("error: zone-of requires CONFIG IP".to_string());
    }
    let nc = load(&parsed.positionals[0])?;
    let ip = &parsed.positionals[1];
    let zone = zone_of_ip(&nc, ip).map_err(|e| format!("error: {e}"))?;

    if parsed.json {
        println!(
            "{{\"ip\": {}, \"zone\": {}}}",
            json_str(ip),
            json_opt(zone.as_deref())
        );
    } else {
        match zone {
            Some(z) => println!("{z}"),
            None => println!("(not in any zone)"),
        }
    }
    Ok(())
}

fn cmd_shadowed(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args)?;
    if parsed.positionals.is_empty() {
        return Err("error: shadowed requires CONFIG".to_string());
    }
    let nc = load(&parsed.positionals[0])?;
    let results = shadowed_rule_refs(&nc);

    if parsed.json {
        let items: Vec<String> = results
            .iter()
            .map(|(sp, r)| {
                format!(
                    "{{\"from_zone\": {}, \"to_zone\": {}, \"rule\": {}}}",
                    json_str(&sp.from_zone),
                    json_str(&sp.to_zone),
                    json_str(&r.name)
                )
            })
            .collect();
        println!("[{}]", items.join(", "));
    } else if results.is_empty() {
        println!("No shadowed rules found.");
    } else {
        for (sp, rule) in &results {
            println!(
                "{} \u{2192} {}: rule '{}' is shadowed",
                sp.from_zone, sp.to_zone, rule.name
            );
        }
    }
    Ok(())
}

fn cmd_interfaces(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args)?;
    if parsed.positionals.is_empty() {
        return Err("error: interfaces requires CONFIG".to_string());
    }
    let nc = load(&parsed.positionals[0])?;
    let ips = interface_ips(&nc);

    if parsed.json {
        let items: Vec<String> = ips
            .iter()
            .map(|(iface, unit, net)| {
                format!(
                    "{{\"interface\": {}, \"unit\": {}, \"network\": {}}}",
                    json_str(iface),
                    json_str(unit),
                    json_str(&net.to_string())
                )
            })
            .collect();
        println!("[{}]", items.join(", "));
    } else if ips.is_empty() {
        println!("No interfaces configured.");
    } else {
        for (iface, unit, net) in &ips {
            println!("{iface}.{unit:<4}  {net}");
        }
    }
    Ok(())
}

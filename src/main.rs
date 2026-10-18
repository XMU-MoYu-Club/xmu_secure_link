mod api;
mod config;
mod crypto;
mod ovpn3;
mod state;

use anyhow::{Result, anyhow};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=======================================================");
    println!("  XMU SecureLink VPN");
    let platform = ovpn3::platform();
    if !platform.is_empty() {
        println!("  {platform}");
    }
    println!("=======================================================");

    warn_if_not_privileged();

    let data_dir = state::data_dir()?;
    let mut api = api::SecureLinkApi::new(&data_dir)?;

    // Session refresh, or interactive SSO (browser + pasted callback URL).
    api.login(None).await?;

    let vpn_config = api.get_vpn_config().await?;
    if api::return_code(&vpn_config) != 1 {
        return Err(anyhow!(
            "get_vpn_config failed: {}",
            vpn_config.get("returnMsg").unwrap_or(&vpn_config)
        ));
    }

    let generated = config::generate(&mut api, &vpn_config)?;
    println!(
        "Remotes: {}",
        generated
            .remotes
            .iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let (vpn, mut rx) = ovpn3::Vpn::new()?;
    vpn.prepare(
        &generated.profile,
        &generated.username,
        &generated.password,
        &generated.peer_info,
    )?;

    // connect() blocks until the session ends; run it off the async runtime.
    let handle = vpn.handle();
    let mut connect = tokio::task::spawn_blocking(move || ovpn3::run_connect(handle));

    println!("Connecting... (press Ctrl-C to disconnect)");
    let mut stopping = false;
    // SecureLink pushes its split-tunnel ACL as `app` options (which OpenVPN3
    // ignores), not as routes. Collect those destinations from the log stream
    // and install host routes for them once the interface is up.
    let mut app_routes: Vec<String> = Vec::new();
    // (interface index, CIDRs we installed) — used to tear them down on exit.
    let mut installed_routes: Option<(String, Vec<String>)> = None;
    let outcome = loop {
        tokio::select! {
            // The blocking connect() finished (clean exit or error) — report it.
            res = &mut connect => break res,
            msg = rx.recv() => match msg {
                Some(ovpn3::Msg::Log(line)) => {
                    for physical in line.split('\n') {
                        // Both the ACL destinations and the pushed DNS servers must
                        // be reachable through the tunnel: the resolver is pointed
                        // at them, so a missing DNS route sends every lookup to the
                        // default gateway (times out off-campus).
                        if let Some(cidr) =
                            parse_app_route(physical).or_else(|| parse_dns_server(physical))
                        {
                            app_routes.push(cidr);
                        }
                    }
                    println!("[ovpn] {line}");
                }
                Some(ovpn3::Msg::Event(ev)) => {
                    if ev.info.is_empty() {
                        println!("[event] {}", ev.name);
                    } else {
                        println!("[event] {} {}", ev.name, ev.info);
                    }
                    match ev.name.as_str() {
                        "CONNECTED" => {
                            println!(">> VPN connected");
                            match parse_connected_info(&ev.info) {
                                Some((if_index, gateway)) => {
                                    let cidrs =
                                        install_app_routes(&app_routes, &if_index, &gateway);
                                    installed_routes = Some((if_index, cidrs));
                                }
                                None => println!(
                                    "[route] could not parse interface/gateway from CONNECTED \
                                     info; split-tunnel routes not installed"
                                ),
                            }
                            // In debug builds, prove the tunnel actually routes
                            // traffic by reaching intranet-only hosts unreachable
                            // off-VPN. Disabled in release.
                            #[cfg(debug_assertions)]
                            {
                                tokio::spawn(probe_ftp());
                                tokio::spawn(probe_ssh());
                            }
                        }
                        _ if ev.fatal => {
                            eprintln!(">> fatal: {} {}", ev.name, ev.info);
                            vpn.stop();
                            stopping = true;
                        }
                        _ => {}
                    }
                }
                // Channel only closes when the client is dropped; ignore until
                // the connect task itself completes.
                None => {}
            },
            _ = tokio::signal::ctrl_c(), if !stopping => {
                println!("\nDisconnecting...");
                vpn.stop();
                stopping = true;
            }
        }
    };

    // Drain any log/event lines the worker emitted just before exiting.
    while let Ok(msg) = rx.try_recv() {
        match msg {
            ovpn3::Msg::Log(line) => println!("[ovpn] {line}"),
            ovpn3::Msg::Event(ev) => println!("[event] {} {}", ev.name, ev.info),
        }
    }

    // Tear down the split-tunnel routes we added. (The DCO interface teardown
    // also drops them, but remove explicitly so nothing lingers on early exit.)
    if let Some((if_index, cidrs)) = installed_routes {
        remove_app_routes(&if_index, &cidrs);
    }

    match outcome {
        Ok(Ok(())) => println!("VPN disconnected"),
        Ok(Err(err)) => return Err(err),
        Err(join_err) => return Err(anyhow!("connect task panicked: {join_err}")),
    }
    Ok(())
}

/// Extract the destination CIDR from a SecureLink `app` ACL log line, e.g.
/// `129 [app] [[addr:121.192.180.236/32][proto:any] [port:21]]` -> `121.192.180.236/32`.
fn parse_app_route(line: &str) -> Option<String> {
    if !line.contains("[app]") {
        return None;
    }
    let after = line.split("[addr:").nth(1)?;
    let cidr = after.split(']').next()?.trim();
    let (ip, _prefix) = cidr.split_once('/')?;
    if ip.split('.').count() == 4 && ip.split('.').all(|o| o.parse::<u8>().is_ok()) {
        Some(cidr.to_string())
    } else {
        None
    }
}

/// Extract a pushed DNS server from a `dhcp-option DNS` log line, e.g.
/// `0 [dhcp-option] [DNS] [210.34.0.18]` -> `210.34.0.18/32`.
///
/// SecureLink's DNS servers live inside the intranet, and OpenVPN3 points the
/// OS resolver at them. The split-tunnel route set only covered the `app` ACL,
/// so off-campus every lookup left through the default gateway and timed out.
/// Returning them as /32 destinations gives them a tunnel route, and they are
/// torn down together with the ACL routes on exit.
fn parse_dns_server(line: &str) -> Option<String> {
    if !line.contains("[dhcp-option]") {
        return None;
    }
    let idx = line.find("[DNS]")?;
    let rest = line[idx + "[DNS]".len()..].trim_start();
    let ip = rest.strip_prefix('[')?.split(']').next()?.trim();
    if ip.split('.').count() == 4 && ip.split('.').all(|o| o.parse::<u8>().is_ok()) {
        Some(format!("{ip}/32"))
    } else {
        None
    }
}

/// Pull the VPN interface index and gateway out of the CONNECTED event info,
/// e.g. `... gw=[172.18.80.1/] ... vpn_interface_index=11`.
fn parse_connected_info(info: &str) -> Option<(String, String)> {
    let if_index = info
        .split("vpn_interface_index=")
        .nth(1)?
        .split_whitespace()
        .next()?
        .trim()
        .to_string();
    let gateway = info
        .split("gw=[")
        .nth(1)?
        .split(['/', ']'])
        .next()?
        .trim()
        .to_string();
    if if_index.is_empty() || gateway.is_empty() {
        return None;
    }
    Some((if_index, gateway))
}

/// Install host routes for the SecureLink split-tunnel destinations through the
/// VPN interface so matching traffic is forwarded into the tunnel. Returns the
/// deduplicated CIDRs that were processed (for later teardown). Needs the
/// privileges the data plane already requires; failures (e.g. route exists) are
/// non-fatal.
fn install_app_routes(routes: &[String], if_index: &str, gateway: &str) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let unique: Vec<String> = routes
        .iter()
        .filter(|c| seen.insert((*c).clone()))
        .cloned()
        .collect();

    println!(
        "[route] installing {} split-tunnel route(s) via interface {if_index} (nexthop {gateway})",
        unique.len()
    );

    let (mut added, mut existed, mut failed) = (0usize, 0usize, 0usize);
    for cidr in &unique {
        #[cfg(target_os = "windows")]
        {
            let out = std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    &format!("prefix={cidr}"),
                    &format!("interface={if_index}"),
                    &format!("nexthop={gateway}"),
                    "store=active",
                ])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    added += 1;
                    println!("[route]   + {cidr} -> if{if_index}");
                }
                Ok(o) => {
                    let detail = netsh_message(&o);
                    // netsh returns failure when the route already exists; treat
                    // that as benign and surface anything else.
                    if detail.contains("already exists") || detail.contains("已经存在") {
                        existed += 1;
                        println!("[route]   = {cidr} (already present)");
                    } else {
                        failed += 1;
                        eprintln!("[route]   ! {cidr}: {detail}");
                    }
                }
                Err(e) => {
                    failed += 1;
                    eprintln!("[route]   ! {cidr}: failed to run netsh: {e}");
                }
            }
        }
        #[cfg(all(unix, not(target_os = "windows")))]
        {
            // Route installation is platform-specific; not yet implemented for non-Windows.
            let _ = (cidr, if_index, gateway);
        }
    }

    println!(
        "[route] done: {added} added, {existed} already present, {failed} failed (of {} total)",
        unique.len()
    );
    unique
}

/// Remove the split-tunnel routes installed by [`install_app_routes`].
fn remove_app_routes(if_index: &str, cidrs: &[String]) {
    if cidrs.is_empty() {
        return;
    }
    println!("[route] removing {} split-tunnel route(s) on exit...", cidrs.len());
    let mut removed = 0usize;
    for cidr in cidrs {
        #[cfg(target_os = "windows")]
        {
            let ok = std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    &format!("prefix={cidr}"),
                    &format!("interface={if_index}"),
                    "store=active",
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                removed += 1;
            }
        }
        #[cfg(all(unix, not(target_os = "windows")))]
        {
            let _ = (cidr, if_index);
        }
    }
    println!("[route] removed {removed}/{} route(s)", cidrs.len());
}

/// Combine netsh stdout/stderr into a single trimmed message for diagnostics.
#[cfg(target_os = "windows")]
fn netsh_message(out: &std::process::Output) -> String {
    let mut msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if msg.is_empty() {
        msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
    }
    if msg.is_empty() {
        msg = format!("netsh exited with {}", out.status);
    }
    msg
}

/// Connect to an intranet-only FTP host and attempt a login. Reachable only if
/// VPN traffic is actually routed through the tunnel (the host is not exposed to
/// the public internet), so this is a real end-to-end routing check.
#[cfg(debug_assertions)]
async fn probe_ftp() {
    const ADDR: &str = "121.192.180.236:21";
    println!("[ftp-probe] testing intranet FTP {ADDR} through the tunnel...");
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        ftp_login_probe(ADDR, "student", "ILoveSoftware!"),
    )
    .await
    {
        Ok(Ok(message)) => println!(">> FTP probe SUCCESS (tunnel routes traffic): {message}"),
        Ok(Err(err)) => println!(">> FTP probe FAILED: {err}"),
        Err(_) => println!(
            ">> FTP probe FAILED: timeout (tunnel up but traffic not routed — \
             run elevated so routes install)"
        ),
    }
}

/// Connect to an intranet-only SSH host and read its banner. Like the FTP
/// probe, this only succeeds if traffic is routed through the tunnel.
#[cfg(debug_assertions)]
async fn probe_ssh() {
    const ADDR: &str = "59.77.5.59:2222";
    println!("[ssh-probe] testing intranet SSH {ADDR} through the tunnel...");
    match tokio::time::timeout(std::time::Duration::from_secs(15), ssh_banner_probe(ADDR)).await {
        Ok(Ok(banner)) => println!(">> SSH probe SUCCESS (tunnel routes traffic): {banner}"),
        Ok(Err(err)) => println!(">> SSH probe FAILED: {err}"),
        Err(_) => println!(">> SSH probe FAILED: timeout (host not routed through tunnel)"),
    }
}

#[cfg(debug_assertions)]
async fn ssh_banner_probe(addr: &str) -> Result<String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpStream;

    let mut reader = BufReader::new(TcpStream::connect(addr).await?);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let line = line.trim().to_string();
    if !line.starts_with("SSH-") {
        return Err(anyhow!("unexpected SSH banner: {line}"));
    }
    Ok(line)
}

#[cfg(debug_assertions)]
async fn ftp_login_probe(addr: &str, username: &str, password: &str) -> Result<String> {
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let mut reader = BufReader::new(TcpStream::connect(addr).await?);
    let greeting = read_ftp_response(&mut reader).await?;
    if !greeting.starts_with("220") {
        return Err(anyhow!("unexpected FTP greeting: {greeting}"));
    }

    reader
        .get_mut()
        .write_all(format!("USER {username}\r\n").as_bytes())
        .await?;
    let user_resp = read_ftp_response(&mut reader).await?;
    if !(user_resp.starts_with("331") || user_resp.starts_with("230")) {
        return Err(anyhow!("USER rejected: {user_resp}"));
    }

    if user_resp.starts_with("331") {
        reader
            .get_mut()
            .write_all(format!("PASS {password}\r\n").as_bytes())
            .await?;
        let pass_resp = read_ftp_response(&mut reader).await?;
        if !pass_resp.starts_with("230") {
            return Err(anyhow!("PASS rejected: {pass_resp}"));
        }
        return Ok(pass_resp);
    }

    Ok(user_resp)
}

#[cfg(debug_assertions)]
async fn read_ftp_response<R>(reader: &mut tokio::io::BufReader<R>) -> Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    if line.len() < 4 {
        return Ok(line.trim().to_string());
    }
    let code = line[..3].to_string();
    let mut last = line.trim().to_string();
    if line.as_bytes().get(3) == Some(&b'-') {
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            last = line.trim().to_string();
            if line.starts_with(&code) && line.as_bytes().get(3) == Some(&b' ') {
                break;
            }
        }
    }
    Ok(last)
}

/// OpenVPN3 configures the OS tun adapter and routes directly in-process, which
/// needs elevated privileges. Warn early instead of failing deep in connect().
fn warn_if_not_privileged() {
    #[cfg(target_os = "windows")]
    {
        if !is_elevated_windows() {
            println!(
                "[warn] Not running as Administrator. The VPN tunnel needs elevation; \
                 re-run from an elevated terminal if connect fails."
            );
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: getuid is always safe to call.
        let uid = unsafe { libc_getuid() };
        if uid != 0 {
            println!("[warn] Not running as root. The VPN tunnel needs root privileges.");
        }
    }
}

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    // Best-effort: a writable handle to the physical drive only succeeds elevated.
    // Avoid extra crates by probing a privileged path via std.
    std::fs::OpenOptions::new()
        .write(true)
        .open(r"\\.\PHYSICALDRIVE0")
        .is_ok()
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_server_accepts_pushed_dns() {
        assert_eq!(
            parse_dns_server("0 [dhcp-option] [DNS] [210.34.0.18]").as_deref(),
            Some("210.34.0.18/32")
        );
        assert_eq!(
            parse_dns_server("1 [dhcp-option] [DNS] [210.34.0.14]").as_deref(),
            Some("210.34.0.14/32")
        );
    }

    #[test]
    fn parse_dns_server_ignores_unrelated_lines() {
        // ACL / topology / domain / ctrl lines must not be picked up here
        assert_eq!(
            parse_dns_server("129 [app] [[addr:121.192.180.236/32][proto:any] [port:21]]"),
            None
        );
        assert_eq!(parse_dns_server("3 [topology] [subnet]"), None);
        assert_eq!(parse_dns_server("0 [dhcp-option] [DOMAIN] [xmu.edu.cn]"), None);
        assert_eq!(
            parse_dns_server("183 [ctrl] [[domain:xk.xmu.edu.cn][sourceIp:219.229.81.200]]"),
            None
        );
    }

    #[test]
    fn parse_dns_server_rejects_invalid_addresses() {
        assert_eq!(parse_dns_server("0 [dhcp-option] [DNS] [abc.def]"), None);
        assert_eq!(parse_dns_server("0 [dhcp-option] [DNS]"), None);
        assert_eq!(parse_dns_server("0 [dhcp-option] [DNS] [1.2.3]"), None);
        assert_eq!(parse_dns_server("0 [dhcp-option] [DNS] [999.1.1.1]"), None);
        assert_eq!(parse_dns_server(""), None);
    }

    #[test]
    fn parse_dns_server_accepts_public_resolver_known_tradeoff() {
        // Documented trade-off: a public resolver is also routed through the
        // tunnel. Current SecureLink only pushes intranet resolvers.
        assert_eq!(
            parse_dns_server("0 [dhcp-option] [DNS] [8.8.8.8]").as_deref(),
            Some("8.8.8.8/32")
        );
    }

    #[test]
    fn acl_lines_still_go_through_parse_app_route() {
        let acl = "129 [app] [[addr:121.192.180.236/32][proto:any] [port:21]]";
        assert_eq!(parse_app_route(acl).as_deref(), Some("121.192.180.236/32"));
        assert_eq!(parse_dns_server(acl), None);
    }
}

//! Rust proxy node.
//!
//! A single-binary proxy server (std-only, no external crates) that speaks
//! two protocols on the same TCP port:
//!
//! * SOCKS5 (RFC 1928) — no-auth (0x00) and username/password (0x02,
//!   RFC 1929), CMD CONNECT (0x01) and UDP ASSOCIATE (0x03). BIND (0x02)
//!   is rejected with REP 0x07 (command not supported).
//! * HTTP CONNECT (RFC 7231, RFC 9110 §9.3.6) — `CONNECT host:port
//!   HTTP/1.1`, with optional `Proxy-Authorization: Basic ...`.
//!
//! Protocol detection: the first byte of a new connection is 0x05 for
//! SOCKS5, otherwise the connection is treated as HTTP (it must start
//! with `CONNECT `).
//!
//! Configuration (CLI wins over environment variables):
//! ```text
//!   --addr 127.0.0.1:1080   (or PROXY_ADDR)
//!   --port 1080             (or PROXY_PORT; overrides the port in --addr)
//!   --user alice            (or PROXY_USER)
//!   --pass secret           (or PROXY_PASS)
//!   --help
//! ```
//! If `--user`/`--pass` (or the env vars) are set, both SOCKS5 and HTTP
//! require that username/password. Otherwise no authentication is needed.
//!
//! CulvertProxy compatibility: CulvertProxy (Windows 11 WinUI3 client)
//! can use this node as an upstream SOCKS5 or HTTP CONNECT server —
//! see README.md. This Linux build cannot run the Windows client itself.

use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Config {
    addr: String,
    auth: Option<(String, String)>,
}

impl Config {
    fn from_args() -> Config {
        let mut addr = env::var("PROXY_ADDR").unwrap_or_else(|_| "127.0.0.1:1080".to_string());
        if let Ok(p) = env::var("PROXY_PORT") {
            let host = addr.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| "127.0.0.1".to_string());
            addr = format!("{}:{}", host, p);
        }
        let mut user = env::var("PROXY_USER").ok();
        let mut pass = env::var("PROXY_PASS").ok();

        let args: Vec<String> = env::args().skip(1).collect();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                "--addr" => {
                    i += 1;
                    if let Some(v) = args.get(i) {
                        addr = v.clone();
                    }
                }
                "--port" => {
                    i += 1;
                    if let Some(p) = args.get(i) {
                        let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("127.0.0.1");
                        addr = format!("{}:{}", host, p);
                    }
                }
                "--user" => {
                    i += 1;
                    user = args.get(i).cloned();
                }
                "--pass" => {
                    i += 1;
                    pass = args.get(i).cloned();
                }
                other if other.starts_with("--addr=") => addr = other["--addr=".len()..].to_string(),
                other if other.starts_with("--port=") => {
                    let p = &other["--port=".len()..];
                    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("127.0.0.1");
                    addr = format!("{}:{}", host, p);
                }
                other if other.starts_with("--user=") => user = Some(other["--user=".len()..].to_string()),
                other if other.starts_with("--pass=") => pass = Some(other["--pass=".len()..].to_string()),
                other => {
                    eprintln!("unknown argument: {}", other);
                    print_help();
                    std::process::exit(2);
                }
            }
            i += 1;
        }

        let auth = match (user, pass) {
            (Some(u), Some(p)) => Some((u, p)),
            (Some(_), None) | (None, Some(_)) => {
                eprintln!("error: --user and --pass must be given together");
                std::process::exit(2);
            }
            (None, None) => None,
        };

        Config { addr, auth }
    }
}

fn print_help() {
    println!("rust-proxy-node 0.1.0 — SOCKS5 + HTTP CONNECT proxy (std-only)");
    println!();
    println!("USAGE: rust-proxy-node [--addr 127.0.0.1:1080] [--port 1080] [--user NAME --pass PASS]");
    println!();
    println!("ENV: PROXY_ADDR, PROXY_PORT, PROXY_USER, PROXY_PASS (CLI wins)");
    println!("Default listen address: 127.0.0.1:1080, no authentication.");
}

// ---------------------------------------------------------------------------
// Small helpers (pure, unit-tested)
// ---------------------------------------------------------------------------

/// Decode standard Base64 (with optional padding). Returns None on bad input.
/// Used for `Proxy-Authorization: Basic <base64(user:pass)>`.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut vals: Vec<u8> = Vec::with_capacity(input.len());
    for c in input.chars() {
        let v = match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '+' => 62,
            '/' => 63,
            '=' => break,
            _ => return None,
        };
        vals.push(v);
    }
    let mut out = Vec::with_capacity(vals.len() * 6 / 8);
    for chunk in vals.chunks(4) {
        let mut acc: u32 = 0;
        for (j, &v) in chunk.iter().enumerate() {
            acc |= (v as u32) << (18 - 6 * j);
        }
        let nbytes = match chunk.len() {
            2 => 1,
            3 => 2,
            4 => 3,
            _ => return None,
        };
        for k in 0..nbytes {
            out.push(((acc >> (16 - 8 * k)) & 0xff) as u8);
        }
    }
    Some(out)
}

#[allow(dead_code)] // used by tests; kept for symmetry with base64_decode
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// A SOCKS5 address: (address-type byte, host string, port).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksAddr {
    atyp: u8,
    host: String,
    port: u16,
}

impl SocksAddr {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let s = format!("{}:{}", self.host, self.port);
        s.to_socket_addrs().map(|it| it.collect())
    }
}

/// Parse a SOCKS5 address from `r` (ATYP + address + 2-byte big-endian port).
fn parse_socks_addr<R: Read>(r: &mut R) -> io::Result<SocksAddr> {
    let mut atyp = [0u8; 1];
    r.read_exact(&mut atyp)?;
    match atyp[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip)?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port)?;
            Ok(SocksAddr {
                atyp: 0x01,
                host: format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                port: u16::from_be_bytes(port),
            })
        }
        0x03 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len)?;
            let mut host = vec![0u8; len[0] as usize];
            r.read_exact(&mut host)?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port)?;
            Ok(SocksAddr {
                atyp: 0x03,
                host: String::from_utf8_lossy(&host).into_owned(),
                port: u16::from_be_bytes(port),
            })
        }
        0x04 => {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip)?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port)?;
            Ok(SocksAddr {
                atyp: 0x04,
                host: format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    u16::from_be_bytes([ip[0], ip[1]]),
                    u16::from_be_bytes([ip[2], ip[3]]),
                    u16::from_be_bytes([ip[4], ip[5]]),
                    u16::from_be_bytes([ip[6], ip[7]]),
                    u16::from_be_bytes([ip[8], ip[9]]),
                    u16::from_be_bytes([ip[10], ip[11]]),
                    u16::from_be_bytes([ip[12], ip[13]]),
                    u16::from_be_bytes([ip[14], ip[15]]),
                ),
                port: u16::from_be_bytes(port),
            })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS5 ATYP 0x{:02x}", other),
        )),
    }
}

/// Serialise a SOCKS5 address (ATYP + address + port) for replies / UDP.
fn encode_socks_addr(addr: &SocksAddr) -> Vec<u8> {
    let mut out = vec![addr.atyp];
    match addr.atyp {
        0x01 => {
            for part in addr.host.split('.') {
                out.push(part.parse::<u8>().unwrap_or(0));
            }
        }
        0x03 => {
            out.push(addr.host.len() as u8);
            out.extend_from_slice(addr.host.as_bytes());
        }
        0x04 => {
            for part in addr.host.split(':') {
                let v = u16::from_str_radix(part, 16).unwrap_or(0);
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        _ => {}
    }
    out.extend_from_slice(&addr.port.to_be_bytes());
    out
}

/// Parse a `CONNECT host:port HTTP/x.y` request line. Returns (host, port) or None.
fn parse_connect_target(request_line: &str) -> Option<(String, u16)> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let authority = parts.next()?;
    if let Some(bracket) = authority.strip_prefix('[') {
        let (host, rest) = bracket.split_once("]:")?;
        let port: u16 = rest.parse().ok()?;
        return Some((format!("[{}]", host), port));
    }
    let (host, port_s) = authority.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// Check a `Proxy-Authorization: Basic ...` header value against expected auth.
fn check_basic_auth(header_value: Option<&str>, expected: &Option<(String, String)>) -> bool {
    let Some((user, pass)) = expected else {
        return true;
    };
    let Some(v) = header_value else {
        return false;
    };
    let Some(b64) = v.strip_prefix("Basic ") else {
        return false;
    };
    let Some(decoded) = base64_decode(b64.trim()) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((u, p)) = text.split_once(':') else {
        return false;
    };
    u == user && p == pass
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

/// Copy both directions between two TCP streams until either side closes.
fn relay_tcp(a: TcpStream, b: TcpStream) {
    let (a_r, b_w) = match (a.try_clone(), b.try_clone()) {
        (Ok(ar), Ok(bw)) => (ar, bw),
        _ => return,
    };
    let (b_r, a_w) = (b, a);
    let mut a_r = a_r;
    let mut b_w = b_w;
    let mut b_r = b_r;
    let mut a_w = a_w;
    let t1 = thread::spawn(move || {
        let _ = io::copy(&mut a_r, &mut b_w);
        let _ = b_w.shutdown(Shutdown::Write);
    });
    let t2 = thread::spawn(move || {
        let _ = io::copy(&mut b_r, &mut a_w);
        let _ = a_w.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
}

fn log(peer: &SocketAddr, msg: &str) {
    eprintln!("[proxy] {} {}", peer, msg);
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

fn socks_reply(stream: &mut TcpStream, rep: u8, bound: &SocketAddr) -> io::Result<()> {
    let atyp = if bound.is_ipv4() { 0x01 } else { 0x04 };
    let mut resp = vec![0x05, rep, 0x00, atyp];
    match bound.ip() {
        std::net::IpAddr::V4(ip) => resp.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => resp.extend_from_slice(&ip.octets()),
    }
    resp.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&resp)?;
    stream.flush()
}

fn handle_socks5(mut stream: TcpStream, peer: SocketAddr, auth: &Option<(String, String)>) -> io::Result<()> {
    // First byte (0x05) already consumed by dispatcher.
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    let nmethods = buf[0] as usize;
    if nmethods == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS5: NMETHODS=0"));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods)?;

    let need_auth = auth.is_some();
    let chosen = if need_auth {
        if methods.contains(&0x02) { 0x02 } else { 0xff }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        0xff
    };
    stream.write_all(&[0x05, chosen])?;
    stream.flush()?;
    if chosen == 0xff {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5: no acceptable auth method"));
    }

    if chosen == 0x02 {
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver)?;
        if ver[0] != 0x01 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS5: bad auth version"));
        }
        let mut ulen = [0u8; 1];
        stream.read_exact(&mut ulen)?;
        let mut uname = vec![0u8; ulen[0] as usize];
        stream.read_exact(&mut uname)?;
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen)?;
        let mut passwd = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut passwd)?;
        let ok = match auth {
            Some((u, p)) => String::from_utf8_lossy(&uname) == *u && String::from_utf8_lossy(&passwd) == *p,
            None => true,
        };
        stream.write_all(&[0x01, if ok { 0x00 } else { 0x01 }])?;
        stream.flush()?;
        if !ok {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5: bad credentials"));
        }
    }

    let mut hdr = [0u8; 3];
    stream.read_exact(&mut hdr)?;
    if hdr[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS5: bad request version"));
    }
    let cmd = hdr[1];
    let target = parse_socks_addr(&mut stream)?;

    match cmd {
        0x01 => {
            let addrs = match target.to_socket_addrs() {
                Ok(a) if !a.is_empty() => a,
                _ => {
                    let bound = stream.local_addr().unwrap_or(peer);
                    socks_reply(&mut stream, 0x04, &bound)?;
                    return Err(io::Error::new(io::ErrorKind::NotFound, "SOCKS5: DNS resolve failed"));
                }
            };
            let mut upstream: Option<TcpStream> = None;
            let mut last_err: Option<io::Error> = None;
            for a in &addrs {
                match TcpStream::connect_timeout(a, Duration::from_secs(10)) {
                    Ok(s) => { upstream = Some(s); break; }
                    Err(e) => last_err = Some(e),
                }
            }
            let upstream = match upstream {
                Some(s) => s,
                None => {
                    let bound = stream.local_addr().unwrap_or(peer);
                    socks_reply(&mut stream, 0x05, &bound)?;
                    return Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "SOCKS5: connect failed")));
                }
            };
            let bound = upstream.local_addr().unwrap_or(peer);
            socks_reply(&mut stream, 0x00, &bound)?;
            log(&peer, &format!("SOCKS5 CONNECT {}:{} ok", target.host, target.port));
            relay_tcp(stream, upstream);
            Ok(())
        }
        0x03 => {
            let relay = UdpSocket::bind("127.0.0.1:0")?;
            relay.set_read_timeout(Some(Duration::from_secs(30)))?;
            let relay_addr = relay.local_addr()?;
            socks_reply(&mut stream, 0x00, &relay_addr)?;
            log(&peer, &format!("SOCKS5 UDP ASSOCIATE relay={} (client {})", relay_addr, peer));
            stream.set_read_timeout(Some(Duration::from_millis(200)))?;
            let mut control_buf = [0u8; 1];
            let mut client_addr: Option<SocketAddr> = None;
            let mut pkt = [0u8; 65535];
            loop {
                match stream.read(&mut control_buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
                match relay.recv_from(&mut pkt) {
                    Ok((n, src)) => {
                        if Some(src) == client_addr || client_addr.is_none() {
                            if client_addr.is_none() { client_addr = Some(src); }
                            if n < 4 { continue; }
                            if pkt[2] != 0x00 { continue; }
                            let mut cursor = &pkt[4..n];
                            let dest = match parse_socks_addr(&mut cursor) { Ok(d) => d, Err(_) => continue };
                            let header_len = 4 + (n - 4 - cursor.len());
                            let payload = &pkt[header_len..n];
                            if let Ok(dest_addrs) = dest.to_socket_addrs() {
                                if let Some(d) = dest_addrs.first() {
                                    let _ = relay.send_to(payload, d);
                                }
                            }
                        } else if let Some(c) = client_addr {
                            let src_addr = SocksAddr {
                                atyp: if src.is_ipv4() { 0x01 } else { 0x04 },
                                host: src.ip().to_string(),
                                port: src.port(),
                            };
                            let mut out = vec![0x00, 0x00, 0x00];
                            out.extend_from_slice(&encode_socks_addr(&src_addr));
                            out.extend_from_slice(&pkt[..n]);
                            let _ = relay.send_to(&out, c);
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => continue,
                    Err(_) => break,
                }
            }
            log(&peer, "SOCKS5 UDP ASSOCIATE closed");
            Ok(())
        }
        _ => {
            let bound = stream.local_addr().unwrap_or(peer);
            socks_reply(&mut stream, 0x07, &bound)?;
            Err(io::Error::new(io::ErrorKind::Unsupported, format!("SOCKS5: CMD 0x{:02x} not supported", cmd)))
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

fn handle_http(mut stream: TcpStream, peer: SocketAddr, auth: &Option<(String, String)>, first: u8) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = vec![first];
    reader.read_until(b'\n', &mut line)?;
    let request_line = String::from_utf8_lossy(&line).trim_end().to_string();

    let target = match parse_connect_target(&request_line) {
        Some(t) => t,
        None => {
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes())?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("HTTP: not a CONNECT request: {}", request_line)));
        }
    };

    let mut proxy_auth: Option<String> = None;
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h)?;
        if n == 0 || h.trim().is_empty() { break; }
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("Proxy-Authorization") {
                proxy_auth = Some(v.trim().to_string());
            }
        }
    }

    if !check_basic_auth(proxy_auth.as_deref(), auth) {
        let resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp.as_bytes())?;
        stream.flush()?;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "HTTP: proxy auth required/failed"));
    }

    let addr_str = format!("{}:{}", target.0, target.1);
    let mut connected: Option<TcpStream> = None;
    if let Ok(mut it) = addr_str.to_socket_addrs() {
        for a in it.by_ref() {
            if let Ok(s) = TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
                connected = Some(s);
                break;
            }
        }
    }
    let upstream = match connected {
        Some(s) => s,
        None => {
            let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes())?;
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "HTTP: upstream connect failed"));
        }
    };

    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    stream.flush()?;
    log(&peer, &format!("HTTP CONNECT {}:{} ok", target.0, target.1));
    drop(reader);
    relay_tcp(stream, upstream);
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatcher + main
// ---------------------------------------------------------------------------

fn handle_client(mut stream: TcpStream, peer: SocketAddr, auth: Option<(String, String)>) {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).is_err() { return; }
    let result = if first[0] == 0x05 {
        handle_socks5(stream, peer, &auth)
    } else {
        handle_http(stream, peer, &auth, first[0])
    };
    if let Err(e) = result {
        log(&peer, &format!("connection closed: {}", e));
    }
}

fn main() {
    let cfg = Config::from_args();
    let listener = match TcpListener::bind(&cfg.addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}: {}", cfg.addr, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "rust-proxy-node listening on {} (SOCKS5 + HTTP CONNECT, auth: {})",
        cfg.addr,
        if cfg.auth.is_some() { "enabled" } else { "disabled" }
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let peer = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                let auth = cfg.auth.clone();
                thread::spawn(move || handle_client(stream, peer, auth));
            }
            Err(e) => eprintln!("[proxy] accept error: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn base64_roundtrip() {
        assert_eq!(base64_decode("YWxpY2U6c2VjcmV0").unwrap(), b"alice:secret");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("!!!"), None);
        assert_eq!(base64_encode(b"alice:secret"), "YWxpY2U6c2VjcmV0");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }

    #[test]
    fn parse_connect_target_ok() {
        assert_eq!(parse_connect_target("CONNECT example.com:443 HTTP/1.1"), Some(("example.com".to_string(), 443)));
        assert_eq!(parse_connect_target("CONNECT 93.184.216.34:80 HTTP/1.0"), Some(("93.184.216.34".to_string(), 80)));
        assert_eq!(parse_connect_target("CONNECT [::1]:1080 HTTP/1.1"), Some(("[::1]".to_string(), 1080)));
    }

    #[test]
    fn parse_connect_target_bad() {
        assert_eq!(parse_connect_target("GET http://example.com/ HTTP/1.1"), None);
        assert_eq!(parse_connect_target("CONNECT example.com HTTP/1.1"), None);
        assert_eq!(parse_connect_target("CONNECT example.com:abc HTTP/1.1"), None);
        assert_eq!(parse_connect_target("CONNECT :443 HTTP/1.1"), None);
    }

    #[test]
    fn socks_addr_ipv4_roundtrip() {
        let raw: Vec<u8> = vec![0x01, 93, 184, 216, 34, 0x01, 0xbb];
        let addr = parse_socks_addr(&mut Cursor::new(raw)).unwrap();
        assert_eq!(addr, SocksAddr { atyp: 0x01, host: "93.184.216.34".to_string(), port: 443 });
        let enc = encode_socks_addr(&addr);
        assert_eq!(enc, vec![0x01, 93, 184, 216, 34, 0x01, 0xbb]);
    }

    #[test]
    fn socks_addr_domain_roundtrip() {
        let mut raw: Vec<u8> = vec![0x03, 11];
        raw.extend_from_slice(b"example.com");
        raw.extend_from_slice(&443u16.to_be_bytes());
        let addr = parse_socks_addr(&mut Cursor::new(raw.clone())).unwrap();
        assert_eq!(addr, SocksAddr { atyp: 0x03, host: "example.com".to_string(), port: 443 });
        assert_eq!(encode_socks_addr(&addr), raw);
    }

    #[test]
    fn socks_addr_bad_atyp() {
        let raw: Vec<u8> = vec![0x09, 1, 2, 3, 4, 0, 80];
        assert!(parse_socks_addr(&mut Cursor::new(raw)).is_err());
    }

    #[test]
    fn basic_auth_check() {
        let expected = Some(("alice".to_string(), "secret".to_string()));
        assert!(check_basic_auth(None, &None));
        let good = format!("Basic {}", base64_encode(b"alice:secret"));
        assert!(check_basic_auth(Some(&good), &expected));
        let bad = format!("Basic {}", base64_encode(b"alice:wrong"));
        assert!(!check_basic_auth(Some(&bad), &expected));
        assert!(!check_basic_auth(None, &expected));
        assert!(!check_basic_auth(Some("Bearer xyz"), &expected));
    }

    #[test]
    fn socks_addr_resolves_localhost() {
        let addr = SocksAddr { atyp: 0x03, host: "localhost".to_string(), port: 1080 };
        let resolved = addr.to_socket_addrs().unwrap();
        assert!(!resolved.is_empty());
    }
}

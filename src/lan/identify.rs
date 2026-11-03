//! Working out what a device is: vendor from its MAC, and an on-demand check
//! of common TCP ports.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, TcpStream};
use std::time::Duration;

use super::discover::Mac;

/// The IEEE OUI registry from the `hwdata` package (or the same file elsewhere).
const OUI_PATHS: [&str; 3] = [
    "/usr/share/hwdata/oui.txt",
    "/usr/share/misc/oui.txt",
    "/usr/share/ieee-data/oui.txt",
];

/// Maps the first three MAC bytes to a vendor name.
#[derive(Default)]
pub struct Vendors(HashMap<[u8; 3], String>);

impl Vendors {
    /// Loads the OUI registry. If no copy is installed the map is empty.
    pub fn load() -> Self {
        let Some(text) = OUI_PATHS.iter().find_map(|p| fs::read_to_string(p).ok()) else {
            return Self::default();
        };
        Self(parse_oui(&text))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn lookup(&self, mac: &Mac) -> Option<String> {
        self.0
            .get(&[mac[0], mac[1], mac[2]])
            .map(|v| tidy_vendor(v))
    }
}

/// Lines look like "28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.".
fn parse_oui(text: &str) -> HashMap<[u8; 3], String> {
    text.lines()
        .filter_map(|l| {
            let (prefix, rest) = l.split_once("(hex)")?;
            let mut b = prefix.trim().split('-').map(|h| u8::from_str_radix(h, 16));
            let key = [b.next()?.ok()?, b.next()?.ok()?, b.next()?.ok()?];
            Some((key, rest.trim().to_string()))
        })
        .collect()
}

/// Drops legal suffixes, which mostly add noise in a narrow column:
/// "TP-LINK TECHNOLOGIES CO.,LTD." becomes "TP-LINK TECHNOLOGIES".
fn tidy_vendor(v: &str) -> String {
    let mut s = v.trim().trim_end_matches('.').to_string();
    for suffix in [
        " co., ltd",
        " co.,ltd",
        " co. ltd",
        " co.ltd",
        " co., ltd",
        ", ltd",
        " ltd",
        " limited",
        ", inc",
        " inc",
        " corporation",
        " corp",
        " gmbh",
        " llc",
        " s.a",
        " b.v",
        " ag",
        " co",
    ] {
        let lower = s.to_lowercase();
        if lower.ends_with(suffix) {
            s.truncate(s.len() - suffix.len());
            s = s.trim_end_matches([',', ' ', '.']).to_string();
        }
    }
    s
}

/// A locally administered MAC. Phones and laptops use randomized "private"
/// addresses like this, so there's no vendor to look up.
pub fn is_random_mac(mac: &Mac) -> bool {
    mac[0] & 0x02 != 0
}

/// Common TCP ports that hint at what a device is.
pub const PROBE_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (53, "dns"),
    (80, "http"),
    (139, "netbios"),
    (443, "https"),
    (445, "smb"),
    (515, "lpd printer"),
    (548, "afp"),
    (554, "rtsp camera"),
    (631, "ipp printer"),
    (1883, "mqtt"),
    (3389, "rdp"),
    (5000, "upnp/nas"),
    (5900, "vnc"),
    (7000, "airplay"),
    (8008, "chromecast"),
    (8009, "chromecast"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (8883, "mqtt-tls"),
    (9100, "jetdirect printer"),
    (32400, "plex"),
    (62078, "apple device"),
];

pub fn port_name(port: u16) -> &'static str {
    PROBE_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map_or("", |(_, n)| n)
}

/// Tries a TCP connect to each common port in parallel. Returns the open ones
/// in order. `scope` is the interface for a link-local IPv6 address.
pub fn probe(ip: IpAddr, scope: u32) -> Vec<u16> {
    let handles: Vec<_> = PROBE_PORTS
        .iter()
        .map(|&(port, _)| {
            std::thread::spawn(move || {
                let addr = match ip {
                    IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, port, 0, scope)),
                    IpAddr::V4(_) => SocketAddr::from((ip, port)),
                };
                TcpStream::connect_timeout(&addr, Duration::from_millis(900))
                    .is_ok()
                    .then_some(port)
            })
        })
        .collect();
    let mut open: Vec<u16> = handles
        .into_iter()
        .filter_map(|h| h.join().ok().flatten())
        .collect();
    open.sort_unstable();
    open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_oui_lines() {
        let text = "OUI/MA-L  Organization\n\n28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.\n286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd.\n\t\t\t\tShanghai\n";
        let m = parse_oui(text);
        assert_eq!(m.len(), 1);
        assert_eq!(m[&[0x28, 0x6f, 0xb9]], "Nokia Shanghai Bell Co., Ltd.");
    }

    #[test]
    fn tidies_vendor_names() {
        assert_eq!(
            tidy_vendor("TP-LINK TECHNOLOGIES CO.,LTD."),
            "TP-LINK TECHNOLOGIES"
        );
        assert_eq!(tidy_vendor("Apple, Inc."), "Apple");
        assert_eq!(tidy_vendor("Intel Corporate"), "Intel Corporate");
        assert_eq!(
            tidy_vendor("Raspberry Pi Trading Ltd"),
            "Raspberry Pi Trading"
        );
    }

    #[test]
    fn random_macs() {
        assert!(is_random_mac(&[0x3a, 0, 0, 0, 0, 0]));
        assert!(!is_random_mac(&[0x1c, 0x61, 0xb4, 0, 0, 0]));
    }

    #[test]
    fn real_oui_file_if_present() {
        let v = Vendors::load();
        if !v.is_empty() {
            assert!(v.0.len() > 10_000);
        }
    }
}

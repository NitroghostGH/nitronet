//! The rows each tab shows: filtered, sorted, and grouped.

use std::cmp::Reverse;
use std::collections::HashMap;

use super::{App, DevSort, ProcSort, ProcView, SockSort, fmt_addr, query};
use crate::lan::DevKey;
use crate::sampler::{Owner, ProcRow, SockRow};

impl App {
    /// Indices into `app.snap.sockets` of the rows to show, filtered and sorted.
    pub fn sock_rows(&self) -> Vec<usize> {
        let app = self;
        let names = app.owner_names();
        let name = |s: &SockRow| {
            names
                .iter()
                .find(|(o, _)| *o == s.owner)
                .map_or("?", |(_, n)| n.as_str())
        };
        let all = &app.snap.sockets;
        let mut idx: Vec<usize> = (0..all.len())
            .filter(|&i| !app.listening_only || all[i].sock.is_listening())
            .filter(|&i| {
                let s = &all[i];
                let pid = match s.owner {
                    Owner::Pid(p) => p.to_string(),
                    _ => String::new(),
                };
                app.matches(&[
                    s.sock.proto.as_str(),
                    &fmt_addr(s.sock.local),
                    &fmt_addr(s.sock.remote),
                    s.sock.state_str(),
                    name(s),
                    &pid,
                ])
            })
            .collect();
        let port_key = |i: &usize| (all[*i].sock.local.port(), all[*i].sock.proto);
        // Ties are in port order: sort by that first, then stably by the key.
        idx.sort_by_key(port_key);
        let rate_in = |s: &SockRow| s.rate_in.unwrap_or(0.0);
        let rate_out = |s: &SockRow| s.rate_out.unwrap_or(0.0);
        let mut by_rate =
            |f: &dyn Fn(&SockRow) -> f64| idx.sort_by(|a, b| f(&all[*b]).total_cmp(&f(&all[*a])));
        match app.sock_sort {
            SockSort::Rate => by_rate(&|s| rate_in(s) + rate_out(s)),
            SockSort::RateIn => by_rate(&rate_in),
            SockSort::RateOut => by_rate(&rate_out),
            SockSort::BytesIn => idx.sort_by_key(|i| Reverse(all[*i].bytes.map_or(0, |b| b.0))),
            SockSort::BytesOut => idx.sort_by_key(|i| Reverse(all[*i].bytes.map_or(0, |b| b.1))),
            SockSort::Port => {}
            SockSort::Proto => idx.sort_by_key(|i| all[*i].sock.proto),
            // Connected sockets first; "*" (no remote) last.
            SockSort::Remote => idx.sort_by_key(|i| {
                let r = all[*i].sock.remote;
                (r.ip().is_unspecified() && r.port() == 0, r)
            }),
            SockSort::State => idx.sort_by_key(|i| all[*i].sock.state_str()),
            SockSort::Program => idx.sort_by_cached_key(|i| name(&all[*i]).to_lowercase()),
            SockSort::Pid => idx.sort_by_key(|i| all[*i].owner),
        }
        if app.reverse.socks {
            idx.reverse();
        }
        idx
    }

    pub fn owner_names(&self) -> Vec<(Owner, String)> {
        let app = self;
        app.snap
            .procs
            .iter()
            .map(|p| (p.owner, p.name.clone()))
            .collect()
    }

    /// The device rows to show, filtered and sorted.
    pub fn dev_rows(&self) -> Vec<DevKey> {
        let devs = &self.lan_state.devices;
        let mut keys: Vec<DevKey> = devs
            .values()
            .filter(|d| {
                let ips: Vec<String> = d.ips().map(|ip| ip.to_string()).collect();
                let mac = d
                    .mac
                    .as_ref()
                    .map(crate::lan::discover::fmt_mac)
                    .unwrap_or_default();
                let mut fields: Vec<&str> = ips.iter().map(String::as_str).collect();
                fields.push(&mac);
                fields.extend(d.name.as_deref());
                fields.extend(d.vendor.as_deref());
                if d.is_gateway {
                    fields.push("gateway");
                }
                if d.is_router {
                    fields.push("router");
                }
                self.matches(&fields)
            })
            .map(|d| d.key)
            .collect();
        let d = |k: &DevKey| &devs[k];
        match self.dev_sort {
            // IPv4 order; IPv6-only devices after, by address.
            DevSort::Ip => {
                keys.sort_by_key(|k| (d(k).ipv4.is_none(), d(k).ipv4, d(k).ipv6.first().copied()))
            }
            // Unnamed devices go last.
            DevSort::Name => keys.sort_by_key(|k| {
                (
                    d(k).name.is_none(),
                    d(k).name.as_ref().map(|n| n.to_lowercase()),
                )
            }),
            DevSort::Vendor => keys.sort_by_key(|k| {
                (
                    d(k).vendor.is_none(),
                    d(k).vendor.as_ref().map(|v| v.to_lowercase()),
                )
            }),
            DevSort::Ipv6 => {
                keys.sort_by_key(|k| (d(k).ipv6.is_empty(), d(k).ipv6.first().copied()))
            }
            DevSort::Mac => keys.sort_by_key(|k| (d(k).mac.is_none(), d(k).mac)),
            DevSort::Rtt => keys.sort_by_key(|k| (d(k).rtt.is_none(), d(k).rtt)),
            DevSort::Seen => keys.sort_by_key(|k| (!d(k).online, Reverse(d(k).last_seen))),
        }
        if self.reverse.devs {
            keys.reverse();
        }
        keys
    }

    /// The filter: every word must appear in some field, and a word starting
    /// with `!` must appear in none ("dns !mdns", "firefox 443").
    pub fn matches(&self, fields: &[&str]) -> bool {
        self.query().matches(fields, &[])
    }

    /// The text filter, parsed.
    pub fn query(&self) -> query::Query {
        query::Query::parse(&self.filter)
    }

    /// The process rows to show: grouped, filtered and sorted.
    pub fn proc_views(&self) -> Vec<ProcView> {
        let mut views: Vec<ProcView> = Vec::new();
        if self.group_by_program {
            let mut index: HashMap<String, usize> = HashMap::new();
            for p in &self.snap.procs {
                let key = match p.owner {
                    Owner::Pid(_) => p.name.clone(),
                    // Keep pseudo-owners such as "(kernel)" separate per uid.
                    other => format!("{other:?}"),
                };
                match index.get(&key) {
                    None => {
                        index.insert(key, views.len());
                        views.push(ProcView {
                            row: p.clone(),
                            owners: vec![p.owner],
                        });
                    }
                    Some(&i) => {
                        let g = &mut views[i];
                        let r = &mut g.row;
                        g.owners.push(p.owner);
                        r.alive |= p.alive;
                        r.rate_in += p.rate_in;
                        r.rate_out += p.rate_out;
                        r.total_in += p.total_in;
                        r.total_out += p.total_out;
                        r.sockets += p.sockets;
                        r.listening.extend_from_slice(&p.listening);
                        r.listening.sort_unstable();
                        r.listening.dedup();
                        if r.unit != p.unit {
                            r.unit = Some("*".into());
                        }
                        if r.user != p.user {
                            r.user = "*".into();
                        }
                        if r.uid != p.uid {
                            r.uid = None;
                        }
                        r.owner = r.owner.min(p.owner);
                    }
                }
            }
        } else {
            views = self
                .snap
                .procs
                .iter()
                .map(|p| ProcView {
                    row: p.clone(),
                    owners: vec![p.owner],
                })
                .collect();
        }

        views.retain(|v| {
            let r = &v.row;
            let pid = match r.owner {
                Owner::Pid(p) => p.to_string(),
                _ => String::new(),
            };
            let ports: Vec<String> = r.listening.iter().map(|(_, p)| p.to_string()).collect();
            let mut fields = vec![
                r.name.as_str(),
                r.user.as_str(),
                pid.as_str(),
                r.unit.as_deref().unwrap_or(""),
            ];
            fields.extend(ports.iter().map(String::as_str));
            self.matches(&fields)
        });

        let rate = |r: &ProcRow| r.rate_in + r.rate_out;
        let total = |r: &ProcRow| r.total_in + r.total_out;
        // Ties: busiest first, then by name and pid. Each sort below is stable.
        views.sort_by(|a, b| {
            let (a, b) = (&a.row, &b.row);
            rate(b)
                .total_cmp(&rate(a))
                .then(total(b).cmp(&total(a)))
                .then(a.name.cmp(&b.name))
                .then(a.owner.cmp(&b.owner))
        });
        let mut by_rate =
            |f: &dyn Fn(&ProcRow) -> f64| views.sort_by(|a, b| f(&b.row).total_cmp(&f(&a.row)));
        match self.proc_sort {
            ProcSort::Rate => {}
            ProcSort::RateIn => by_rate(&|r| r.rate_in),
            ProcSort::RateOut => by_rate(&|r| r.rate_out),
            ProcSort::Total => views.sort_by_key(|v| Reverse(total(&v.row))),
            ProcSort::TotalIn => views.sort_by_key(|v| Reverse(v.row.total_in)),
            ProcSort::TotalOut => views.sort_by_key(|v| Reverse(v.row.total_out)),
            ProcSort::Conn => views.sort_by_key(|v| Reverse(v.row.sockets)),
            ProcSort::Name => views.sort_by_cached_key(|v| v.row.name.to_lowercase()),
            ProcSort::Pid => views.sort_by_key(|v| v.row.owner),
            // Rows without a value go last.
            ProcSort::Service => views.sort_by_cached_key(|v| {
                let unit = v.row.unit.as_ref().map(|u| u.to_lowercase());
                (unit.is_none(), unit)
            }),
            ProcSort::User => views.sort_by_cached_key(|v| v.row.user.to_lowercase()),
            ProcSort::Ports => views.sort_by_key(|v| {
                let lowest = v.row.listening.iter().map(|&(_, p)| p).min();
                (lowest.is_none(), lowest)
            }),
        }
        if self.reverse.procs {
            views.reverse();
        }
        views
    }
}

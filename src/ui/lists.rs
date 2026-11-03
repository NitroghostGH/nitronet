//! The rows each tab shows: filtered, sorted, and grouped.

use std::collections::HashMap;

use super::{App, DevSort, ProcSort, ProcView, SockSort, fmt_addr, query};
use crate::lan::DevKey;
use crate::sampler::{Owner, SockRow};

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
        let rate = |i: &usize| all[*i].rate_in.unwrap_or(0.0) + all[*i].rate_out.unwrap_or(0.0);
        let port_key = |i: &usize| (all[*i].sock.local.port(), all[*i].sock.proto);
        match app.sock_sort {
            SockSort::Rate => idx.sort_by(|a, b| {
                rate(b)
                    .total_cmp(&rate(a))
                    .then(port_key(a).cmp(&port_key(b)))
            }),
            SockSort::Port => idx.sort_by_key(port_key),
            SockSort::State => idx.sort_by_key(|i| (all[*i].sock.state_str(), port_key(i))),
            SockSort::Program => idx.sort_by_key(|i| (name(&all[*i]).to_lowercase(), port_key(i))),
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
            DevSort::Seen => {
                keys.sort_by_key(|k| (!d(k).online, std::cmp::Reverse(d(k).last_seen)))
            }
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

        let rate = |v: &ProcView| v.row.rate_in + v.row.rate_out;
        let total = |v: &ProcView| v.row.total_in + v.row.total_out;
        match self.proc_sort {
            ProcSort::Rate => views.sort_by(|a, b| {
                rate(b)
                    .total_cmp(&rate(a))
                    .then(total(b).cmp(&total(a)))
                    .then(a.row.name.cmp(&b.row.name))
            }),
            ProcSort::Total => {
                views.sort_by(|a, b| total(b).cmp(&total(a)).then(a.row.name.cmp(&b.row.name)))
            }
            ProcSort::Name => views.sort_by(|a, b| {
                a.row
                    .name
                    .to_lowercase()
                    .cmp(&b.row.name.to_lowercase())
                    .then(a.row.owner.cmp(&b.row.owner))
            }),
            ProcSort::Pid => views.sort_by_key(|v| v.row.owner),
        }
        if self.reverse.procs {
            views.reverse();
        }
        views
    }
}

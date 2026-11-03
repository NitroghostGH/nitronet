//! Going through captured packets: the direction and content filters, and
//! grouping packets into conversations (one row per connection).

use std::collections::HashMap;
use std::time::SystemTime;

use super::App;
use crate::packet::{Content, FlowKey, Packet};
use crate::sampler::Owner;

/// `i`: which directions to show.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum DirFilter {
    Both,
    Sent,
    Received,
}

impl DirFilter {
    pub fn next(self) -> Self {
        match self {
            DirFilter::Both => DirFilter::Sent,
            DirFilter::Sent => DirFilter::Received,
            DirFilter::Received => DirFilter::Both,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            DirFilter::Both => "sent and received",
            DirFilter::Sent => "sent only",
            DirFilter::Received => "received only",
        }
    }
}

/// `e`: which payloads to show.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum ContentFilter {
    All,
    /// Hide packets with no payload (handshakes, acks).
    Data,
    /// Only packets whose payload isn't encrypted.
    Unencrypted,
    /// Only packets carrying a password or login unencrypted.
    Secrets,
}

impl ContentFilter {
    pub fn next(self) -> Self {
        match self {
            ContentFilter::All => ContentFilter::Data,
            ContentFilter::Data => ContentFilter::Unencrypted,
            ContentFilter::Unencrypted => ContentFilter::Secrets,
            ContentFilter::Secrets => ContentFilter::All,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ContentFilter::All => "all packets",
            ContentFilter::Data => "with data",
            ContentFilter::Unencrypted => "unencrypted",
            ContentFilter::Secrets => "logins in clear",
        }
    }
    fn allows(self, p: &Packet) -> bool {
        match self {
            ContentFilter::All => true,
            ContentFilter::Data => p.content != Content::Empty,
            ContentFilter::Unencrypted => p.content.unencrypted_data(),
            ContentFilter::Secrets => p.secret.is_some(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum FlowSort {
    Recent,
    Bytes,
    Packets,
    Program,
}

impl FlowSort {
    pub fn next(self) -> Self {
        match self {
            FlowSort::Recent => FlowSort::Bytes,
            FlowSort::Bytes => FlowSort::Packets,
            FlowSort::Packets => FlowSort::Program,
            FlowSort::Program => FlowSort::Recent,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            FlowSort::Recent => "recent",
            FlowSort::Bytes => "bytes",
            FlowSort::Packets => "packets",
            FlowSort::Program => "program",
        }
    }
}

/// A conversation: the captured packets of one connection, summed up.
#[derive(Clone, Debug)]
pub(crate) struct Flow {
    pub key: FlowKey,
    pub owner: Owner,
    pub sent: usize,
    pub received: usize,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub first: SystemTime,
    pub last: SystemTime,
    /// Readable things seen in it: DNS names, TLS server names, HTTP lines.
    pub names: Vec<String>,
    pub plain: usize,
    pub encrypted: usize,
    pub empty: usize,
    pub binary: usize,
    /// Why it's encrypted, from its first encrypted packet.
    pub encrypted_why: Option<&'static str>,
    /// Packets carrying a login secret unencrypted, and the first one's kind.
    pub secrets: usize,
    pub secret: Option<&'static str>,
}

impl Flow {
    pub fn packets(&self) -> usize {
        self.sent + self.received
    }

    /// A short description for the table.
    pub fn what(&self) -> String {
        if !self.names.is_empty() {
            return self.names.join(" · ");
        }
        match (self.encrypted_why, self.binary, self.plain) {
            (Some(why), _, _) => format!("encrypted ({why})"),
            (None, b, _) if b > 0 => "binary data".into(),
            (None, _, p) if p > 0 => "plain data".into(),
            _ => "no data".into(),
        }
    }
}

const MAX_NAMES: usize = 6;

impl App {
    /// Whether a packet passes the direction and content filters, and is in
    /// the conversation being looked at (if any).
    pub(super) fn pkt_passes(&self, p: &Packet) -> bool {
        let dir = match self.pkt_dir {
            DirFilter::Both => true,
            DirFilter::Sent => p.outgoing,
            DirFilter::Received => !p.outgoing,
        };
        dir && self.pkt_content.allows(p)
            && self
                .pkt_flow
                .as_ref()
                .is_none_or(|f| p.flow().as_ref() == Some(f))
    }

    /// Indices into `app.packets` of the rows to show: filtered, oldest first
    /// (newest first when reversed).
    pub fn pkt_rows(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.packets.len())
            .filter(|&i| {
                let p = &self.packets[i];
                self.pkt_passes(p) && self.pkt_matches(p)
            })
            .collect();
        if self.reverse {
            idx.reverse();
        }
        idx
    }

    /// Whether a packet matches the text filter. Its payload is searched too,
    /// so "/password" finds the packet that carries one.
    fn pkt_matches(&self, p: &Packet) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let pid = match p.owner {
            Owner::Pid(p) => p.to_string(),
            _ => String::new(),
        };
        let (local, remote) = p
            .ends()
            .map(|(l, r)| (l.to_string(), r.to_string()))
            .unwrap_or_default();
        let (proto, info) = p
            .head
            .as_ref()
            .map(|d| (d.proto(), d.info.as_str()))
            .unwrap_or(("?", ""));
        let content = p.content.label();
        let secret = p.secret.unwrap_or_default();
        self.matches_with_bytes(
            &[
                &p.program, &pid, &local, &remote, proto, info, &content, secret,
            ],
            p.payload(),
        )
    }

    /// The conversations among the packets that pass the filters, sorted.
    pub fn flows(&self) -> Vec<Flow> {
        let mut index: HashMap<FlowKey, usize> = HashMap::new();
        let mut flows: Vec<Flow> = Vec::new();
        // Conversations with a packet that matches the text filter by itself.
        let mut hit: Vec<bool> = Vec::new();
        for p in &self.packets {
            if !self.pkt_passes(p) {
                continue;
            }
            let Some(key) = p.flow() else {
                continue;
            };
            let i = *index.entry(key.clone()).or_insert_with(|| {
                flows.push(Flow {
                    key,
                    owner: p.owner,
                    sent: 0,
                    received: 0,
                    bytes_out: 0,
                    bytes_in: 0,
                    first: p.at,
                    last: p.at,
                    names: Vec::new(),
                    plain: 0,
                    encrypted: 0,
                    empty: 0,
                    binary: 0,
                    encrypted_why: None,
                    secrets: 0,
                    secret: None,
                });
                hit.push(false);
                flows.len() - 1
            });
            if !hit[i] && !self.filter.is_empty() {
                hit[i] = self.pkt_matches(p);
            }
            let f = &mut flows[i];
            if p.outgoing {
                f.sent += 1;
                f.bytes_out += p.len as u64;
            } else {
                f.received += 1;
                f.bytes_in += p.len as u64;
            }
            f.last = p.at;
            if let Some(s) = p.secret {
                f.secrets += 1;
                f.secret.get_or_insert(s);
            }
            match p.content {
                Content::Empty => f.empty += 1,
                Content::Binary | Content::Compressed => f.binary += 1,
                Content::Encrypted(why) => {
                    f.encrypted += 1;
                    f.encrypted_why.get_or_insert(why);
                }
                Content::Plain(_) => {
                    f.plain += 1;
                    if let Some(app) = p.app_info()
                        && f.names.len() < MAX_NAMES
                        && !f.names.iter().any(|n| n == app)
                    {
                        f.names.push(app.to_string());
                    }
                }
            }
        }

        let mut hit = hit.into_iter();
        flows.retain(|f| {
            if hit.next() == Some(true) || self.filter.is_empty() {
                return true;
            }
            let pid = match f.owner {
                Owner::Pid(p) => p.to_string(),
                _ => String::new(),
            };
            let (local, remote) = (f.key.local.to_string(), f.key.remote.to_string());
            let what = f.what();
            self.matches(&[&f.key.program, &pid, &local, &remote, f.key.proto, &what])
        });
        let bytes = |f: &Flow| f.bytes_in + f.bytes_out;
        match self.flow_sort {
            FlowSort::Recent => flows.sort_by_key(|f| std::cmp::Reverse(f.last)),
            FlowSort::Bytes => flows.sort_by_key(|f| std::cmp::Reverse(bytes(f))),
            FlowSort::Packets => flows.sort_by_key(|f| std::cmp::Reverse(f.packets())),
            FlowSort::Program => flows.sort_by(|a, b| {
                a.key
                    .program
                    .to_lowercase()
                    .cmp(&b.key.program.to_lowercase())
                    .then(b.last.cmp(&a.last))
            }),
        }
        if self.reverse {
            flows.reverse();
        }
        flows
    }
}

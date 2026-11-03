//! Rate history for the graphs.

use std::collections::{HashMap, VecDeque};

use crate::sampler::{Owner, Snapshot};

/// Samples kept for graphs. That's enough to fill a 300-column-wide graph at
/// two samples per cell.
pub(super) const HISTORY: usize = 600;

/// Rate history: a whole-machine series, plus one per owner for the detail pane.
#[derive(Default)]
pub(crate) struct History {
    pub total_in: VecDeque<f64>,
    pub total_out: VecDeque<f64>,
    pub peak: (f64, f64),
    owners: HashMap<Owner, VecDeque<(f64, f64)>>,
}

fn push_capped<T>(q: &mut VecDeque<T>, v: T) {
    if q.len() == HISTORY {
        q.pop_front();
    }
    q.push_back(v);
}

impl History {
    pub(super) fn push(&mut self, snap: &Snapshot) {
        let (rx, tx) = snap.nic_rate.unwrap_or(snap.seen_rate);
        push_capped(&mut self.total_in, rx);
        push_capped(&mut self.total_out, tx);
        self.peak = (self.peak.0.max(rx), self.peak.1.max(tx));

        let mut now: HashMap<Owner, (f64, f64)> = snap
            .procs
            .iter()
            .filter(|p| p.alive)
            .map(|p| (p.owner, (p.rate_in, p.rate_out)))
            .collect();
        for (owner, q) in self.owners.iter_mut() {
            push_capped(q, now.remove(owner).unwrap_or((0.0, 0.0)));
        }
        for (owner, v) in now {
            let mut q = VecDeque::new();
            q.push_back(v);
            self.owners.insert(owner, q);
        }
        // Forget owners that have been silent for the whole window.
        self.owners
            .retain(|_, q| q.iter().any(|&(i, o)| i > 0.0 || o > 0.0) || q.len() < HISTORY);
    }

    /// The summed (in, out) series for a set of owners, aligned at the newest sample.
    pub fn series(&self, owners: &[Owner]) -> (Vec<f64>, Vec<f64>) {
        let len = owners
            .iter()
            .filter_map(|o| self.owners.get(o))
            .map(|q| q.len())
            .max()
            .unwrap_or(0);
        let (mut i, mut o) = (vec![0.0; len], vec![0.0; len]);
        for q in owners.iter().filter_map(|o| self.owners.get(o)) {
            let off = len - q.len();
            for (k, &(a, b)) in q.iter().enumerate() {
                i[off + k] += a;
                o[off + k] += b;
            }
        }
        (i, o)
    }
}

//! What each list can be sorted by. A click on a column header sorts by that
//! column (each view maps its columns to these); `s` cycles through the most
//! useful few.

/// Implements the shared parts: `CYCLE` (the `s` order), `next()`, the label
/// shown in the panel border, and whether the natural order is descending
/// (largest or most recent first) rather than ascending (A to Z, lowest first).
macro_rules! sort_enum {
    (
        $(#[$meta:meta])*
        $name:ident, cycle [$($cycle:ident),+ $(,)?],
        { $($(#[$vmeta:meta])* $variant:ident => ($label:literal, $desc:literal)),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(crate) enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            pub const CYCLE: &'static [Self] = &[$(Self::$cycle),+];

            /// The next sort in `CYCLE`, or its first if this one isn't in it.
            pub fn next(self) -> Self {
                let at = Self::CYCLE.iter().position(|&s| s == self);
                at.and_then(|i| Self::CYCLE.get(i + 1))
                    .copied()
                    .unwrap_or(Self::CYCLE[0])
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }

            pub fn desc(self) -> bool {
                match self {
                    $(Self::$variant => $desc),+
                }
            }
        }
    };
}

sort_enum! {
    ProcSort, cycle [Rate, Total, Name, Pid],
    {
        Pid => ("pid", false),
        Name => ("name", false),
        Service => ("service", false),
        User => ("user", false),
        RateIn => ("↓ rate", true),
        RateOut => ("↑ rate", true),
        /// Download and upload together.
        Rate => ("rate", true),
        TotalIn => ("↓ total", true),
        TotalOut => ("↑ total", true),
        Total => ("total", true),
        Conn => ("connections", true),
        Ports => ("ports", false),
    }
}

sort_enum! {
    SockSort, cycle [Rate, Port, State, Program],
    {
        Proto => ("protocol", false),
        /// The local port.
        Port => ("port", false),
        Remote => ("remote", false),
        State => ("state", false),
        Program => ("program", false),
        Pid => ("pid", false),
        RateIn => ("↓ rate", true),
        RateOut => ("↑ rate", true),
        Rate => ("rate", true),
        BytesIn => ("↓ bytes", true),
        BytesOut => ("↑ bytes", true),
    }
}

sort_enum! {
    DevSort, cycle [Ip, Name, Vendor, Seen],
    {
        Ip => ("ip", false),
        Name => ("name", false),
        Ipv6 => ("ipv6", false),
        Vendor => ("vendor", false),
        Mac => ("mac", false),
        /// Fastest first.
        Rtt => ("rtt", false),
        /// Online first, then most recently seen.
        Seen => ("seen", false),
    }
}

sort_enum! {
    FlowSort, cycle [Recent, Bytes, Packets, Program],
    {
        Recent => ("recent", true),
        Program => ("program", false),
        Proto => ("protocol", false),
        Remote => ("remote", false),
        Local => ("local", false),
        Packets => ("packets", true),
        BytesIn => ("↓ bytes", true),
        BytesOut => ("↑ bytes", true),
        /// Both directions together.
        Bytes => ("bytes", true),
    }
}

/// Applies a click on a column that sorts by `new`: the same sort again flips
/// the order; another one starts in its natural order.
pub(crate) fn pick<S: PartialEq + Copy>(cur: &mut S, reversed: &mut bool, new: Option<S>) {
    if let Some(s) = new {
        if *cur == s {
            *reversed = !*reversed;
        } else {
            *cur = s;
            *reversed = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s_cycles_and_rejoins_the_cycle() {
        assert_eq!(ProcSort::Rate.next(), ProcSort::Total);
        assert_eq!(ProcSort::Pid.next(), ProcSort::Rate);
        // A sort picked by clicking a column goes back to the start.
        assert_eq!(ProcSort::Conn.next(), ProcSort::Rate);
        assert_eq!(FlowSort::Program.next(), FlowSort::Recent);
    }

    #[test]
    fn clicking_the_same_column_flips_it() {
        let (mut s, mut r) = (SockSort::Rate, false);
        pick(&mut s, &mut r, Some(SockSort::BytesIn));
        assert_eq!((s, r), (SockSort::BytesIn, false));
        pick(&mut s, &mut r, Some(SockSort::BytesIn));
        assert_eq!((s, r), (SockSort::BytesIn, true));
        pick(&mut s, &mut r, None);
        assert_eq!((s, r), (SockSort::BytesIn, true));
        pick(&mut s, &mut r, Some(SockSort::Port));
        assert_eq!((s, r), (SockSort::Port, false));
    }
}

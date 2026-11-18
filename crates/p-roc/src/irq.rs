//! `/proc/interrupts` and `/proc/irq/<n>/`.

use std::fs;

use crate::cpuset::CpuSet;
use crate::error::Error;
use crate::root::{Root, Scan, Unreadable, numeric_entries, read};

/// The per-CPU rows without an IRQ number that matter to a realtime host:
/// timer ticks and inter-processor interrupts.
pub const NAMED_ROWS: [&str; 4] = ["LOC", "CAL", "RES", "TLB"];

/// One row of `/proc/interrupts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The IRQ number (`"125"`) or the row name (`"LOC"`).
    pub id: String,
    /// Counts, one per CPU column.
    pub counts: Vec<u64>,
    /// Interrupt chip (`IR-PCI-MSIX-0000:04:00.0`), numbered rows only.
    pub chip: Option<String>,
    /// Hardware number and trigger (`0-edge`), when the row has one.
    pub hwirq: Option<String>,
    /// Device names (`lan0-TxRx-0`) for a numbered row; the description for a named one.
    pub name: String,
}

/// `/proc/interrupts`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interrupts {
    /// The CPU numbers of the columns.
    pub cpus: Vec<u32>,
    /// The rows in file order.
    pub rows: Vec<Row>,
}

impl Interrupts {
    /// The row with this id.
    #[must_use]
    pub fn row(&self, id: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.id == id)
    }
}

fn looks_like_hwirq(t: &str) -> bool {
    t.split_once('-')
        .is_some_and(|(n, kind)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !kind.is_empty())
}

/// Parses `/proc/interrupts`.
///
/// # Errors
/// When the header names no CPU.
pub fn parse_interrupts(s: &str) -> Result<Interrupts, Error> {
    let mut lines = s.lines();
    let header = lines.next().unwrap_or_default();
    let cpus: Vec<u32> = header.split_whitespace().filter_map(|t| t.strip_prefix("CPU")?.parse().ok()).collect();
    if cpus.is_empty() {
        return Err(Error::parse("interrupts", "header names no CPU"));
    }
    let mut rows = Vec::new();
    for line in lines {
        let mut f = line.split_whitespace();
        let Some(id) = f.next().and_then(|t| t.strip_suffix(':')) else { continue };
        let rest: Vec<&str> = f.collect();
        let n = rest.iter().take(cpus.len()).take_while(|t| t.bytes().all(|b| b.is_ascii_digit())).count();
        let counts = rest[..n].iter().filter_map(|t| t.parse().ok()).collect();
        let tail = &rest[n..];
        let numbered = id.bytes().all(|b| b.is_ascii_digit());
        let (chip, hwirq, name) = match tail {
            [chip, hw, name @ ..] if numbered && looks_like_hwirq(hw) => {
                (Some((*chip).to_string()), Some((*hw).to_string()), name.join(" "))
            }
            [chip, name @ ..] if numbered => (Some((*chip).to_string()), None, name.join(" ")),
            _ => (None, None, tail.join(" ")),
        };
        rows.push(Row { id: id.to_string(), counts, chip, hwirq, name });
    }
    Ok(Interrupts { cpus, rows })
}

/// Reads `/proc/interrupts`.
///
/// # Errors
/// When it cannot be read or parsed.
pub fn read_interrupts(root: &Root) -> Result<Interrupts, Error> {
    parse_interrupts(&read(&root.proc.join("interrupts"))?)
}

/// Per-CPU counts that moved between two readings of the same row, as
/// `(cpu, delta)`; a counter that went backwards counts as zero.
#[must_use]
pub fn delta(cpus: &[u32], before: &Row, after: &Row) -> Vec<(u32, u64)> {
    cpus.iter().zip(before.counts.iter().zip(&after.counts)).map(|(c, (b, a))| (*c, a.saturating_sub(*b))).collect()
}

/// One IRQ under `/proc/irq/<n>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Irq {
    /// The number.
    pub irq: u32,
    /// `smp_affinity_list`.
    pub affinity: Option<CpuSet>,
    /// `effective_affinity_list` (absent on some kernels and for some chips).
    pub effective: Option<CpuSet>,
    /// The action names: the subdirectories (`lan0-TxRx-0`).
    pub actions: Vec<String>,
}

fn cpu_file(path: &std::path::Path) -> Result<Option<CpuSet>, Error> {
    match fs::read_to_string(path) {
        Ok(s) => {
            CpuSet::parse_list(&s).map(Some).map_err(|source| Error::Cpus { what: path.display().to_string(), source })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Reads every IRQ directory. An IRQ that goes away mid-scan is skipped; an
/// unreadable affinity file is listed.
///
/// # Errors
/// When `/proc/irq` itself cannot be listed.
pub fn read_irqs(root: &Root) -> Result<Scan<Irq>, Error> {
    let dir = root.proc.join("irq");
    let mut out = Scan::default();
    for n in numeric_entries(&dir)? {
        let base = dir.join(n.to_string());
        let read_one = || -> Result<Irq, Error> {
            let mut actions: Vec<String> = fs::read_dir(&base)
                .map_err(|e| Error::io(&base, e))?
                .filter_map(|e| {
                    let e = e.ok()?;
                    (e.file_type().ok()?.is_dir()).then(|| e.file_name().to_string_lossy().into_owned())
                })
                .filter(|n| n != "node")
                .collect();
            actions.sort();
            Ok(Irq {
                irq: n as u32,
                affinity: cpu_file(&base.join("smp_affinity_list"))?,
                effective: cpu_file(&base.join("effective_affinity_list"))?,
                actions,
            })
        };
        match read_one() {
            Ok(i) => out.items.push(i),
            Err(e) if e.is_gone() => {}
            Err(e) => out.unreadable.push(Unreadable::new(base.display().to_string(), &e)),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "           CPU0       CPU1       CPU2
  0:         12          0          0   IO-APIC   2-edge      timer
125:          0       5000        200  IR-PCI-MSIX-0000:04:00.0  0-edge      lan0-TxRx-0
 NMI:          1          2          3   Non-maskable interrupts
LOC:       1000       2000       3000   Local timer interrupts
ERR:          0
 30:          1          2          3  GICv3  30 Level     arch_timer
";

    #[test]
    fn parses_numbered_and_named_rows() {
        let i = parse_interrupts(SAMPLE).unwrap();
        assert_eq!(i.cpus, [0, 1, 2]);
        let r = i.row("125").unwrap();
        assert_eq!(r.counts, [0, 5000, 200]);
        assert_eq!(r.chip.as_deref(), Some("IR-PCI-MSIX-0000:04:00.0"));
        assert_eq!(r.hwirq.as_deref(), Some("0-edge"));
        assert_eq!(r.name, "lan0-TxRx-0");
        assert_eq!(i.row("LOC").unwrap().name, "Local timer interrupts");
        assert_eq!(i.row("ERR").unwrap().counts, [0]);
        assert_eq!(i.row("30").unwrap().name, "30 Level arch_timer");
        assert!(parse_interrupts("garbage").is_err());
    }

    #[test]
    fn delta_saturates() {
        let a = Row { id: "1".into(), counts: vec![5, 9], chip: None, hwirq: None, name: String::new() };
        let b = Row { counts: vec![8, 3], ..a.clone() };
        assert_eq!(delta(&[0, 1], &a, &b), [(0, 3), (1, 0)]);
    }
}

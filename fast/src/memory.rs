use std::{collections::BTreeSet, fs, time::{Duration, Instant}, sync::{Arc, atomic::{AtomicBool, Ordering}}};

use anyhow::{Context, Result, bail};
use crate::{cli::MemoryArgs, process};

#[derive(Debug, Default)]
struct MemStats {
    psi_some: Vec<f32>,
    psi_full: Vec<f32>,
    faults: Vec<(u64, u64)>,
    swap_kb: Vec<u64>,
}

fn read_psi(path: &str) -> Result<f32> {
    let content = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    for line in content.lines() {
        if line.starts_with("some") || line.starts_with("full") {
            for part in line.split_whitespace() {
                if part.starts_with("avg10=") {
                    let v = part.strip_prefix("avg10=").unwrap_or("0").parse::<f32>().unwrap_or(0.0);
                    return Ok(v);
                }
            }
        }
    }
    Ok(0.0)
}

fn read_meminfo_swap() -> u64 {
    fs::read_to_string("/proc/meminfo").ok().and_then(|c| {
        for line in c.lines() {
            if let Some(v) = line.strip_prefix("SwapTotal:") {
                let kb: u64 = v.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
                let free: u64 = c.lines().find(|l| l.starts_with("SwapFree:")).and_then(|l| l.strip_prefix("SwapFree:")).and_then(|v| v.split_whitespace().next().unwrap_or("0").parse().ok()).unwrap_or(0);
                return Some(kb.saturating_sub(free));
            }
        }
        None
    }).unwrap_or(0)
}

fn read_faults(pid: u32) -> Result<(u64, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).with_context(|| format!("read stat {pid}"))?;
    let end = stat.rfind(')').context("malformed stat")?;
    let after = &stat[end+2..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    if fields.len() < 10 { bail!("too few fields"); }
    let minflt: u64 = fields[7].parse().unwrap_or(0);
    let majflt: u64 = fields[9].parse().unwrap_or(0);
    Ok((minflt, majflt))
}

pub fn run(args: MemoryArgs) -> Result<()> {
    let pid = args.pid;
    let process_name = process::read_name(pid).with_context(|| format!("read {pid}"))?;
    let started = Instant::now();
    let mut stats = MemStats::default();
    let mut next_poll = started + Duration::from_millis(200);
    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let s = Arc::clone(&stop); let i = Arc::clone(&interrupted);
        ctrlc::set_handler(move || { i.store(true, Ordering::Relaxed); s.store(true, Ordering::Relaxed); }).context("Ctrl-C")?;
    }

    while started.elapsed() < args.duration {
        if stop.load(Ordering::Relaxed) { break; }
        if Instant::now() >= next_poll {
            let some = read_psi("/proc/pressure/memory").unwrap_or(0.0);
            let full = read_psi("/proc/pressure/cpu").unwrap_or(0.0);
            let faults = read_faults(pid).unwrap_or((0,0));
            let swap = read_meminfo_swap();
            stats.psi_some.push(some);
            stats.psi_full.push(full);
            stats.faults.push(faults);
            stats.swap_kb.push(swap);
            next_poll = Instant::now() + Duration::from_millis(200);
        }
        std::thread::sleep(Duration::from_millis(50));
        if !process::is_alive(pid).unwrap_or(false) {
            break;
        }
    }

    let elapsed = started.elapsed().min(args.duration);
    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(elapsed));
    if interrupted.load(Ordering::Relaxed) { println!("Status: interrupted"); }
    println!();
    println!("Memory pressure");
    if stats.psi_some.is_empty() {
        println!("No PSI data (requires CONFIG_PSI and /proc/pressure)");
    } else {
        let avg_some: f32 = stats.psi_some.iter().sum::<f32>() / stats.psi_some.len() as f32;
        let max_some = stats.psi_some.iter().cloned().fold(0.0f32, f32::max);
        let avg_full: f32 = stats.psi_full.iter().cloned().sum::<f32>() / stats.psi_full.len() as f32;
        println!("PSI some avg10: {:.1}% max {:.1}%", avg_some, max_some);
        println!("PSI full avg10: {:.1}%", avg_full);
    }
    if stats.faults.is_empty() {
        println!("No fault data");
    } else {
        let first = stats.faults.first().unwrap();
        let last = stats.faults.last().unwrap();
        let min_delta = last.0.saturating_sub(first.0);
        let maj_delta = last.1.saturating_sub(first.1);
        let rate_min = min_delta as f64 / elapsed.as_secs_f64();
        let rate_maj = maj_delta as f64 / elapsed.as_secs_f64();
        println!("Page faults: minflt {} ({:.1}/s) majflt {} ({:.1}/s)", min_delta, rate_min, maj_delta, rate_maj);
    }
    let max_swap = stats.swap_kb.iter().cloned().max().unwrap_or(0);
    println!("Swap used: {} KB", max_swap);
    println!();
    println!("Note: system vs process distinguished; PSI is system-level, faults are per-process.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn psi_parse() {
        let s = "some avg10=12.34 avg60=5.00 avg300=1.00 total=12345\nfull avg10=2.00 avg60=1.00 total=2345\n";
        // simulate read_psi logic
        let mut some = 0.0;
        for line in s.lines() {
            if line.starts_with("some") {
                for part in line.split_whitespace() {
                    if part.starts_with("avg10=") {
                        some = part.strip_prefix("avg10=").unwrap().parse().unwrap();
                    }
                }
            }
        }
        assert!((some - 12.34f32).abs() < 0.01);
    }
}

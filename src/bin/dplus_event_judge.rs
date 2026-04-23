use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allow,
    Throttle,
    Quarantine,
    Forbid,
    Emergency,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Throttle => "THROTTLE",
            Self::Quarantine => "QUARANTINE",
            Self::Forbid => "FORBID",
            Self::Emergency => "EMERGENCY",
        }
    }
}

fn fnv1a64_step(mut h: u64, b: u8) -> u64 {
    const PRIME: u64 = 0x100000001b3;
    h ^= b as u64;
    h.wrapping_mul(PRIME)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    let mut h = OFFSET_BASIS;
    for &b in bytes {
        h = fnv1a64_step(h, b);
    }
    h
}

fn js(src: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = src.find(&needle)? + needle.len();
    let end = src[start..].find('"')? + start;
    Some(src[start..end].to_string())
}

fn judge_line(line: &str) -> Result<(Verdict, String), String> {
    let severity = js(line, "severity").ok_or_else(|| "missing severity".to_string())?;
    let event_kind = js(line, "event_kind").ok_or_else(|| "missing event_kind".to_string())?;
    let recommended_action =
        js(line, "recommended_action").ok_or_else(|| "missing recommended_action".to_string())?;

    let verdict = match severity.as_str() {
        "FATAL" => Verdict::Emergency,
        "CRITICAL" => {
            if event_kind == "RISK_ALERT" {
                Verdict::Quarantine
            } else {
                Verdict::Forbid
            }
        }
        "WARN" => Verdict::Throttle,
        "INFO" => Verdict::Allow,
        _ => return Err(format!("invalid severity: {severity}")),
    };

    let reason = format!(
        "severity={} event_kind={} next={}",
        severity, event_kind, recommended_action
    );
    Ok((verdict, reason))
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage:\n  dplus_event_judge <event.json>\n  dplus_event_judge --replay <events.jsonl>"
    );
    std::process::exit(2);
}

fn run_single(path: &str) -> Result<(), String> {
    let src = fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;
    let (verdict, reason) = judge_line(src.trim())?;
    println!("VERDICT {}", verdict.as_str());
    println!("REASON {}", reason);
    Ok(())
}

fn run_replay(path: &str) -> Result<(), String> {
    let src = fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;
    let mut allow = 0usize;
    let mut throttle = 0usize;
    let mut quarantine = 0usize;
    let mut forbid = 0usize;
    let mut emergency = 0usize;
    let mut errors = 0usize;

    let mut hash = fnv1a64(b"DPLUS_EVENT_REPLAY_V1");
    for (i, raw) in src.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match judge_line(line) {
            Ok((v, reason)) => {
                match v {
                    Verdict::Allow => allow += 1,
                    Verdict::Throttle => throttle += 1,
                    Verdict::Quarantine => quarantine += 1,
                    Verdict::Forbid => forbid += 1,
                    Verdict::Emergency => emergency += 1,
                }
                hash = fnv1a64_step(hash, (v as u8) + 1);
                for b in reason.as_bytes() {
                    hash = fnv1a64_step(hash, *b);
                }
            }
            Err(e) => {
                errors += 1;
                let mark = format!("line={} err={}", i + 1, e);
                for b in mark.as_bytes() {
                    hash = fnv1a64_step(hash, *b);
                }
            }
        }
    }

    println!(
        "REPLAY total={} allow={} throttle={} quarantine={} forbid={} emergency={} errors={}",
        allow + throttle + quarantine + forbid + emergency + errors,
        allow,
        throttle,
        quarantine,
        forbid,
        emergency,
        errors
    );
    println!("REPLAY fingerprint=0x{:016x}", hash);
    if errors > 0 {
        return Err(format!("replay found {} invalid event line(s)", errors));
    }
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next().unwrap_or_else(|| usage_and_exit());
    let result = if first == "--replay" {
        let path = args.next().unwrap_or_else(|| usage_and_exit());
        run_replay(&path)
    } else if first.starts_with('-') {
        usage_and_exit();
    } else {
        run_single(&first)
    };

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// soma_gate.rs — D+ Warden Gate evaluator (Phase I, oo-host side)
///
/// Mirrors the bare-metal `oo_dplus_gate.h` logic in Rust so that oo-host can:
/// 1. Evaluate [oo-event] kind=dplus_verdict lines received via UART
/// 2. Apply its own D+ judgment from received warden events
/// 3. Log verdicts into the oo-host journal
///
/// This is the host-side twin of the bare-metal gate — both apply identical rules.

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum WardGateVerdict {
    Allow = 0,
    Throttle = 1,
    Quarantine = 2,
    Forbid = 3,
    Emergency = 4,
}

impl WardGateVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            WardGateVerdict::Allow      => "ALLOW",
            WardGateVerdict::Throttle   => "THROTTLE",
            WardGateVerdict::Quarantine => "QUARANTINE",
            WardGateVerdict::Forbid     => "FORBID",
            WardGateVerdict::Emergency  => "EMERGENCY",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ALLOW"      => Some(WardGateVerdict::Allow),
            "THROTTLE"   => Some(WardGateVerdict::Throttle),
            "QUARANTINE" => Some(WardGateVerdict::Quarantine),
            "FORBID"     => Some(WardGateVerdict::Forbid),
            "EMERGENCY"  => Some(WardGateVerdict::Emergency),
            _            => None,
        }
    }
}

/// Reason bit flags (mirrors DPLUS_REASON_* in oo_dplus_gate.h)
pub struct WardGateReasons(pub u8);

impl WardGateReasons {
    pub const PRESSURE_CRIT: u8 = 1 << 0;
    pub const SENTINEL:      u8 = 1 << 1;
    pub const OOM:           u8 = 1 << 2;
    pub const TOK_RATE:      u8 = 1 << 3;
    pub const RESONANCE:     u8 = 1 << 4;
    pub const CONSEC_DENY:   u8 = 1 << 5;

    pub fn has(&self, flag: u8) -> bool { self.0 & flag != 0 }
}

/// Input snapshot to evaluate.
#[derive(Copy, Clone, Debug, Default)]
pub struct WardGateRequest {
    /// SOMA_PRESSURE_* (0=NONE, 1=LOW, 2=HIGH, 3=CRITICAL)
    pub pressure: u8,
    /// 1 if sentinel tripped
    pub sentinel_tripped: bool,
    /// Free memory in MiB (approximate)
    pub mem_free_mib: u32,
    /// Tokens per second (0 if unknown)
    pub tok_s: u32,
    /// Resonance anomaly score 0-100
    pub resonance: u8,
    /// Consecutive non-ALLOW verdict count (from gate state)
    pub consec_non_allow: u32,
}

/// Evaluate the D+ gate — mirrors bare-metal logic exactly.
pub fn evaluate_ward_gate(req: &WardGateRequest) -> (WardGateVerdict, WardGateReasons) {
    const MIN_TOK_S:           u32 = 4;
    const MEM_EMERGENCY_MIB:   u32 = 16;
    const RESONANCE_QUARANTINE: u8 = 85;
    const CONSEC_ESCALATE:     u32 = 3;

    let mut verdict = WardGateVerdict::Allow;
    let mut reasons = 0u8;

    // Rule 1: OOM
    if req.mem_free_mib < MEM_EMERGENCY_MIB {
        verdict = WardGateVerdict::Emergency;
        reasons |= WardGateReasons::OOM;
    }

    // Rule 2: Sentinel tripped → at least QUARANTINE
    if req.sentinel_tripped {
        if verdict < WardGateVerdict::Quarantine {
            verdict = WardGateVerdict::Quarantine;
        }
        reasons |= WardGateReasons::SENTINEL;
    }

    // Rule 3: CRITICAL pressure → at least QUARANTINE
    if req.pressure >= 3 {
        if verdict < WardGateVerdict::Quarantine {
            verdict = WardGateVerdict::Quarantine;
        }
        reasons |= WardGateReasons::PRESSURE_CRIT;
    }

    // Rule 4: HIGH pressure + slow tok/s → THROTTLE
    if req.pressure >= 2 && req.tok_s > 0 && req.tok_s < MIN_TOK_S {
        if verdict < WardGateVerdict::Throttle {
            verdict = WardGateVerdict::Throttle;
        }
        reasons |= WardGateReasons::TOK_RATE;
    }

    // Rule 5: Behavioral resonance anomaly → QUARANTINE
    if req.resonance > RESONANCE_QUARANTINE {
        if verdict < WardGateVerdict::Quarantine {
            verdict = WardGateVerdict::Quarantine;
        }
        reasons |= WardGateReasons::RESONANCE;
    }

    // Rule 6: Consecutive non-ALLOW → escalate one level
    if req.consec_non_allow >= CONSEC_ESCALATE {
        let v = verdict as u8;
        if v < WardGateVerdict::Emergency as u8 {
            verdict = match v + 1 {
                1 => WardGateVerdict::Throttle,
                2 => WardGateVerdict::Quarantine,
                3 => WardGateVerdict::Forbid,
                _ => WardGateVerdict::Emergency,
            };
            reasons |= WardGateReasons::CONSEC_DENY;
        }
    }

    (verdict, WardGateReasons(reasons))
}

/// Stateful gate that tracks consecutive non-ALLOW verdicts (mirrors DPlusGateCtx).
#[derive(Debug, Default)]
pub struct WardGateState {
    pub verdict:           WardGateVerdict,
    pub consec_non_allow:  u32,
    pub total_evaluations: u32,
    pub total_escalations: u32,
    pub total_reliefs:     u32,
}

impl Default for WardGateVerdict {
    fn default() -> Self { WardGateVerdict::Allow }
}

impl WardGateState {
    pub fn new() -> Self { WardGateState::default() }

    /// Evaluate and update state. Returns (verdict, reasons).
    pub fn evaluate(&mut self, mut req: WardGateRequest) -> (WardGateVerdict, WardGateReasons) {
        req.consec_non_allow = self.consec_non_allow;
        let (verdict, reasons) = evaluate_ward_gate(&req);
        let prev = self.verdict;

        if verdict != WardGateVerdict::Allow {
            self.consec_non_allow += 1;
        } else {
            self.consec_non_allow = 0;
        }

        if verdict > prev { self.total_escalations += 1; }
        else if verdict < prev { self.total_reliefs += 1; }

        self.verdict = verdict;
        self.total_evaluations += 1;
        (verdict, reasons)
    }

    pub fn reset(&mut self) {
        self.verdict = WardGateVerdict::Allow;
        self.consec_non_allow = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nominal_allow() {
        let req = WardGateRequest {
            pressure: 0, sentinel_tripped: false, mem_free_mib: 512,
            tok_s: 20, resonance: 10, consec_non_allow: 0,
        };
        let (v, r) = evaluate_ward_gate(&req);
        assert_eq!(v, WardGateVerdict::Allow);
        assert_eq!(r.0, 0);
    }

    #[test]
    fn oom_emergency() {
        let req = WardGateRequest { mem_free_mib: 8, ..Default::default() };
        let (v, _) = evaluate_ward_gate(&req);
        assert_eq!(v, WardGateVerdict::Emergency);
    }

    #[test]
    fn sentinel_quarantine() {
        let req = WardGateRequest { sentinel_tripped: true, mem_free_mib: 512, ..Default::default() };
        let (v, r) = evaluate_ward_gate(&req);
        assert_eq!(v, WardGateVerdict::Quarantine);
        assert!(r.has(WardGateReasons::SENTINEL));
    }

    #[test]
    fn critical_pressure_quarantine() {
        let req = WardGateRequest { pressure: 3, mem_free_mib: 512, ..Default::default() };
        let (v, r) = evaluate_ward_gate(&req);
        assert_eq!(v, WardGateVerdict::Quarantine);
        assert!(r.has(WardGateReasons::PRESSURE_CRIT));
    }

    #[test]
    fn slow_tok_throttle() {
        let req = WardGateRequest { pressure: 2, tok_s: 2, mem_free_mib: 512, ..Default::default() };
        let (v, r) = evaluate_ward_gate(&req);
        assert_eq!(v, WardGateVerdict::Throttle);
        assert!(r.has(WardGateReasons::TOK_RATE));
    }

    #[test]
    fn resonance_quarantine() {
        let req = WardGateRequest { resonance: 90, mem_free_mib: 512, ..Default::default() };
        let (v, r) = evaluate_ward_gate(&req);
        assert_eq!(v, WardGateVerdict::Quarantine);
        assert!(r.has(WardGateReasons::RESONANCE));
    }

    #[test]
    fn consec_escalates_throttle_to_quarantine() {
        let req = WardGateRequest {
            pressure: 2, tok_s: 2, mem_free_mib: 512,
            consec_non_allow: 3, ..Default::default()
        };
        let (v, r) = evaluate_ward_gate(&req);
        // Base: THROTTLE → escalated to QUARANTINE
        assert_eq!(v, WardGateVerdict::Quarantine);
        assert!(r.has(WardGateReasons::CONSEC_DENY));
    }

    #[test]
    fn stateful_gate_tracks_consec() {
        let mut gate = WardGateState::new();
        let req = WardGateRequest { pressure: 2, tok_s: 2, mem_free_mib: 512, ..Default::default() };
        for _ in 0..3 {
            gate.evaluate(req);
        }
        // After 3 consecutive THROTTLE, next should escalate to QUARANTINE
        let (v, _) = gate.evaluate(req);
        assert!(v >= WardGateVerdict::Quarantine);
    }

    #[test]
    fn verdict_from_str_roundtrip() {
        for s in ["ALLOW", "THROTTLE", "QUARANTINE", "FORBID", "EMERGENCY"] {
            let v = WardGateVerdict::from_str(s).unwrap();
            assert_eq!(v.as_str(), s);
        }
    }
}

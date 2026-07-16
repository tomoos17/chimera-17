# brain/state.py — CHIMERA-17 Bloodstream
# The shared state that connects every module.
# Every component reads and writes to this single object.

import time
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class Finding:
    source: str = ""          # "sword" or "shield"
    finding_type: str = ""    # "vulnerability", "threat", "info"
    severity: str = ""        # "critical", "high", "medium", "low", "info"
    title: str = ""           # short description
    description: str = ""     # full details
    evidence: str = ""        # raw data that triggered this
    confidence: float = 0.0   # 0-100%
    verdict: str = ""         # "confirmed", "suspicious", "false_positive"
    timestamp: float = field(default_factory=time.time)

@dataclass
class TargetProfile:
    ip: str = ""
    domain: str = ""
    ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    banners: Dict[int, str] = field(default_factory=dict)
    os: str = ""
    smb_info: str = ""
    anonymous_login: bool = False

class ChimeraState:
    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = time.time()
        
        # Target intelligence
        self.target = TargetProfile()
        
        # All findings from every module
        self.findings: List[Finding] = []
        
        # Sword stats
        self.sword: Dict[str, Any] = {
            "targets_probed": 0,
            "vulns_found": 0,
        }
        
        # Shield stats
        self.shield: Dict[str, Any] = {
            "threats_detected": 0,
            "logs_analysed": 0,
        }
        
        # Brain stats
        self.brain: Dict[str, Any] = {
            "queries_to_ai": 0,
            "models_used": {},
        }

    def add_finding(self, finding: Finding):
        with self._lock:
            self.findings.append(finding)
            
            if finding.source == "sword":
                self.sword["vulns_found"] += 1
            elif finding.source == "shield":
                self.shield["threats_detected"] += 1

    def get_stats(self) -> Dict[str, Any]:
        return {
            "uptime": round(time.time() - self.start_time, 1),
            "total_findings": len(self.findings),
            "sword": self.sword.copy(),
            "shield": self.shield.copy(),
            "brain": self.brain.copy(),
        }
    
    def summary(self) -> str:
        s = self.get_stats()
        return (
            f"[CHIMERA] Uptime: {s['uptime']}s | "
            f"Findings: {s['total_findings']} | "
            f"Threats: {s['shield']['threats_detected']} | "
            f"Vulns: {s['sword']['vulns_found']}"
        )
    
if __name__ == "__main__":
    state = ChimeraState()
    
    finding = Finding(
        source="sword",
        finding_type="info",
        severity="medium",
        title="Test finding",
        description="Testing the bloodstream",
        evidence="test"
    )
    
    state.add_finding(finding)
    print(state.summary())
    print("[PASS] Bloodstream is alive.")
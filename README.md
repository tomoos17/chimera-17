# CHIMERA-17

> An AI security organism that thinks, adapts, and acts — autonomously.

CHIMERA-17 is a fully local AI security system that can both attack and defend simultaneously. Both sides are connected through a shared intelligence — when the defensive side detects an attack, the offensive side learns from it. When the offensive side finds a vulnerability, the defensive side watches for it. It thinks on its own, acts on its own, and gets smarter every engagement.

No cloud. No paid APIs. Runs entirely on your machine.

---

## What Makes It Different

Every other security tool is either a red team tool or a blue team tool. CHIMERA-17 is both — and the two sides talk to each other continuously through a shared state called the **bloodstream**.

It also has self-awareness. CHIMERA knows what it is doing, why it is doing it, and what it has learned. It is not a script you run. It is an organism you deploy.

---

## Core Components

| Component | Role |
|-----------|------|
| **Shield** | Defensive — detects threats, analyses scans and logs |
| **Sword** | Offensive — hunts vulnerabilities, probes targets |
| **Brain** | Routes decisions to the right AI model based on priority |
| **Bloodstream** | Shared state connecting every component in real time |
| **Ghost** | Stealth layer — evasion, identity rotation, WAF bypass |
| **Learning** | Autonomous reinforcement learning + manual teaching mode |

---

## How It Thinks

CHIMERA uses a **curiosity score** (0–10) to decide how interesting something is and which AI model should analyse it.

- Score ≥ 7 → Mistral 7B (deep analysis)
- Score ≥ 4 → Phi-3 Mini (quick triage)
- Score < 4 → Rule-based (no AI compute wasted)

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) running locally
- Models: `mistral`, `phi3`, `llama3`

---

## Status

Active development. Building module by module.

---

*Author: Thomas Gabriel Naduvilaveedu Martin*  
*BSc (Hons) Cybersecurity & Networks — University of Plymouth*

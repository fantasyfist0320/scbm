# Repository Overview

## What It Does

**AetherAudit / AetherFuzz** is an agentic smart contract security auditing and fuzzing framework. It automates vulnerability detection in Solidity contracts using:

- **Static analysis** — Slither integration + 40+ custom detectors (DeFi, oracle manipulation, MEV, reentrancy, access control, etc.)
- **AI-powered analysis** — OpenAI / Gemini LLM ensemble with multi-agent consensus to reduce false positives
- **Dynamic fuzzing** — Foundry/Anvil-based property testing with seed mutation and coverage tracking
- **Exploit PoC generation** — Automatic Foundry test generation for bug bounty submissions

Supports multiple EVM chains (Ethereum, Polygon, Arbitrum, Base, Avalanche, Fantom, BSC) and can fetch contracts from Etherscan or audit entire GitHub repositories.

## Tech Stack

| Layer              | Technology                                   |
|--------------------|----------------------------------------------|
| Language           | Python 3.8+                                  |
| Static Analysis    | Slither 0.10.0                               |
| Blockchain Tools   | Foundry/Anvil, Web3.py, eth-account          |
| AI/LLM            | OpenAI (GPT-4/4o/5-mini), Google Gemini      |
| CLI/UI             | Click, Rich, Questionary                     |
| Web API            | FastAPI, Uvicorn                             |
| Database           | SQLite                                       |
| Dev Tools          | Black, isort, Flake8, mypy, pytest, mkdocs   |

## Main Entry Points

| File | Description |
|------|-------------|
| `main.py` | CLI entry point — Click commands: `audit`, `fuzz`, `run`, `foundry`, `fetch`, `report`, `db`, `config`, `console`, `version` |
| `cli/main.py` | `AetherCLI` class — core CLI logic |
| `cli/console.py` | Interactive Metasploit-style console |
| `blackhole-agent.py` | AI audit agent implementation |
| `core/audit_engine.py` | Main audit orchestrator |
| `core/fuzz_engine.py` | Dynamic fuzzing engine |
| `core/foundry_poc_generator.py` | Automatic PoC generation for bug bounties |

## Key Directories

```
core/           Analysis engines, vulnerability detectors (120+ files)
cli/            Command-line interface
configs/        YAML pipeline definitions (default_audit, enhanced_audit, full_pipeline)
sample-agents/  Example AI audit agents
tests/          Test suite (120+ test files)
reports/        Sample audit reports (Code4rena, Cantina, Immunefi)
scripts/        Helper shell/Python scripts
utils/          Shared utilities (file handling, setup helpers)
data/learning/  Learned patterns and metrics for continuous improvement
```

## CLI Commands

- **`audit`** — Run static + AI analysis on contracts (local paths or GitHub repos)
- **`fuzz`** — Run dynamic fuzzing campaigns (configurable runs/timeout)
- **`run`** — Full audit-fix-fuzz pipeline
- **`foundry`** — Generate Foundry tests and PoCs
- **`fetch`** — Download contract source from blockchain explorers
- **`report`** — Generate reports from audit database
- **`db`** — Database management (stats, exports, cleanup)
- **`config`** — Manage API keys, network settings, triage thresholds
- **`console`** — Interactive console for advanced operations

## Configuration

Required environment variables (see `env.example`):
- `OPENAI_API_KEY`, `GEMINI_API_KEY` — LLM access
- `ETHERSCAN_API_KEY` — Contract fetching
- Network-specific keys: `POLYGONSCAN_API_KEY`, `ARBISCAN_API_KEY`, etc.

Pipeline behavior is configured via YAML files in `configs/`.

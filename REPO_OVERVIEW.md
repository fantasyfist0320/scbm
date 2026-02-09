# Repository Overview

## What It Does

**AetherAudit / AetherFuzz** is an agentic smart contract security auditing and fuzzing framework. It automates vulnerability detection in Solidity contracts using:

- **Static analysis** — Slither integration + 40+ custom detectors (DeFi, oracle manipulation, MEV, reentrancy, access control, cross-protocol, input validation, etc.)
- **AI-powered analysis** — OpenAI / Gemini LLM ensemble (`core/ai_ensemble.py`) with multi-agent consensus and confidence scoring to reduce false positives
- **Dynamic fuzzing** — Foundry/Anvil-based property testing with seed mutation and coverage tracking
- **Exploit PoC generation** — Automatic Foundry test generation for bug bounty submissions
- **Exploit validation** — End-to-end exploit testing and fork verification against live networks

Supports multiple EVM chains (Ethereum, Polygon, Arbitrum, Base, Avalanche, Fantom, BSC) and can fetch contracts from Etherscan or audit entire GitHub repositories.

## Tech Stack

| Layer              | Technology                                   |
|--------------------|----------------------------------------------|
| Language           | Python 3.8+                                  |
| Static Analysis    | Slither 0.10.0                               |
| Blockchain Tools   | Foundry/Anvil, Web3.py, eth-account          |
| AI/LLM            | OpenAI (GPT-4/4o/5-mini), Google Gemini      |
| CLI/UI             | argparse, Rich, Questionary                  |
| Database           | SQLite                                       |
| Dev Tools          | Black, isort, Flake8, mypy, pytest, mkdocs   |

> **Note:** FastAPI and Uvicorn are listed in `requirements.txt` but no server implementation exists in the codebase currently.

## Main Entry Points

| File | Description |
|------|-------------|
| `main.py` | Primary CLI entry point — argparse with 13 subcommands (see below) |
| `aether_console.py` | Alternative entry point — launches interactive console directly |
| `cli/main.py` | `AetherCLI` class — core CLI orchestration logic |
| `cli/console.py` | Interactive Metasploit-style console implementation |
| `blackhole-agent.py` | AI audit agent implementation |
| `setup.py` | Interactive installation and configuration wizard |
| `core/audit_engine.py` | Main audit orchestrator |
| `core/enhanced_audit_engine.py` | Enhanced audit with multiple detector pipelines |
| `core/ai_ensemble.py` | Multi-LLM consensus engine with specialized agents |
| `core/fuzz_engine.py` | Dynamic fuzzing engine |
| `core/foundry_poc_generator.py` | Automatic PoC generation for bug bounties |
| `core/exploit_tester.py` | Exploit code testing against audited contracts |
| `core/exploit_validator.py` | Exploit validation pipeline |

## Key Directories

```
core/                Analysis engines, detectors, validators (120+ files)
  nodes/             Pipeline execution nodes (audit_nodes, fuzz_nodes, enhanced_exploitability_node)
  config/            Detection rules (architectural_patterns.json, validation_rules.json)
cli/                 Command-line interface
configs/             YAML pipeline definitions:
                       default_audit, enhanced_audit, full_pipeline, protocol_protection
sample-agents/       Example AI audit agents (default-agent, cot, agent_hik, etc.)
tests/               Test suite (120+ test files)
reports/             Sample audit reports (Code4rena, Cantina, Immunefi)
scripts/             Helper shell/Python scripts
utils/               Shared utilities (file handling, setup helpers)
data/learning/       Learned patterns and metrics for continuous improvement
```

## CLI Commands (13 total)

**Analysis:**
- **`audit`** — Run static + AI analysis on contracts (local paths or GitHub repos); supports enhanced mode, Phase 3 AI ensemble, Foundry validation, LLM validation, per-contract reports
- **`fuzz`** — Run dynamic fuzzing campaigns (configurable max-runs/timeout)
- **`run`** — Full audit-fix-fuzz pipeline with end-to-end cycle support

**PoC & Exploit Testing:**
- **`foundry`** — Run Foundry validation with PoC generation for bug bounty submissions
- **`generate-foundry`** — Generate Foundry PoCs from `results.json`, audit reports, or database findings
- **`fork-verify`** — Run generated Foundry tests against an Anvil fork of a live network
- **`exploit-test`** — Test generated exploit code against real audited contracts

**Data & Reporting:**
- **`fetch`** — Download contract source from multiple blockchain explorers (Ethereum, Polygon, Arbitrum, Optimism, BSC, Base, Avalanche, Fantom, etc.)
- **`report`** — Generate reports from GitHub audit database in multiple formats (Markdown, JSON, HTML)
- **`db`** — Database management (stats, list audits, export, cleanup)

**Configuration & Utilities:**
- **`config`** — Manage API keys, network settings, triage thresholds, LLM preferences
- **`console`** — Launch interactive Metasploit-style console for advanced operations
- **`version`** — Show version information

## Notable Core Modules

| Module | Purpose |
|--------|---------|
| `ai_ensemble.py` | Multi-LLM consensus with specialized focus agents |
| `enhanced_llm_analyzer.py` | LLM analysis with persistent learning |
| `validation_pipeline.py` | Multi-stage finding validation |
| `finding_deduplicator.py` | Cross-detector deduplication |
| `database_manager.py` | SQLite persistence for audit results and learned patterns |
| `github_auditor.py` | Full GitHub repository auditing |
| `github_audit_report_generator.py` | Report generation from GitHub audits |
| `etherscan_fetcher.py` | Multi-chain contract source fetching |
| `flow_executor.py` | YAML-based pipeline orchestration |
| `performance_optimizer.py` | Optimization for large contract analysis |
| `analysis_cache.py` | Caching layer for repeated analyses |

## Configuration

Required environment variables (see `env.example`):
- `OPENAI_API_KEY`, `GEMINI_API_KEY` — LLM access
- `ETHERSCAN_API_KEY` — Contract fetching
- Network-specific keys: `POLYGONSCAN_API_KEY`, `ARBISCAN_API_KEY`, etc.

Pipeline behavior is configured via YAML files in `configs/`. Detection rules live in `core/config/*.json`.

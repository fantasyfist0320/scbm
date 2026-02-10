import hashlib
import json
import os
import re
import requests
import sys
import time
import traceback
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Tuple
from textwrap import dedent
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel

console = Console()

# =============================================================================
# PHASE 0: DESIGN INFERENCE + COT PREAMBLE
# Prepended to every user message so the LLM reasons about the contract
# before looking for bugs. This is generic — no protocol-specific content.
# =============================================================================

PHASE_0_PREAMBLE = """
============================================================
STEP 1 — UNDERSTAND THE DESIGN (do this FIRST, before looking for bugs)
============================================================

Before searching for vulnerabilities, reason about the protocol's design:

1. What assets/values does the contract manage? How does value enter and exit?
2. What are the trust boundaries? (users vs admins vs keepers vs anyone)
3. What are the accounting invariants? (what must always balance?)
4. Are resources created at predictable identifiers? (CREATE, clones, factory)
5. What external contracts does this depend on? How are their return values used?

============================================================
STEP 2 — TRACE CALL CHAINS
============================================================

For each external/public function:
1. What internal/external functions does it call?
2. What do those return? How is the return value USED? Is the UNIT correct?
3. For each value transfer: what goes IN, what goes OUT, does it balance?

============================================================
STEP 3 — FIND VULNERABILITIES
============================================================

Using your understanding from Steps 1-2, identify bugs matching the system prompt patterns.

============================================================
OUTPUT FORMAT
============================================================

First write your ANALYSIS NOTES — trace value flows, call chains, state transitions,
and access control observations. Think step by step. This is your scratchpad.

Then output your findings as JSON:
{{"vulnerabilities": [...]}}
"""

# =============================================================================
# PROMPT 1: VALUE FLOW & SETTLEMENT
# Covers: token accounting, refunds, return value confusion, slippage
# All patterns are described by their MECHANICS, not by protocol names.
# =============================================================================

SYSTEM_VALUE_FLOW = """
You are an expert smart contract security auditor focused on VALUE FLOW correctness.

============================================================
A. SETTLEMENT & REFUND SAFETY
============================================================

For EACH function that takes value then returns/refunds:
1. What is the REQUESTED amount (parameter) vs ACTUAL amount consumed?
2. Is the refund computed from the REQUESTED amount or the ACTUAL amount?
3. CRITICAL BUG PATTERN: Function debits the actual amount but refunds
   (requested - actual). If requested was never fully taken, the refund
   is free money — pure protocol loss.
4. Watch for TWO fixes applied simultaneously: code changed to take(actual)
   AND added refund(requested - actual) — both together = double benefit.

For Rust/Stylus contracts specifically:
- Trace take(from, amount_in) vs transfer_to_sender(original - amount_in)
- BUG if original was never taken but the difference is still refunded
- Watch for checked_sub() / saturating_sub() silently masking errors

============================================================
B. RETURN VALUE UNIT CONFUSION
============================================================

Trace return values through call chains:
- Does a deploy/deposit function return ASSETS deposited or SHARES received?
- Does an undeploy/withdraw function return ASSETS withdrawn or SHARES burned?
- Does the caller treat the return value as the correct unit?
- Vault standards (e.g., ERC4626): deposit(assets) returns SHARES, not assets

============================================================
C. MISSING SLIPPAGE / DEADLINE PROTECTION
============================================================

For value-changing operations (swaps, liquidity adds/removes, withdrawals):
- Are minimum output amounts enforced?
- Can transactions be held in the mempool and executed at a stale price?
- Are there deadline parameters that are actually checked?

============================================================
D. PRECISION & ROUNDING ERRORS
============================================================

1. Index/balance desync: division rounds to 0, global index unchanged, but
   per-user lastBalance always updates — rewards permanently lost for small stakers
2. Release rate recalculation: after partial claim or transfer, is remaining
   entitlement recalculated from original total instead of remaining? (BUG)
3. Integer division truncation causing zeroed-out rewards or incorrect ratios

IMPORTANT: Only report SPECIFIC bugs with EXACT functions and EXACT value mismatch.
Do NOT report generic "reentrancy possible" without tracing through the actual code.

***OUTPUT FORMAT***
Return ONLY raw valid JSON. Begin with: {{"vulnerabilities":
{format_instructions}
"""

# =============================================================================
# PROMPT 2: STATE MANAGEMENT & LIFECYCLE
# Covers: paired operation asymmetry, receive/fallback traps, temporal ordering
# =============================================================================

SYSTEM_STATE_LIFECYCLE = """
You are an expert smart contract security auditor focused on STATE CORRECTNESS.

============================================================
A. STATE UPDATE OMISSIONS (CRITICAL)
============================================================

For EVERY state-modifying function, ask:
"What OTHER state variables SHOULD be updated but AREN'T?"

Method:
1. Find a FORWARD operation (deposit, stake, deploy, queue, request)
2. List ALL state variables it modifies
3. Find the REVERSE operation (withdraw, unstake, undeploy, cancel)
4. Verify EACH state variable from step 2 is properly restored/decremented
5. BUG if the reverse operation forgets ANY variable from the forward operation

Common example: deploy() increments a tracking variable, but undeploy() forgets
to decrement it. Result: dependent calculations (fees, profit) use stale values.

============================================================
B. RECEIVE / FALLBACK AUTO-EXECUTION TRAPS (CRITICAL)
============================================================

1. Find receive() or fallback() functions — do they auto-execute logic?
   (e.g., auto-stake, auto-deposit, auto-wrap)
2. Trace ALL paths where native tokens are sent TO this contract:
   - Withdrawals from other protocols, refunds, bridge returns, validator rewards
3. BUG: If a withdrawal sends ETH to the contract and receive() auto-stakes it,
   the withdrawal effectively fails — funds are re-locked instead of returned
4. Check: Should certain senders be exempted from receive() logic?

============================================================
C. PAIRED OPERATION ASYMMETRY
============================================================

For each operation pair (request/cancel, deposit/withdraw, stake/unstake,
lock/unlock, open/close):
- Build a STATE CHANGE TABLE for both directions
- If the forward operation modifies [A, B, C] but reverse only modifies [B, C],
  then A is NEVER RESTORED = BUG
- Pay special attention to buffer/escrow variables and accounting trackers

============================================================
D. TEMPORAL ORDERING / STALE RATE ATTACKS
============================================================

For queued/delayed operations (queue → wait → confirm/execute):
1. What value is locked/snapshot at queue time vs recalculated at execution time?
2. Can adverse events (slashing, fee changes, rate changes) occur between
   queue and execution?
3. BUG: User queues withdrawal at favorable rate, adverse event occurs during
   the delay period, user confirms at the stale (pre-event) rate

============================================================
E. ENUMERATION & ITERATION CORRECTNESS
============================================================

When the contract iterates over a collection (token IDs, validators, positions):
1. Does it assume contiguous/sequential identifiers?
2. Can burns/removals create gaps that break iteration?
3. Does it use totalSupply as an upper bound when IDs can exceed it?

IMPORTANT: Only report with EXACT state variables and EXACT functions.

***OUTPUT FORMAT***
Return ONLY raw valid JSON. Begin with: {{"vulnerabilities":
{format_instructions}
"""

# =============================================================================
# PROMPT 3: ACCESS CONTROL & EXECUTION ENVIRONMENT
# Covers: unrestricted functions, gas griefing, front-running, delegation
# =============================================================================

SYSTEM_ACCESS_ENVIRONMENT = """
You are an expert smart contract security auditor focused on ACCESS CONTROL
and EXECUTION ENVIRONMENT safety.

============================================================
A. ACCESS CONTROL GAPS (CRITICAL — check EVERY external/public function)
============================================================

For EACH external/public function that modifies state:
1. Is it restricted (onlyOwner, onlyRole, onlyKeeper, auth, etc.)?
2. If NOT restricted — SHOULD it be? What's the impact if anyone calls it?
3. CRITICAL: Functions that update accounting (harvest, rebalance, sync,
   compound) without access control let attackers front-run fee collection
   or manipulate exchange rates
4. Functions that accept a 'from' or 'account' parameter for transferFrom —
   is msg.sender == from enforced? If not, anyone can drain approved tokens

============================================================
B. PRIVILEGED ROLE ABUSE WITHIN VALID BOUNDS
============================================================

IMPORTANT: Do NOT dismiss bugs just because a function has an access modifier.
Ask: Can a privileged role (admin, coordinator, keeper, operator) use their
LEGITIMATE powers to harm users while staying within technically valid parameters?

Examples of valid-bounds abuse:
- Setting a fee/rate/timeout to an extreme-but-technically-allowed value
- Choosing parameters that create unfavorable conditions for specific users
- Ordering operations to extract value from pending user positions
- Using parameter-setting authority to manipulate settlement prices

Report these if the impact is concrete and the parameter bounds allow it.

============================================================
C. GAS GRIEFING VIA 63/64 RULE
============================================================

Pattern:
1. Function makes an irreversible state change BEFORE an external call
2. External call via call/delegatecall/send
3. Non-reverting execution path when the subcall fails (try/catch, low-level call)
4. Attacker supplies just enough gas so main function succeeds but subcall
   gets only 1/64th — state is committed, subcall silently fails

============================================================
D. PREDICTABLE IDENTIFIER FRONT-RUNNING
============================================================

1. Does the contract create resources at predictable addresses?
   (CREATE uses sender+nonce, CREATE2 uses salt, Clones.clone() uses nonce)
2. Can an external party predict the address before creation?
3. Does creation REVERT if the resource already exists at that address?
4. BUG: Attacker pre-deploys at predicted address → factory permanently DoS'd
5. Check: existence check? try/catch? random salt?

============================================================
E. DELEGATION & REWARD ROUTING
============================================================

In staking/delegation systems:
- Are reward claims routed to the correct recipient (delegator vs delegatee)?
- Can an intermediary (validator, operator) claim rewards belonging to end users?
- After un-delegation, can the old delegatee still interact with the position?

IMPORTANT: Only report SPECIFIC bugs with CONCRETE exploit paths.

***OUTPUT FORMAT***
Return ONLY raw valid JSON. Begin with: {{"vulnerabilities":
{format_instructions}
"""

# =============================================================================
# PROMPT 4: MATH, CUSTOM LIBRARIES & TYPE SAFETY
# Covers: custom math edge cases, type casting, comparison correctness
# =============================================================================

SYSTEM_MATH_PRECISION = """
You are an expert smart contract security auditor focused on MATHEMATICAL
CORRECTNESS and CUSTOM LIBRARY SAFETY.

============================================================
A. CUSTOM MATH LIBRARY EDGE CASES
============================================================

For ANY custom math operation (sqrt, ln, exp, pow, div, comparison):
1. What happens with ZERO input? Does it revert, return 0, or silently
   produce a wrong result?
2. What happens with NEGATIVE input (for functions like ln)?
   Does it revert or silently produce garbage?
3. For multi-step calculations: is the ORDER OF OPERATIONS correct?
   - Does an early truncation/scaling step cause a later step to use
     wrong magnitude values?
   - Are intermediate results large enough to avoid precision loss?

============================================================
B. CUSTOM TYPE COMPARISON / EQUALITY
============================================================

For custom packed/encoded types (packed floats, fixed-point, encoded structs):
1. Can TWO DIFFERENT internal representations encode the SAME logical value?
   (e.g., different mantissa+exponent pairs representing the same number)
2. Does the equality function normalize before comparing?
3. Does unwrapping/decoding handle ALL internal flags and special bits?
4. BUG: eq(a, b) returns false for mathematically equal values because
   their internal representations differ

============================================================
C. TYPE CASTING & TRUNCATION
============================================================

1. Unsafe downcasts: uint256 → uint128/uint160/uint96 without bounds check
2. Signed/unsigned confusion: int256 cast to uint256 with negative values
3. In Rust: `as` casts that silently truncate (u128 as u64)

============================================================
D. DIVISION & ROUNDING DIRECTION
============================================================

1. Division before multiplication amplifying rounding errors
2. Rounding direction: should it round UP (for protocol safety) or DOWN
   (for user fairness)? Does the code match the intended direction?
3. Division by values that can be zero or near-zero

IMPORTANT: Only report if you can trace the EXACT function and show how
incorrect math leads to concrete value loss or broken invariants.

***OUTPUT FORMAT***
Return ONLY raw valid JSON. Begin with: {{"vulnerabilities":
{format_instructions}
"""

# =============================================================================
# PROMPT 5: CROSS-CONTRACT & EXTERNAL INTEGRATION
# Covers: external calls, callbacks, oracle manipulation, approval drains
# =============================================================================

SYSTEM_EXTERNAL_INTEGRATION = """
You are an expert smart contract security auditor focused on EXTERNAL
INTEGRATION and CROSS-CONTRACT INTERACTION safety.

============================================================
A. EXTERNAL CALL RETURN VALUE HANDLING
============================================================

For EACH external call (.call, .delegatecall, interface calls):
1. Is the return value checked? Is success/failure handled?
2. For low-level calls: is returndata decoded correctly?
3. Can a malicious external contract return unexpected data?

============================================================
B. CALLBACK & REENTRANCY VECTORS
============================================================

1. After token transfers (especially ERC721/ERC777/ERC1155 with callbacks),
   can the recipient re-enter the contract?
2. Is the checks-effects-interactions pattern followed?
3. Are reentrancy guards applied to ALL functions that share state, not
   just the entry point?

============================================================
C. ORACLE & PRICE FEED MANIPULATION
============================================================

1. Are oracle prices validated for staleness (timestamp check)?
2. Can spot prices be manipulated via flash loans?
3. Are TWAP windows long enough to resist manipulation?
4. Does the contract verify oracle decimals match expected precision?

============================================================
D. APPROVAL & ALLOWANCE DRAIN
============================================================

1. Does a router/helper contract hold user approvals?
2. Can an attacker craft a call through the router to drain approved tokens
   belonging to other users?
3. Are approvals properly scoped and reset after use?

============================================================
E. CROSS-LANGUAGE / CROSS-CONTRACT ABI MISMATCH
============================================================

In mixed-language codebases (Solidity + Rust/Stylus, Solidity + Vyper):
1. Do function signatures match across the interface boundary?
2. Are parameter types compatible? (e.g., Solidity uint256 vs Rust U256)
3. Are return value semantics consistent on both sides?

IMPORTANT: Only report with EXACT external calls and CONCRETE attack scenarios.

***OUTPUT FORMAT***
Return ONLY raw valid JSON. Begin with: {{"vulnerabilities":
{format_instructions}
"""

# =============================================================================
# RUST-SPECIFIC BROAD PROMPT
# Used instead of the 5 Solidity prompts when analyzing .rs files
# =============================================================================

SYSTEM_RUST_BROAD = """
You are an expert Rust/Stylus smart contract security auditor.

============================================================
A. VALUE FLOW & SETTLEMENT (RUST)
============================================================

For EACH function handling tokens:
1. What goes IN? (erc20::take, transfer_from, msg_value)
2. What goes OUT? (erc20::transfer, transfer_to_sender)
3. Does IN == OUT for the intended flow?
4. CRITICAL: take(amount_in) then transfer(original - amount_in) is a BUG
   if original was never actually taken. The refund becomes free money.
5. Redundant fix pattern: code changed to take(actual) AND added
   refund(requested - actual) — both fixes together = double benefit

============================================================
B. STATE CORRECTNESS (RUST)
============================================================

1. Are storage writes via self.field.set() properly ordered?
2. Error paths: does the ? operator return BEFORE cleanup code runs?
3. For each paired operation — verify all state is reversed on cancel
4. Does receive() or a payable handler auto-execute logic on incoming transfers?

============================================================
C. ACCESS & ENVIRONMENT (RUST)
============================================================

1. Are pub fn functions properly restricted?
2. #[payable] — what happens with msg_value = 0?
3. Cross-contract calls via RawCall: is return value handled?
4. Reentrancy through callbacks?

============================================================
D. RUST-SPECIFIC PATTERNS
============================================================

- checked_sub(), saturating_sub() masking real calculation errors
- `as` casts that truncate silently (u128 as u64)
- Clone() creating divergent state copies
- sol_storage! macro initialization edge cases
- Multiple return paths where some skip state updates

IMPORTANT: Only report SPECIFIC bugs with EXACT Rust functions and state fields.

***OUTPUT FORMAT***
Return ONLY raw valid JSON. Begin with: {{"vulnerabilities":
{format_instructions}
"""

# =============================================================================
# VERIFICATION PROMPT — used in Phase 2 to confirm/reject findings
# =============================================================================

SYSTEM_VERIFY = """
You are verifying potential vulnerabilities in smart contracts.

For each finding, verify:

1. CODE GROUNDING: Does the described function/variable/pattern actually exist
   in the provided code?
2. MECHANISM: Trace the described attack step-by-step through the actual code.
   Does each step work as claimed?
3. IMPACT: Would successful exploitation cause real harm?
   (fund loss, permanent DoS, broken accounting)

Verdicts:
- CONFIRMED: Bug mechanism checks out, functions exist, impact is real.
- UNCERTAIN: Function exists, mechanism plausible but hard to fully trace.
- REJECTED: Function doesn't exist, mechanism contradicts code,
  purely informational, Solidity 0.8+ overflow without unchecked block,
  test/mock file only, or requires admin to act maliciously with no
  legitimate reason.

When in doubt between UNCERTAIN and REJECTED, prefer UNCERTAIN.

Return JSON:
{{
    "verifications": [
        {{
            "index": 0,
            "verdict": "CONFIRMED",
            "reasoning": "Brief explanation",
            "adjusted_severity": "critical",
            "adjusted_confidence": 0.9
        }}
    ]
}}
"""

# =============================================================================
# FALSE-POSITIVE FILTER PATTERNS
# =============================================================================

KNOWN_FP_PATTERNS = [
    r'missing\s+events?\s+emission',
    r'floating\s+pragma',
    r'missing\s+natspec',
    r'code\s+style',
    r'gas\s+optimization',
    r'lack\s+of\s+documentation',
    r'missing\s+zero\s+address\s+check',
    r'^centralization\s+risk$',
    r'single\s+point\s+of\s+failure',
    r'no\s+event\s+emitted',
    r'missing\s+input\s+validation\s+for\s+zero',
]

SOLIDITY_08_FP_PATTERNS = [
    r'integer\s+overflow(?!\s+in\s+unchecked)',
    r'integer\s+underflow(?!\s+in\s+unchecked)',
    r'arithmetic\s+overflow(?!\s+in\s+unchecked)',
    r'arithmetic\s+underflow(?!\s+in\s+unchecked)',
]


# =============================================================================
# MODELS
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Vulnerability(BaseModel):
    title: str
    description: str
    vulnerability_type: str
    severity: Severity
    confidence: float
    location: str
    file: str
    id: str | None = None
    reported_by_model: str = ""
    status: str = "proposed"

    def __init__(self, **data):
        super().__init__(**data)
        if not self.id:
            id_source = f"{self.file}:{self.title}:{self.location[:50]}"
            self.id = hashlib.md5(id_source.encode()).hexdigest()[:16]


class Vulnerabilities(BaseModel):
    vulnerabilities: list[Vulnerability]


class AnalysisResult(BaseModel):
    project: str
    timestamp: str
    files_analyzed: int
    files_skipped: int
    total_vulnerabilities: int
    vulnerabilities: list[Vulnerability]
    token_usage: dict[str, int]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def detect_language(file_path: Path) -> str:
    suffix = file_path.suffix.lower()
    return {'sol': 'solidity', 'vy': 'vyper', 'rs': 'rust'}.get(
        suffix.lstrip('.'), 'solidity'
    )


def get_code_lang(language: str) -> str:
    return {'solidity': 'solidity', 'vyper': 'python', 'rust': 'rust'}.get(
        language, 'solidity'
    )


def is_test_or_mock(file_path: Path) -> bool:
    name_lower = file_path.name.lower()
    path_lower = str(file_path).lower()
    for indicator in ['test', 'mock', 'fake', 'stub', 'fixture']:
        if indicator in name_lower or f'/{indicator}/' in path_lower:
            return True
    return False


def is_interface_only(file_path: Path, content: str = "") -> bool:
    name = file_path.name
    if name.startswith('I') and len(name) > 1 and name[1].isupper() and file_path.suffix == '.sol':
        return True
    if content and 'interface ' in content and 'function ' in content:
        if not re.findall(r'function\s+\w+[^;]*\{', content):
            return True
    return False


def extract_solidity_version(content: str) -> str:
    match = re.search(r'pragma\s+solidity\s*[\^~>=<]*\s*(\d+\.\d+)', content)
    return match.group(1) if match else "0.8"


def is_solidity_08_plus(content: str) -> bool:
    version = extract_solidity_version(content)
    try:
        major, minor = map(int, version.split('.')[:2])
        return major > 0 or minor >= 8
    except Exception:
        return True


def pre_filter_finding(vuln: Vulnerability, content: str) -> Tuple[bool, str]:
    """Return (should_filter, reason) — True means discard this finding."""
    combined = f"{vuln.title.lower()} {vuln.description.lower()}"

    for pattern in KNOWN_FP_PATTERNS:
        if re.search(pattern, combined):
            return True, f"Known FP pattern: {pattern[:30]}"

    if is_solidity_08_plus(content):
        for pattern in SOLIDITY_08_FP_PATTERNS:
            if re.search(pattern, combined) and 'unchecked' not in combined:
                return True, "Solidity 0.8+ has built-in overflow protection"

    return False, ""


def extract_state_mapping(content: str, language: str) -> str:
    """Extract state variables and which functions modify them."""
    if language == 'rust':
        field_vars = set(re.findall(
            r'self\.(\w+)\s*(?:\.|\.get|\.set|\.insert|\.remove|\+=|-=|=)', content
        ))
        if not field_vars:
            return ""
        func_pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
        functions = re.findall(func_pattern, content, re.DOTALL)
        lines = ["RUST STATE MAPPING:"]
        for func_name, func_body in functions[:30]:
            writes = []
            for var in field_vars:
                if re.search(rf'self\.{re.escape(var)}\s*(?:\.|\.set|\.insert|\+=|-=|=(?!=))', func_body):
                    writes.append(var)
            if writes:
                lines.append(f"  {func_name}() MODIFIES: {', '.join(set(writes))}")
        return '\n'.join(lines[:25]) if len(lines) > 1 else ""

    # Solidity
    state_pattern = r'^\s*(mapping\s*\([^)]+\)|uint\d*|int\d*|bool|address|bytes\d*|string)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*[;=]'
    state_vars = re.findall(state_pattern, content, re.MULTILINE)
    var_names = [name for _, name in state_vars]
    if not var_names:
        return ""

    func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    functions = re.findall(func_pattern, content, re.DOTALL)

    lines = ["STATE VARIABLE MAPPING:"]
    for func_name, func_body in functions[:30]:
        writes = []
        for var in var_names:
            if re.search(rf'\b{re.escape(var)}\b\s*[\+\-\*\/]?=(?!=)', func_body):
                writes.append(var)
            if re.search(rf'delete\s+{re.escape(var)}', func_body):
                writes.append(f"delete:{var}")
        if writes:
            lines.append(f"  {func_name}() MODIFIES: {', '.join(set(writes))}")

    return '\n'.join(lines[:25]) if len(lines) > 1 else ""


def extract_call_graph(content: str, language: str) -> str:
    """Extract which functions call which, with access control info."""
    if language == 'solidity':
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*((?:(?:public|external|internal|private|view|pure|payable|virtual|override|nonReentrant|onlyOwner|onlyRole\([^)]*\)|returns\s*\([^)]*\))\s*)*)\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
    elif language == 'rust':
        func_pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(([^)]*)\)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
    else:
        return ""

    functions = re.findall(func_pattern, content, re.DOTALL)
    if not functions:
        return ""

    all_func_names = {m[0] for m in functions}
    lines = ["CALL GRAPH:"]

    for match in functions[:30]:
        if language == 'solidity':
            func_name, _params, modifiers, func_body = match
            visibility = 'internal'
            for v in ('external', 'public', 'private'):
                if v in modifiers:
                    visibility = v
                    break
            access = ""
            if 'onlyOwner' in modifiers or 'onlyRole' in modifiers:
                access = " [RESTRICTED]"
            elif visibility in ('external', 'public'):
                access = " [ANYONE]" if 'view' not in modifiers and 'pure' not in modifiers else ""
        else:
            func_name, _params, func_body = match
            access = ""

        internal_calls = set()
        for other in all_func_names:
            if other != func_name and re.search(rf'\b{other}\s*\(', func_body):
                internal_calls.add(other)

        external_calls = set(re.findall(r'(\w+\.\w+)\s*\(', func_body))
        skip = {'msg.', 'block.', 'abi.', 'tx.', 'type.'}
        external_calls = {c for c in external_calls if not any(c.startswith(p) for p in skip)}

        if internal_calls or external_calls or access:
            calls = sorted(internal_calls) + [f"[EXT]{c}" for c in sorted(external_calls)]
            call_str = f" -> {', '.join(calls)}" if calls else ""
            lines.append(f"  {func_name}(){access}{call_str}")

    return '\n'.join(lines) if len(lines) > 1 else ""


def deduplicate_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Semantic deduplication across prompts."""
    if not vulnerabilities:
        return []

    sorted_vulns = sorted(vulnerabilities, key=lambda x: -x.confidence)
    deduped = []

    for vuln in sorted_vulns:
        is_dup = False
        vuln_words = set(re.findall(r'\w{4,}', vuln.title.lower()))

        for existing in deduped:
            if vuln.file != existing.file:
                continue
            # Same vuln type + same location prefix
            if vuln.vulnerability_type == existing.vulnerability_type and vuln.location[:30] == existing.location[:30]:
                is_dup = True
                break
            # Same title prefix
            if vuln.title.lower()[:40] == existing.title.lower()[:40]:
                is_dup = True
                break
            # High word overlap in titles
            existing_words = set(re.findall(r'\w{4,}', existing.title.lower()))
            if vuln_words and existing_words:
                overlap = len(vuln_words & existing_words) / max(len(vuln_words | existing_words), 1)
                if overlap > 0.6:
                    is_dup = True
                    break
            # Same functions mentioned + same vuln type
            stopwords = {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return'}
            vuln_funcs = set(re.findall(r'(\w+)\s*\(', vuln.description[:300])) - stopwords
            existing_funcs = set(re.findall(r'(\w+)\s*\(', existing.description[:300])) - stopwords
            if len(vuln_funcs & existing_funcs) >= 2 and vuln.vulnerability_type == existing.vulnerability_type:
                is_dup = True
                break

        if not is_dup:
            deduped.append(vuln)

    return deduped


def compute_specificity_score(finding: Vulnerability, file_content: str = "") -> float:
    """Score how specific/grounded a finding is."""
    score = 0.0
    desc = finding.description

    # Check if quoted code actually exists in the file
    if file_content:
        quotes = re.findall(r'`([^`]+)`', desc)
        for q in quotes:
            if len(q) > 5 and q in file_content:
                score += 0.15
                break

    # Function references
    score += min(len(re.findall(r'\b[a-zA-Z_]\w+\s*\(\)', desc)) * 0.08, 0.24)
    # State variable references
    score += min(len(re.findall(
        r'\b\w+(?:Amount|Balance|Counter|Index|Rate|Buffer|Total|Supply|Nonce)\b', desc, re.I
    )) * 0.1, 0.2)
    # Concrete values
    if re.search(r'\d+\s*(?:wei|ether|gwei|gas|%|x\b)', desc, re.I):
        score += 0.1
    # Step-by-step exploit
    if re.search(r'(?:step\s*\d|1\.\s*\w|first.*then)', desc, re.I):
        score += 0.1

    return min(score * finding.confidence, 1.0)


# =============================================================================
# MAIN RUNNER
# =============================================================================

class ImprovedRunner:
    def __init__(self, config: dict[str, Any] | None = None, inference_api: str = None):
        self.config = config or {}
        self.model = self.config.get('model', 'Qwen/Qwen3-Next-80B-A3B-Instruct')
        self.inference_api = inference_api or os.getenv('INFERENCE_API', "http://bitsec_proxy:8000")
        self.project_id = os.getenv('PROJECT_ID', "local")
        self.job_id = os.getenv('JOB_ID', "local")

        console.print(f"[cyan]Model: {self.model}[/cyan]")
        console.print(f"[cyan]API: {self.inference_api}[/cyan]")

    # -----------------------------------------------------------------
    # INFERENCE
    # -----------------------------------------------------------------

    def inference(self, messages: list, model: str | None = None,
                  timeout: int = 180, temperature: float = 0.1) -> dict:
        payload = {
            "model": model or self.model,
            "messages": messages,
            "temperature": temperature,
        }
        headers = {
            "x_project_id": self.project_id,
            "x_job_id": self.job_id,
        }

        resp = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    f"{self.inference_api}/inference",
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                )
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.RequestException as e:
                error_detail = "No response"
                if resp is not None:
                    try:
                        error_detail = resp.json()
                    except Exception:
                        error_detail = resp.text[:200] if hasattr(resp, 'text') else str(resp)
                console.print(f"[yellow]Inference error (attempt {attempt+1}/3): {e} — {error_detail}[/yellow]")
                if attempt < 2:
                    time.sleep(10 + attempt * 10)
                else:
                    raise
        return {}

    # -----------------------------------------------------------------
    # JSON PARSING (supports CoT reasoning before JSON)
    # -----------------------------------------------------------------

    def clean_json(self, response: str) -> dict:
        response = response.strip()

        # Remove code block markers
        if "```" in response:
            lines = response.split('\n')
            lines = [l for l in lines if not l.strip().startswith("```")]
            response = '\n'.join(lines)

        # Find all top-level JSON objects, prefer one with "vulnerabilities"
        candidates = []
        i = 0
        while i < len(response):
            if response[i] == '{':
                depth = 0
                for j in range(i, len(response)):
                    if response[j] == '{':
                        depth += 1
                    elif response[j] == '}':
                        depth -= 1
                    if depth == 0:
                        try:
                            parsed = json.loads(response[i:j+1])
                            if isinstance(parsed, dict):
                                candidates.append(parsed)
                        except Exception:
                            pass
                        i = j + 1
                        break
                else:
                    i += 1
            else:
                i += 1

        for c in candidates:
            if "vulnerabilities" in c:
                return c
        for c in candidates:
            if "findings" in c:
                return {"vulnerabilities": c["findings"]}
        if candidates:
            largest = max(candidates, key=lambda x: len(str(x)))
            if "vulnerabilities" not in largest:
                largest["vulnerabilities"] = []
            return largest

        return {"vulnerabilities": []}

    def safe_parse_vulns(self, result: dict) -> List[Vulnerability]:
        try:
            raw = result.get('vulnerabilities', [])
            if not isinstance(raw, list):
                return []
            return list(Vulnerabilities(vulnerabilities=raw).vulnerabilities)
        except Exception as e:
            console.print(f"[dim]    Parse warning: {e}[/dim]")
            return []

    # -----------------------------------------------------------------
    # FILE DISCOVERY
    # -----------------------------------------------------------------

    def find_files(self, source_dir: Path) -> List[Path]:
        exclude = {
            'node_modules', 'test', 'tests', 'script', 'scripts',
            'mocks', 'mock', 'lib', '.git', 'cache', 'out', 'forge-std',
            'interfaces', 'artifacts', 'dist', 'build'
        }

        files = []
        for pattern in ['**/*.sol', '**/*.vy', '**/*.cairo', '**/*.rs', '**/*.move']:
            files.extend(source_dir.glob(pattern))

        def should_include(f: Path) -> bool:
            if not f.is_file():
                return False
            if is_test_or_mock(f):
                return False
            for part in f.parts:
                if part.lower() in exclude:
                    return False
            return True

        files = list(set(f for f in files if should_include(f)))

        # Out-of-scope filtering
        oos_path = source_dir / 'out_of_scope.txt'
        if oos_path.exists():
            try:
                with open(oos_path) as f:
                    oos = {l.strip() for l in f if l.strip() and not l.startswith('#')}
                files = [f for f in files if not any(
                    s in str(f.relative_to(source_dir)) or
                    f"./{f.relative_to(source_dir).as_posix()}" == s or
                    f.name == s
                    for s in oos
                )]
            except Exception as e:
                console.print(f"[yellow]Warning reading out_of_scope.txt: {e}[/yellow]")

        # Priority sort: .sol > .vy > .cairo > .rs > others, then by depth
        def ext_priority(f):
            ext = f.suffix.lower()
            order = {'.sol': 0, '.vy': 1, '.cairo': 2, '.rs': 3}
            return (order.get(ext, 4), len(f.parts), str(f))

        return sorted(files, key=ext_priority)

    # -----------------------------------------------------------------
    # RELATED FILE DISCOVERY (regex-based, no LLM call needed)
    # -----------------------------------------------------------------

    def get_related_content(self, file_path: Path, all_files: List[Path],
                            source_dir: Path) -> str:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        language = detect_language(file_path)

        if language == 'rust':
            import_pattern = r'(?:use\s+(?:crate|super|self)::(\w+)|mod\s+(\w+))'
            imports = [m[0] or m[1] for m in re.findall(import_pattern, content)]
            inherits = []
        elif language == 'vyper':
            import_pattern = r'(?:from\s+\S+\s+import\s+(\w+)|import\s+(\w+))'
            imports = [m[0] or m[1] for m in re.findall(import_pattern, content)]
            inherits = []
        else:
            import_pattern = r'import\s+(?:\{[^}]+\}\s+from\s+)?["\']([^"\']+)["\']'
            imports = re.findall(import_pattern, content)
            inherit_pattern = r'contract\s+\w+\s+is\s+([^{]+)'
            inherits = []
            for match in re.findall(inherit_pattern, content):
                inherits.extend([p.strip().split('(')[0].strip() for p in match.split(',')])

        related = []
        for term in imports + inherits:
            term_clean = (term.replace('./', '').replace('../', '')
                         .replace('.sol', '').replace('.rs', '').split('/')[-1])
            for f in all_files:
                if term_clean in f.stem and f != file_path and f not in related:
                    related.append(f)

        parts = []
        total_len = 0
        max_len = 20000

        for rf in related[:6]:
            try:
                with open(rf, 'r', encoding='utf-8') as f:
                    rc = f.read()
                if total_len + len(rc) < max_len:
                    rf_lang = detect_language(rf)
                    rel = rf.relative_to(source_dir)
                    parts.append(f"\nRELATED FILE: {rel}\n```{get_code_lang(rf_lang)}\n{rc}\n```")
                    total_len += len(rc)
            except Exception:
                pass

        return '\n'.join(parts)

    # -----------------------------------------------------------------
    # PHASE 1: BROAD SWEEP WITH COT
    # -----------------------------------------------------------------

    def analyze_file_with_prompt(
        self, source_dir: Path, relative_path: str, related_content: str,
        analysis_model: str, system_prompt: str, prompt_name: str,
    ) -> Tuple[List[Vulnerability], int, int]:
        file_path = Path(relative_path)

        with open(source_dir / file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        language = detect_language(file_path)
        code_lang = get_code_lang(language)

        if is_interface_only(file_path, content):
            console.print(f"[dim]  -> {file_path.name} (skipped: interface)[/dim]")
            return [], 0, 0

        console.print(f"[dim]  -> {file_path.name} ({prompt_name}) [{language}][/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        system = system_prompt.format(format_instructions=parser.get_format_instructions())

        # Pre-computed static analysis context
        state_mapping = extract_state_mapping(content, language)
        call_graph = extract_call_graph(content, language)

        context_sections = ""
        if state_mapping:
            context_sections += f"\n{state_mapping}\n"
        if call_graph:
            context_sections += f"\n{call_graph}\n"

        lang_hint = ""
        if language == 'rust':
            lang_hint = "\nThis is a Rust/Stylus smart contract. Look for erc20::take(), transfer_to_sender(), self.field.set/get(), ? operator paths.\n"
        elif language == 'vyper':
            lang_hint = "\nThis is a Vyper contract. Look for @external/@internal, send(), raw_call(), self.variable.\n"

        user_msg = f"""{PHASE_0_PREAMBLE}

PRIMARY FILE: {file_path}
```{code_lang}
{content}
```
{context_sections}
{lang_hint}
{related_content}

For each vulnerability found:
- Name the EXACT function and call chain
- Describe the EXACT code behavior with specific state variable names
- Give CONCRETE exploit steps
"""

        try:
            response = self.inference(
                [{"role": "system", "content": system},
                 {"role": "user", "content": user_msg}],
                model=analysis_model,
                timeout=240,
            )

            result = self.clean_json(response.get('content', '{}'))
            vuln_list = self.safe_parse_vulns(result)

            validated = []
            for v in vuln_list:
                v.file = str(file_path)
                v.reported_by_model = f"{analysis_model}_{prompt_name}"

                should_filter, reason = pre_filter_finding(v, content)
                if should_filter:
                    console.print(f"[dim]    Filtered: {v.title[:40]} ({reason})[/dim]")
                    continue

                if v.confidence >= 0.6:
                    validated.append(v)

            if validated:
                console.print(f"[green]    Found {len(validated)} potential issues[/green]")

            return validated, response.get('input_tokens', 0), response.get('output_tokens', 0)

        except Exception as e:
            console.print(f"[red]    Error: {e}[/red]")
            return [], 0, 0

    # -----------------------------------------------------------------
    # PHASE 2: VERIFICATION
    # -----------------------------------------------------------------

    def verify_findings(self, source_dir: Path, findings: List[Vulnerability],
                        file_contents: Dict[str, str], verify_model: str) -> List[Vulnerability]:
        if not findings:
            return []

        console.print(f"\n[cyan]Phase 2: Verifying {len(findings)} findings...[/cyan]")

        verified = []
        by_file: Dict[str, List[Vulnerability]] = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)

        for file_path, file_findings in by_file.items():
            content = file_contents.get(file_path, "")
            if not content:
                try:
                    with open(source_dir / file_path, 'r') as fh:
                        content = fh.read()
                except Exception:
                    verified.extend(file_findings)
                    continue

            language = detect_language(Path(file_path))
            code_lang = get_code_lang(language)

            for batch_start in range(0, len(file_findings), 5):
                batch = file_findings[batch_start:batch_start + 5]

                findings_json = json.dumps([{
                    "index": i, "title": f.title, "description": f.description[:400],
                    "vulnerability_type": f.vulnerability_type, "severity": f.severity.value,
                    "location": f.location,
                } for i, f in enumerate(batch)], indent=2)

                code_for_verify = content[:25000]

                verify_prompt = f"""Verify these findings against the code.

CODE ({file_path}):
```{code_lang}
{code_for_verify}
```

FINDINGS:
{findings_json}

For each finding:
- CONFIRM if the described mechanism checks out in the actual code
- UNCERTAIN if plausible but hard to fully trace
- REJECT if wrong (function doesn't exist, mechanism contradicts code, etc.)

Return JSON:
{{"verifications": [{{"index": 0, "verdict": "CONFIRMED", "reasoning": "...", "adjusted_severity": "high", "adjusted_confidence": 0.8}}]}}
"""

                try:
                    response = self.inference(
                        [{"role": "system", "content": SYSTEM_VERIFY},
                         {"role": "user", "content": verify_prompt}],
                        model=verify_model, timeout=120
                    )
                    result = self.clean_json(response.get('content', '{}'))

                    for i, finding in enumerate(batch):
                        v_result = next(
                            (v for v in result.get('verifications', []) if v.get('index') == i),
                            None
                        )

                        if v_result is None:
                            if finding.confidence >= 0.8:
                                verified.append(finding)
                        elif v_result.get('verdict', '').upper() == 'CONFIRMED':
                            if v_result.get('adjusted_severity'):
                                try:
                                    finding.severity = Severity(v_result['adjusted_severity'].lower())
                                except Exception:
                                    pass
                            if v_result.get('adjusted_confidence') is not None:
                                try:
                                    finding.confidence = float(v_result['adjusted_confidence'])
                                except Exception:
                                    pass
                            finding.status = "verified"
                            verified.append(finding)
                            console.print(f"[green]  V {finding.title[:60]}[/green]")
                        elif v_result.get('verdict', '').upper() == 'UNCERTAIN':
                            finding.confidence = max(finding.confidence - 0.1, 0.5)
                            if finding.confidence >= 0.7 or finding.severity.value in ('critical', 'high'):
                                finding.status = "uncertain"
                                verified.append(finding)
                                console.print(f"[yellow]  ~ {finding.title[:60]}[/yellow]")
                        else:
                            console.print(f"[dim]  X {finding.title[:60]}[/dim]")

                except Exception as e:
                    console.print(f"[yellow]  Verify error: {e}[/yellow]")
                    for f in batch:
                        if f.confidence >= 0.8:
                            verified.append(f)

        return verified

    # -----------------------------------------------------------------
    # MAIN ORCHESTRATOR
    # -----------------------------------------------------------------

    def analyze_project(
        self,
        source_dir: Path,
        project_name: str,
        file_patterns: list[str] | None = None
    ) -> AnalysisResult:
        console.print(f"\n[bold cyan]=== Analyzing: {project_name} ===[/bold cyan]")

        analysis_model = self.config.get('analysis_model', self.model)
        verify_model = self.config.get('verify_model', self.model)
        max_threads = 8

        # Find files
        files = self.find_files(source_dir)
        if not files:
            console.print("[yellow]No files found to analyze[/yellow]")
            return AnalysisResult(
                project=project_name, timestamp=datetime.now().isoformat(),
                files_analyzed=0, files_skipped=0, total_vulnerabilities=0,
                vulnerabilities=[],
                token_usage={'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}
            )

        max_files = min(len(files), 20)
        files_to_analyze = files[:max_files]
        console.print(f"[dim]Found {len(files)} files, analyzing {len(files_to_analyze)}[/dim]")

        # Pre-compute context
        related_map = {}
        file_contents: Dict[str, str] = {}
        for f in files_to_analyze:
            related_map[f] = self.get_related_content(f, files, source_dir)
            rel_path = str(f.relative_to(source_dir))
            try:
                with open(f, 'r', encoding='utf-8') as fh:
                    file_contents[rel_path] = fh.read()
            except Exception:
                pass

        # Prompt selection per language
        solidity_prompts = [
            (SYSTEM_VALUE_FLOW, 'value_flow'),
            (SYSTEM_STATE_LIFECYCLE, 'state_lifecycle'),
            (SYSTEM_ACCESS_ENVIRONMENT, 'access_env'),
            (SYSTEM_MATH_PRECISION, 'math_precision'),
            (SYSTEM_EXTERNAL_INTEGRATION, 'external_integration'),
        ]

        rust_prompts = [
            (SYSTEM_RUST_BROAD, 'rust_broad'),
            (SYSTEM_STATE_LIFECYCLE, 'state_lifecycle'),
            (SYSTEM_ACCESS_ENVIRONMENT, 'access_env'),
        ]

        vyper_prompts = solidity_prompts  # Same generic patterns apply

        all_vulns: List[Vulnerability] = []
        total_in = total_out = 0

        # =============================================
        # PHASE 1: BROAD SWEEP WITH COT
        # =============================================
        total_tasks = sum(
            len(rust_prompts) if detect_language(f) == 'rust' else len(solidity_prompts)
            for f in files_to_analyze
        )
        console.print(f"\n[cyan]Phase 1: Broad Sweep ({len(files_to_analyze)} files, {total_tasks} tasks)[/cyan]")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {}
            for file_path in files_to_analyze:
                rel_path = str(file_path.relative_to(source_dir))
                related = related_map.get(file_path, "")
                language = detect_language(file_path)

                if language == 'rust':
                    prompts = rust_prompts
                elif language == 'vyper':
                    prompts = vyper_prompts
                else:
                    prompts = solidity_prompts

                for sys_prompt, prompt_name in prompts:
                    future = executor.submit(
                        self.analyze_file_with_prompt,
                        source_dir, rel_path, related,
                        analysis_model, sys_prompt, prompt_name
                    )
                    futures[future] = (rel_path, prompt_name)

            start_time = time.time()
            timeout_minutes = 16
            try:
                for future in as_completed(futures, timeout=timeout_minutes * 60):
                    try:
                        vulns, inp, out = future.result(timeout=4 * 60)
                        total_in += inp
                        total_out += out
                        all_vulns.extend(vulns)
                    except Exception as e:
                        rel, name = futures[future]
                        console.print(f"[red]Task failed ({rel}/{name}): {e}[/red]")

                    if time.time() - start_time > timeout_minutes * 60:
                        console.print(f"[yellow]Timeout reached ({timeout_minutes} min)[/yellow]")
                        for f in futures:
                            f.cancel()
                        break
            except TimeoutError:
                console.print(f"[yellow]Timeout reached ({timeout_minutes} min)[/yellow]")
                for f in futures:
                    f.cancel()

        console.print(f"[cyan]Phase 1 found {len(all_vulns)} raw findings[/cyan]")

        # =============================================
        # DEDUPLICATION
        # =============================================
        deduped = deduplicate_findings(all_vulns)
        console.print(f"[dim]After dedup: {len(deduped)} unique findings[/dim]")

        # =============================================
        # PHASE 2: VERIFICATION
        # =============================================
        verified = self.verify_findings(source_dir, deduped, file_contents, verify_model)
        console.print(f"[cyan]After verification: {len(verified)} findings[/cyan]")

        # =============================================
        # QUALITY GATE: specificity scoring + sort
        # =============================================
        scored = []
        for v in verified:
            content = file_contents.get(v.file, "")
            spec_score = compute_specificity_score(v, content)
            scored.append((spec_score, v))

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        scored.sort(key=lambda x: (-x[0], severity_order.get(x[1].severity.value, 4), -x[1].confidence))

        # Cap at 80 findings max
        final_vulns = [v for _, v in scored[:80]]

        console.print(f"\n[green]Final: {len(final_vulns)} findings[/green]")

        result = AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=len(files_to_analyze),
            files_skipped=len(files) - len(files_to_analyze),
            total_vulnerabilities=len(final_vulns),
            vulnerabilities=final_vulns,
            token_usage={
                'input_tokens': total_in,
                'output_tokens': total_out,
                'total_tokens': total_in + total_out
            }
        )

        self.print_summary(result)
        return result

    def print_summary(self, result: AnalysisResult):
        console.print(f"\n[bold]Summary for {result.project}:[/bold]")
        console.print(f"  Files analyzed: {result.files_analyzed}")
        console.print(f"  Files skipped: {result.files_skipped}")
        console.print(f"  Total vulnerabilities: {result.total_vulnerabilities}")
        console.print(f"  Tokens: {result.token_usage['total_tokens']:,}")

        if result.vulnerabilities:
            severity_counts: Dict[str, int] = {}
            for v in result.vulnerabilities:
                severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
            console.print("  By severity:")
            for sev in ['critical', 'high', 'medium', 'low']:
                if sev in severity_counts:
                    console.print(f"    {sev.capitalize()}: {severity_counts[sev]}")

    def save_result(self, result: AnalysisResult, output_file: str = "agent_report.json"):
        result_dict = result.model_dump()
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2)
        console.print(f"\n[green]Results saved to: {output_file}[/green]")
        return output_file


# =============================================================================
# MAIN ENTRYPOINT
# =============================================================================

def agent_main(project_dir: str = None, inference_api: str = None):
    config = {
        'model': "Qwen/Qwen3-Next-80B-A3B-Instruct",
        'analysis_model': "Qwen/Qwen3-Next-80B-A3B-Instruct",
        'verify_model': "Qwen/Qwen3-Next-80B-A3B-Instruct",
    }

    if not project_dir:
        project_dir = "/app/project_code"

    console.print(Panel.fit(
        "[bold cyan]CJO AGENT — Improved[/bold cyan]\n"
        f"[dim]Model: {config['model']}[/dim]\n"
        "[dim]5 generic prompts | CoT | Verification | Dedup | FP filter[/dim]",
        border_style="cyan"
    ))

    try:
        start = time.time()
        runner = ImprovedRunner(config, inference_api)

        source_dir = Path(project_dir) if project_dir else None
        if not source_dir or not source_dir.exists() or not source_dir.is_dir():
            console.print(f"[red]Error: Invalid source directory: {project_dir}[/red]")
            sys.exit(1)

        result = runner.analyze_project(
            source_dir=source_dir,
            project_name=project_dir,
        )

        output_file = runner.save_result(result)

        elapsed = time.time() - start
        console.print("\n" + ("=" * 60))
        console.print(Panel.fit(
            f"[bold green]ANALYSIS COMPLETE[/bold green]\n\n"
            f"Project: {result.project}\n"
            f"Files analyzed: {result.files_analyzed}\n"
            f"Total vulnerabilities: {result.total_vulnerabilities}\n"
            f"Time: {elapsed:.1f}s\n"
            f"Results saved to: {output_file}",
            border_style="green"
        ))

        return result.model_dump(mode="json")

    except ValueError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    import sys
    from pathlib import Path
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from scripts.projects import fetch_projects
    from validator.manager import SandboxManager

    SandboxManager(is_local=True)
    time.sleep(10)  # wait for proxy to start
    fetch_projects()
    inference_api = 'http://localhost:8087'
    report = agent_main('projects/ttt', inference_api=inference_api)

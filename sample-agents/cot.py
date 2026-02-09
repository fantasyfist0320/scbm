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
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel

console = Console()

# =============================================================================
# PHASE 0: DESIGN INFERENCE + COT (prepended to every user message)
# =============================================================================

PHASE_0_PREAMBLE = """
============================================================
STEP 1 — UNDERSTAND THE DESIGN (do this FIRST)
============================================================

Before looking for bugs, reason about the protocol's design:

1. What assets/values are managed? How does value enter and exit?
2. What are the trust boundaries (users, admins, keepers, anyone)?
3. What are the accounting invariants (what must always balance)?
4. Are resources created at predictable identifiers (CREATE, clones, factory pairs)?
5. What external dependencies exist?

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

Using your understanding from Steps 1-2, find bugs matching the system prompt patterns.

============================================================
OUTPUT FORMAT
============================================================

First write your ANALYSIS NOTES — trace value flows, call chains, state transitions,
and access control observations. Think step by step. This is your scratchpad.

Then output your findings as JSON:
{{"vulnerabilities": [...]}}
"""

# =============================================================================
# BROAD PROMPT 1: VALUE FLOW & SETTLEMENT
# Merges: VALUE_ACCOUNTING + USER_PROTECTIONS + PRECISION
# =============================================================================

SYSTEM_VALUE_FLOW = """
You are an expert smart contract security auditor focused on VALUE FLOW correctness.

============================================================
A. SETTLEMENT & REFUND SAFETY
============================================================

For EACH function that takes value then returns/refunds:
1. What is the REQUESTED amount (parameter) vs ACTUAL amount taken?
2. Is refund computed from REQUESTED or ACTUAL?
3. CRITICAL BUG: Refund exceeds what was debited
   - take(actual_amount) then refund(requested - actual) = free money
   - This happens when two fixes are applied: changed debit to use actual
     AND added refund of difference — both together = double benefit

For Rust/Stylus specifically:
- erc20::take(from, amount_in) takes the actual amount
- erc20::transfer_to_sender(original - amount_in) refunds the difference
- BUG if original was never taken — refund is pure protocol loss
- Watch for checked_sub(), saturating_sub() masking errors

============================================================
B. RETURN VALUE UNIT CONFUSION
============================================================

Trace return values through call chains:
- Does _deploy() return ASSETS deposited or SHARES received?
- Does _undeploy() return ASSETS withdrawn or SHARES burned?
- Does the caller treat the return as the right unit?
- ERC4626: vault.deposit(assets) returns SHARES, not assets

============================================================
C. MISSING SLIPPAGE/DEADLINE PROTECTION
============================================================

For value-changing operations (swaps, liquidity, withdrawals):
- Are minAmountOut / amount0Min / amount1Min enforced?
- Can transactions be held and executed at a stale price?

============================================================
D. PRECISION & ROUNDING
============================================================

1. Index/balance desync: division rounds to 0, index unchanged, but
   lastBalance always updates — rewards permanently lost
2. Release rate recalculation: after partial claim or transfer, is
   remaining entitlement recalculated from original total? (BUG)

IMPORTANT: Only report SPECIFIC bugs with EXACT functions and EXACT mismatch.

{format_instructions}
"""

# =============================================================================
# BROAD PROMPT 2: STATE & LIFECYCLE
# Merges: STATE_CONSISTENCY + OPERATION_REVERSAL + CONTROL_FLOW
# =============================================================================

SYSTEM_STATE_LIFECYCLE = """
You are an expert smart contract security auditor focused on STATE CORRECTNESS.

============================================================
A. STATE UPDATE OMISSIONS (CRITICAL)
============================================================

For EVERY state-modifying function, ask:
"What OTHER state variables SHOULD be updated but AREN'T?"

Method:
1. Find FORWARD operation (deposit, stake, deploy, queue)
2. List ALL state it modifies
3. Find REVERSE operation (withdraw, unstake, undeploy, cancel)
4. Verify EACH state variable is properly updated in the reverse
5. BUG if reverse forgets any variable

Key example: deploy() sets _deployedAmount, undeploy() forgets to decrement.
Result: harvest() sees wrong _deployedAmount, profit miscalculated, fees lost.

============================================================
B. RECEIVE/FALLBACK AUTO-EXECUTION TRAPS (CRITICAL)
============================================================

1. Find receive() or fallback() — does it auto-execute logic (stake, deposit)?
2. Trace ALL paths where native tokens are sent TO this contract:
   - Withdrawals, refunds, bridge returns, validator rewards
3. BUG: Withdrawal sends ETH → receive() auto-stakes it → withdrawal fails
4. Check: Should certain senders bypass receive() logic?

============================================================
C. PAIRED OPERATION ASYMMETRY
============================================================

For each operation pair (request/cancel, deposit/withdraw, stake/unstake):
- Build STATE CHANGE TABLE for both directions
- If forward modifies [A, B, C] but reverse only modifies [B, C],
  then A is NEVER RESTORED = BUG

============================================================
D. TEMPORAL ORDERING / STALE RATE ATTACKS
============================================================

For queued operations (queue → wait → confirm):
1. What value is locked at queue time vs recalculated at confirm time?
2. Can slashing/rewards/fee changes occur between queue and confirm?
3. BUG: User queues at old rate, adverse event occurs, confirms at stale rate

============================================================
E. CONTROL FLOW
============================================================

1. Mutually exclusive branches: Can both conditions be true? If yes,
   second branch silently skipped via else-if
2. Wrong flag/direction: bitmask assumes fixed token ordering but actual
   ordering depends on address sort
3. Entitlement on transfer: is progress correctly scoped per position?

IMPORTANT: Only report with EXACT state variables and EXACT functions.

{format_instructions}
"""

# =============================================================================
# BROAD PROMPT 3: ACCESS & ENVIRONMENT
# Merges: GENERAL + ADVERSARIAL_CONTROL + EXECUTION_ENV
# =============================================================================

SYSTEM_ACCESS_ENVIRONMENT = """
You are an expert smart contract security auditor focused on ACCESS CONTROL
and EXECUTION ENVIRONMENT safety.

============================================================
A. ACCESS CONTROL GAPS (CRITICAL — check EVERY external/public function)
============================================================

For EACH external/public function that modifies state:
1. Is it restricted (onlyOwner, onlyRole, onlyKeeper, auth)?
2. If NOT restricted — should it be? What's the impact if anyone calls it?
3. CRITICAL: Functions that update accounting (harvest, rebalance, sync)
   without access control let attackers front-run fee collection
4. Functions that take a 'from' parameter for transferFrom — is
   msg.sender == from enforced? If not, anyone can drain approvals

============================================================
B. GAS GRIEFING VIA 63/64 RULE
============================================================

Pattern:
1. Function consumes irreversible state BEFORE external call
2. External call via call/delegatecall/send
3. Non-reverting path when call fails
4. Attacker supplies just enough gas — state consumed, subcall fails

============================================================
C. PREDICTABLE IDENTIFIER FRONT-RUNNING (CRITICAL)
============================================================

1. Does the contract create resources via CREATE, CREATE2, Clones.clone()?
2. Can an external party predict the address before creation?
   - clone() uses CREATE — next nonce is public
   - Factory patterns: createPair address is deterministic
3. Does creation REVERT if resource already exists?
4. BUG: Attacker pre-creates at predicted address → protocol permanently DoS'd
5. Check: existence check before creation? Try/catch? Random salt?

============================================================
D. SIGNATURE GRIEFING
============================================================

- Can attacker submit valid signature with different msg.value?
- Can attacker front-run and consume signature before intended use?
- Permit frontrunning: attacker extracts permit from mempool

============================================================
E. DELEGATION & STAKING
============================================================

- Are reward claims routed to correct recipient (delegator vs validator)?
- Can intermediary claim rewards belonging to end user?

IMPORTANT: Only report SPECIFIC bugs with CONCRETE exploit paths.

{format_instructions}
"""

# =============================================================================
# RUST-SPECIFIC BROAD PROMPT (replaces 4 separate Rust prompts)
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
4. CRITICAL: take(amount_in) then transfer(original - amount_in) = BUG
   if original was never taken. The refund is free money.
5. Redundant fix pattern: code changed to take(actual) AND added
   refund(requested - actual) — both fixes together = double benefit

============================================================
B. STATE CORRECTNESS (RUST)
============================================================

1. Are storage writes via self.field.set() properly ordered?
2. Error paths: does ? operator return before cleanup?
3. For each operation pair — verify all state is reversed on cancel
4. Does receive handler auto-execute logic on incoming transfers?

============================================================
C. ACCESS & ENVIRONMENT (RUST)
============================================================

1. Are pub fn functions properly restricted?
2. #[payable] — what happens with msg_value = 0?
3. Cross-contract calls: RawCall, return value handling
4. Reentrancy through callbacks?

============================================================
D. RUST-SPECIFIC PATTERNS
============================================================

- checked_sub(), saturating_sub() masking calculation errors
- as casts that truncate (u128 as u64)
- Clone() creating divergent state copies
- sol_storage! macro initialization
- Multiple return paths with different state

IMPORTANT: Only report SPECIFIC bugs with EXACT Rust functions and state fields.

{format_instructions}
"""

# =============================================================================
# DEEP-DIVE PROMPT (for focused function-level analysis in Phase 2)
# =============================================================================

SYSTEM_DEEP_DIVE = """
You are performing a FOCUSED LINE-BY-LINE security analysis of a specific function.

For this function, you MUST:

1. TRACE every variable: where does each value come from? What does it represent?
2. TRACE every token movement: what amount is taken? what amount is sent? Do they balance?
3. CHECK every state update: which variables change? Are any missing?
4. CHECK return values: what unit is returned? How does the caller use it?
5. CHECK access: who can call this? Should it be restricted?

Think step by step. Write your full reasoning before any conclusions.

Then report issues as JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# ACCESS CONTROL PRE-SCAN PROMPT (for regex-detected suspects)
# =============================================================================

SYSTEM_ACCESS_SCAN = """
You are checking whether specific public functions should have access restrictions.

For each function listed:
1. What state does it modify?
2. What is the IMPACT if anyone can call it at any time?
3. Can a user/attacker exploit the timing of this call?
   - Front-run fee collection by calling harvest() first?
   - Reset accounting to avoid paying fees?
   - Manipulate exchange rates?

Only report if unrestricted access causes concrete harm (fund loss, fee avoidance,
broken accounting). Do NOT report if the function is legitimately permissionless.

Think step by step. Then report as JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# VERIFICATION PROMPT
# =============================================================================

SYSTEM_VERIFY = """
You are verifying potential vulnerabilities in smart contracts.

For each finding, verify:

1. CODE GROUNDING: Does the described function/pattern exist in the code?
2. MECHANISM: Trace the described attack through actual code — does it work?
3. IMPACT: Would exploitation cause real harm (fund loss, DoS, broken invariants)?

CONFIRMED: Bug mechanism checks out, functions exist, impact is real.
UNCERTAIN: Function exists, mechanism plausible but hard to fully trace.
REJECTED: Function doesn't exist, mechanism contradicts code, purely informational,
          Solidity 0.8+ overflow without unchecked, test/mock only, requires malicious admin.

When in doubt between UNCERTAIN and REJECTED, prefer UNCERTAIN.

Return JSON:
{{
    "verifications": [
        {{
            "index": 0,
            "verdict": "CONFIRMED" or "UNCERTAIN" or "REJECTED",
            "reasoning": "Brief explanation",
            "adjusted_severity": "critical/high/medium/low",
            "adjusted_confidence": 0.0-1.0
        }}
    ]
}}
"""

# =============================================================================
# PRE-FILTER PATTERNS
# =============================================================================

KNOWN_FALSE_POSITIVE_PATTERNS = [
    r'missing\s+events?\s+emission',
    r'floating\s+pragma',
    r'missing\s+natspec',
    r'code\s+style',
    r'gas\s+optimization',
    r'lack\s+of\s+documentation',
    r'missing\s+zero\s+address\s+check',
    r'^centralization\s+risk$',
    r'single\s+point\s+of\s+failure',
]

SOLIDITY_08_FALSE_POSITIVES = [
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
# UTILITIES
# =============================================================================

def is_test_or_mock_file(file_path: Path) -> bool:
    name_lower = file_path.name.lower()
    path_lower = str(file_path).lower()
    test_indicators = ['test', 'mock', 'fake', 'stub', 'fixture']
    for indicator in test_indicators:
        if indicator in name_lower or f'/{indicator}/' in path_lower:
            return True
    return False


def is_interface_file(file_path: Path, content: str = "") -> bool:
    """Detect interface-only files that shouldn't be audited."""
    name = file_path.name
    # Common naming: IERC20.sol, IVault.sol
    if name.startswith('I') and len(name) > 1 and name[1].isupper() and file_path.suffix == '.sol':
        return True
    # Check content: if it's only an interface definition
    if content and 'interface ' in content and 'function ' in content:
        # If there are no function bodies (no { after function sig before ;)
        func_bodies = re.findall(r'function\s+\w+[^;]*\{', content)
        if not func_bodies:
            return True
    return False


def detect_language(file_path: Path) -> str:
    suffix = file_path.suffix.lower()
    if suffix == '.sol':
        return 'solidity'
    elif suffix == '.vy':
        return 'vyper'
    elif suffix == '.rs':
        return 'rust'
    else:
        return 'solidity'


def get_code_block_lang(language: str) -> str:
    return {'solidity': 'solidity', 'vyper': 'python', 'rust': 'rust'}.get(language, 'solidity')


def extract_solidity_version(content: str) -> str:
    match = re.search(r'pragma\s+solidity\s*[\^~>=<]*\s*(\d+\.\d+)', content)
    return match.group(1) if match else "0.8"


def is_solidity_08_plus(content: str) -> bool:
    version = extract_solidity_version(content)
    try:
        major, minor = map(int, version.split('.')[:2])
        return major > 0 or minor >= 8
    except:
        return True


def pre_filter_finding(vuln: Vulnerability, content: str) -> tuple[bool, str]:
    title_lower = vuln.title.lower()
    desc_lower = vuln.description.lower()
    combined = f"{title_lower} {desc_lower}"

    for pattern in KNOWN_FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, combined):
            return True, f"Matches FP pattern: {pattern[:30]}"

    if is_solidity_08_plus(content):
        for pattern in SOLIDITY_08_FALSE_POSITIVES:
            if re.search(pattern, combined):
                if 'unchecked' not in combined:
                    return True, "Solidity 0.8+ overflow protection"

    return False, ""


# =============================================================================
# STATIC ANALYSIS: ACCESS CONTROL PRE-SCAN
# =============================================================================

def scan_unprotected_functions(content: str, language: str) -> List[dict]:
    """Find external/public functions that modify state without access control."""
    suspects = []

    if language == 'solidity':
        # Match function signatures with visibility
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s+((?:(?:external|public|internal|private|view|pure|payable|virtual|override|nonReentrant|onlyOwner|onlyRole\([^)]*\)|onlyAdmin|onlyOperator|onlyKeeper|onlyVault|onlyStrategy|auth|restricted|returns\s*\([^)]*\))\s*)*)\{'
        for name, params, modifiers in re.findall(func_pattern, content):
            # Must be external or public
            if 'external' not in modifiers and 'public' not in modifiers:
                continue
            # Skip views
            if 'view' in modifiers or 'pure' in modifiers:
                continue
            # Check for access control
            access_keywords = ['onlyOwner', 'onlyRole', 'onlyAdmin', 'onlyOperator',
                             'onlyKeeper', 'onlyVault', 'onlyStrategy', 'auth', 'restricted']
            has_access = any(kw in modifiers for kw in access_keywords)
            if not has_access:
                suspects.append({
                    'name': name,
                    'visibility': 'external' if 'external' in modifiers else 'public',
                    'params': params.strip()[:80],
                })

    elif language == 'rust':
        # Look for pub fn without access checks
        func_pattern = r'pub\s+fn\s+(\w+)\s*\(([^)]*)\)'
        for name, params in re.findall(func_pattern, content):
            # Check if function body has msg_sender checks
            func_body_match = re.search(rf'pub\s+fn\s+{name}\s*\([^)]*\)[^{{]*\{{((?:[^{{}}]|\{{(?:[^{{}}]|\{{[^{{}}]*\}})*\}})*)\}}', content, re.DOTALL)
            if func_body_match:
                body = func_body_match.group(1)
                has_access = any(kw in body for kw in ['msg_sender', 'only_owner', 'require_auth', 'assert_eq!(caller'])
                if not has_access and any(kw in body for kw in ['.set(', '.insert(', '+= ', '-= ', '= ']):
                    suspects.append({
                        'name': name,
                        'visibility': 'pub',
                        'params': params.strip()[:80],
                    })

    return suspects


def extract_state_mapping(content: str, language: str) -> str:
    """Extract state variables and which functions modify them."""
    if language == 'rust':
        return _extract_rust_state_mapping(content)

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


def _extract_rust_state_mapping(content: str) -> str:
    field_vars = set(re.findall(r'self\.(\w+)\s*(?:\.|\.get|\.set|\.insert|\.remove|\+=|-=|=)', content))
    if not field_vars:
        return ""

    func_pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
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

    if language == 'solidity':
        all_func_names = {m[0] for m in functions}
    else:
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
            if 'onlyOwner' in modifiers:
                access = " [onlyOwner]"
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


def extract_function_code(content: str, func_name: str, language: str, context_lines: int = 5) -> str:
    """Extract a specific function's code with surrounding context."""
    lines = content.split('\n')

    if language == 'solidity':
        pattern = f'function {func_name}'
    elif language == 'rust':
        pattern = f'fn {func_name}'
    else:
        pattern = f'def {func_name}'

    for i, line in enumerate(lines):
        if pattern in line:
            # Find function end by brace matching
            start = max(0, i - context_lines)
            depth = 0
            end = i
            for j in range(i, len(lines)):
                depth += lines[j].count('{') - lines[j].count('}')
                if language == 'vyper':
                    # Vyper uses indentation
                    if j > i and lines[j].strip() and not lines[j].startswith(' ') and not lines[j].startswith('\t'):
                        end = j
                        break
                elif depth <= 0 and j > i:
                    end = j + 1
                    break
            end = min(end + context_lines, len(lines))
            return '\n'.join(f"{n+1:4d}: {l}" for n, l in enumerate(lines[start:end], start))

    return ""


def deduplicate_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Deduplicate by semantic root cause."""
    if not vulnerabilities:
        return []

    sorted_vulns = sorted(vulnerabilities, key=lambda x: -x.confidence)

    # Lexical dedup
    deduped = []
    for vuln in sorted_vulns:
        is_dup = False
        vuln_words = set(re.findall(r'\w{4,}', vuln.title.lower()))

        for existing in deduped:
            if vuln.file != existing.file:
                continue
            if vuln.vulnerability_type == existing.vulnerability_type and vuln.location[:30] == existing.location[:30]:
                is_dup = True; break
            if vuln.title.lower()[:40] == existing.title.lower()[:40]:
                is_dup = True; break
            existing_words = set(re.findall(r'\w{4,}', existing.title.lower()))
            if vuln_words and existing_words:
                overlap = len(vuln_words & existing_words) / max(len(vuln_words | existing_words), 1)
                if overlap > 0.6:
                    is_dup = True; break
            vuln_funcs = set(re.findall(r'(\w+)\s*\(', vuln.description[:200]))
            existing_funcs = set(re.findall(r'(\w+)\s*\(', existing.description[:200]))
            common = vuln_funcs & existing_funcs - {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return'}
            if len(common) >= 2 and vuln.vulnerability_type == existing.vulnerability_type:
                is_dup = True; break

        if not is_dup:
            deduped.append(vuln)

    # Cluster by root cause, keep max 2
    stopwords = {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return', 'memory', 'storage'}
    clusters: dict[tuple, List[Vulnerability]] = {}
    for v in deduped:
        funcs = re.findall(r'(\w+)\s*\(', f"{v.title} {v.description[:300]}")
        funcs = [f for f in funcs if f.lower() not in stopwords and len(f) > 2]
        primary = funcs[0] if funcs else "unknown"

        desc = v.description.lower()
        if any(x in desc for x in ['refund', 'value mismatch', 'amount taken']):
            cat = 'value'
        elif any(x in desc for x in ['cancel', 'not reversed', 'not restored']):
            cat = 'reversal'
        elif any(x in desc for x in ['gas', '63/64', 'griefing']):
            cat = 'gas'
        elif any(x in desc for x in ['access', 'anyone', 'permissionless', 'no.*modifier']):
            cat = 'access'
        elif any(x in desc for x in ['front-run', 'predictable', 'create.*pair']):
            cat = 'frontrun'
        elif any(x in desc for x in ['receive', 'fallback', 'auto-stak']):
            cat = 'receive'
        else:
            cat = 'other'

        key = (v.file, primary, cat)
        clusters.setdefault(key, []).append(v)

    result = []
    for group in clusters.values():
        group.sort(key=lambda x: -x.confidence)
        result.extend(group[:2])
    return result


def compute_specificity_score(finding: Vulnerability, file_content: str = "") -> float:
    score = 0.0
    desc = finding.description

    if file_content:
        quotes = re.findall(r'`([^`]+)`', desc)
        for q in quotes:
            if len(q) > 5 and q in file_content:
                score += 0.15; break

    score += min(len(re.findall(r'\b[a-zA-Z_]\w+\s*\(\)', desc)) * 0.08, 0.24)
    score += min(len(re.findall(r'\b\w+(?:Amount|Balance|Counter|Index|Rate|Buffer|Total|Supply|Nonce)\b', desc, re.I)) * 0.1, 0.2)
    if re.search(r'\d+\s*(?:wei|ether|gwei|gas|%|x\b)', desc, re.I):
        score += 0.1
    if re.search(r'(?:step\s*\d|1\.\s*\w|first.*then)', desc, re.I):
        score += 0.1

    return min(score * finding.confidence, 1.0)


def apply_quality_gate(findings: List[Vulnerability], file_contents: Dict[str, str], max_findings: int = 80) -> List[Vulnerability]:
    if len(findings) <= max_findings:
        return findings

    scored = []
    for f in findings:
        content = file_contents.get(f.file, "")
        scored.append((compute_specificity_score(f, content), f))

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    scored.sort(key=lambda x: (-x[0], severity_order.get(x[1].severity.value, 4)))
    return [f for _, f in scored[:max_findings]]


# =============================================================================
# RUNNER
# =============================================================================

class EnhancedRunner:
    def __init__(self, config: dict | None = None, inference_api: str = None):
        self.config = config or {}
        self.model = self.config.get('model', 'Qwen/Qwen3-Next-80B-A3B-Instruct')
        self.inference_api = inference_api or os.getenv('INFERENCE_API', "http://bitsec_proxy:8000")
        self.project_id = os.getenv('PROJECT_ID', "local")
        self.job_id = os.getenv('JOB_ID', "local")

        console.print(f"[cyan]Model: {self.model}[/cyan]")
        console.print(f"[cyan]API: {self.inference_api}[/cyan]")

    def inference(self, messages: list, model: str | None = None, timeout: int = 180, temperature: float = 0.1) -> dict:
        payload = {
            "model": model or self.model,
            "messages": messages,
            "temperature": temperature,
        }
        headers = {
            "x_project_id": self.project_id,
            "x_job_id": self.job_id,
        }

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
            except Exception as e:
                if attempt < 2:
                    console.print(f"[yellow]Retry {attempt+1}/3: {e}[/yellow]")
                    time.sleep(30 + attempt * 15)
                else:
                    raise
        return {}

    def clean_json(self, response: str) -> dict:
        """Extract JSON from response that may contain CoT reasoning before the JSON."""
        response = response.strip()
        if "```" in response:
            lines = response.split('\n')
            lines = [l for l in lines if not l.strip().startswith("```")]
            response = '\n'.join(lines)

        # Strategy: find ALL valid top-level JSON objects, prefer one with "vulnerabilities"
        candidates = []
        i = 0
        while i < len(response):
            if response[i] == '{':
                depth = 0
                for j in range(i, len(response)):
                    if response[j] == '{': depth += 1
                    elif response[j] == '}': depth -= 1
                    if depth == 0:
                        try:
                            parsed = json.loads(response[i:j+1])
                            if isinstance(parsed, dict):
                                candidates.append(parsed)
                        except:
                            pass
                        i = j + 1
                        break
                else:
                    i += 1
            else:
                i += 1

        # Prefer candidate with "vulnerabilities" key
        for c in candidates:
            if "vulnerabilities" in c:
                return c

        # Fallback: check for alternate keys like "findings"
        for c in candidates:
            if "findings" in c:
                return {"vulnerabilities": c["findings"]}

        # Last resort: return the largest candidate or empty
        if candidates:
            largest = max(candidates, key=lambda x: len(str(x)))
            if "vulnerabilities" not in largest:
                largest["vulnerabilities"] = []
            return largest

        return {"vulnerabilities": []}

    def _safe_parse_vulns(self, result: dict) -> List[Vulnerability]:
        """Safely parse vulnerabilities from JSON, handling missing/malformed data."""
        try:
            # Ensure vulnerabilities key exists and is a list
            raw_vulns = result.get('vulnerabilities', [])
            if not isinstance(raw_vulns, list):
                return []
            vulns = Vulnerabilities(vulnerabilities=raw_vulns)
            return list(vulns.vulnerabilities)
        except Exception as e:
            console.print(f"[dim]    Parse warning: {e}[/dim]")
            return []

    # -----------------------------------------------------------------
    # PHASE 1: BROAD SWEEP WITH COT
    # -----------------------------------------------------------------

    def analyze_file_with_prompt(
        self, source_dir: Path, relative_path: str, related_content: str,
        model: str, system_prompt: str, prompt_name: str,
    ) -> Tuple[List[Vulnerability], int, int]:
        file_path = Path(relative_path)

        with open(source_dir / file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        language = detect_language(file_path)
        code_lang = get_code_block_lang(language)

        # Skip interface files
        if is_interface_file(file_path, content):
            console.print(f"[dim]  -> {file_path.name} (skipped: interface)[/dim]")
            return [], 0, 0

        console.print(f"[dim]  -> {file_path.name} ({prompt_name}) [{language}][/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        system = system_prompt.format(format_instructions=parser.get_format_instructions())

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
- Give CONCRETE exploit steps with specific values
"""

        try:
            response = self.inference(
                [{"role": "system", "content": system}, {"role": "user", "content": user_msg}],
                model=model,
                timeout=240,  # More time for CoT reasoning
            )

            result = self.clean_json(response.get('content', '{}'))
            vuln_list = self._safe_parse_vulns(result)

            validated = []
            for v in vuln_list:
                v.file = str(file_path)
                v.reported_by_model = f"{model}_{prompt_name}"

                should_filter, reason = pre_filter_finding(v, content)
                if should_filter:
                    continue

                if v.confidence >= 0.6:  # Slightly lower threshold — CoT findings are higher quality
                    validated.append(v)

            if validated:
                console.print(f"[green]    Found {len(validated)} potential issues[/green]")

            return validated, response.get('input_tokens', 0), response.get('output_tokens', 0)

        except Exception as e:
            console.print(f"[red]    Error: {e}[/red]")
            return [], 0, 0

    # -----------------------------------------------------------------
    # PHASE 1B: ACCESS CONTROL PRE-SCAN (regex + focused LLM)
    # -----------------------------------------------------------------

    def scan_access_control(
        self, source_dir: Path, files_to_analyze: List[Path],
        file_contents: Dict[str, str], model: str
    ) -> List[Vulnerability]:
        """Regex scan for unprotected functions, then ask LLM about impact."""
        all_suspects = []

        for file_path in files_to_analyze:
            rel_path = str(file_path.relative_to(source_dir))
            content = file_contents.get(rel_path, "")
            if not content:
                continue
            language = detect_language(file_path)
            suspects = scan_unprotected_functions(content, language)
            if suspects:
                for s in suspects:
                    s['file'] = rel_path
                    s['language'] = language
                all_suspects.extend(suspects)

        if not all_suspects:
            return []

        console.print(f"[cyan]  Access scan: {len(all_suspects)} unprotected state-modifying functions[/cyan]")

        # Group by file and ask LLM about impact
        by_file: Dict[str, list] = {}
        for s in all_suspects:
            by_file.setdefault(s['file'], []).append(s)

        findings = []
        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)

        for file_path, suspects in by_file.items():
            content = file_contents.get(file_path, "")
            language = suspects[0]['language']
            code_lang = get_code_block_lang(language)

            suspect_list = '\n'.join(
                f"- {s['name']}() is {s['visibility']} — no access control modifier"
                for s in suspects
            )

            # Extract just the suspect functions' code for focused context
            func_codes = []
            for s in suspects:
                code = extract_function_code(content, s['name'], language)
                if code:
                    func_codes.append(f"// {s['name']}()\n{code}")

            func_context = '\n\n'.join(func_codes) if func_codes else content[:8000]

            prompt = f"""These functions in {file_path} are external/public with NO access control:

{suspect_list}

FUNCTION CODE:
```{code_lang}
{func_context}
```

For each function:
1. What state does it modify?
2. What happens if ANYONE can call it at any time?
3. Can an attacker exploit timing (front-run fee collection, reset accounting)?

Think step by step. Only report if unrestricted access causes concrete harm.

{parser.get_format_instructions()}
"""

            try:
                system = SYSTEM_ACCESS_SCAN.format(format_instructions=parser.get_format_instructions())
                response = self.inference(
                    [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                    model=model, timeout=120,
                )
                result = self.clean_json(response.get('content', '{}'))
                vuln_list = self._safe_parse_vulns(result)
                for v in vuln_list:
                    v.file = file_path
                    v.reported_by_model = f"{model}_access_scan"
                    if v.confidence >= 0.6:
                        findings.append(v)
                        console.print(f"[green]    Access issue: {v.title[:60]}[/green]")
            except Exception as e:
                console.print(f"[yellow]    Access scan error ({file_path}): {e}[/yellow]")

        return findings

    # -----------------------------------------------------------------
    # PHASE 2: DEEP-DIVE ON VALUE-HANDLING FUNCTIONS
    # -----------------------------------------------------------------

    def deep_dive_value_functions(
        self, source_dir: Path, files_to_analyze: List[Path],
        file_contents: Dict[str, str], existing_findings: List[Vulnerability],
        model: str
    ) -> List[Vulnerability]:
        """Focused line-by-line analysis of functions that handle value transfers."""
        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        findings = []

        # Identify value-handling functions across all files
        targets = []
        for file_path in files_to_analyze:
            rel_path = str(file_path.relative_to(source_dir))
            content = file_contents.get(rel_path, "")
            if not content:
                continue
            language = detect_language(file_path)

            # Find functions that move value
            if language == 'rust':
                value_patterns = [r'erc20::take', r'erc20::transfer', r'transfer_to_sender',
                                r'msg_value', r'raw_call.*value']
            else:
                value_patterns = [r'\.transfer\(', r'\.call\{value', r'transferFrom\(',
                                r'\.safeTransfer\(', r'\.safeTransferFrom\(', r'mint\(',
                                r'\.deposit\(', r'\.withdraw\(']

            # Find function names that contain value operations
            if language == 'solidity':
                func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
            elif language == 'rust':
                func_pattern = r'(?:pub\s+)?fn\s+(\w+)\s*\([^)]*\)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
            else:
                continue

            for fname, fbody in re.findall(func_pattern, content, re.DOTALL):
                if any(re.search(p, fbody) for p in value_patterns):
                    # Check if this function was already found by Phase 1
                    already_found = any(
                        fname.lower() in f.description.lower()[:300] or fname.lower() in f.title.lower()
                        for f in existing_findings if f.file == rel_path
                    )
                    if not already_found:
                        targets.append((rel_path, fname, language))

        if not targets:
            console.print("[dim]  No additional value-handling functions to deep-dive[/dim]")
            return []

        # Cap at 15 most important functions to stay within time budget
        targets = targets[:15]
        console.print(f"[cyan]  Deep-diving {len(targets)} value-handling functions[/cyan]")

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {}
            for rel_path, func_name, language in targets:
                content = file_contents.get(rel_path, "")
                code_lang = get_code_block_lang(language)
                func_code = extract_function_code(content, func_name, language)

                if not func_code or len(func_code) < 20:
                    continue

                prompt = f"""Analyze this function LINE BY LINE for value flow correctness:

FILE: {rel_path}
FUNCTION: {func_name}

```{code_lang}
{func_code}
```

For each token transfer in this function:
1. What EXACT amount is moved? Where did that variable come from?
2. Was that amount previously debited from the user?
3. If this is a refund: was the base amount actually taken first?
4. Are any state variables that should be updated NOT updated?

Think step by step. Write your full trace before conclusions.

{parser.get_format_instructions()}
"""
                system = SYSTEM_DEEP_DIVE.format(format_instructions=parser.get_format_instructions())
                future = executor.submit(
                    self.inference,
                    [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                    model, 120, 0.2
                )
                futures[future] = (rel_path, func_name)

            for future in as_completed(futures, timeout=10*60):
                rel_path, func_name = futures[future]
                try:
                    response = future.result(timeout=120)
                    result = self.clean_json(response.get('content', '{}'))
                    vuln_list = self._safe_parse_vulns(result)
                    for v in vuln_list:
                        v.file = rel_path
                        v.reported_by_model = f"{model}_deep_dive"
                        if v.confidence >= 0.6:
                            findings.append(v)
                            console.print(f"[green]    Deep-dive found: {v.title[:60]}[/green]")
                except Exception as e:
                    console.print(f"[dim]    Deep-dive error ({func_name}): {e}[/dim]")

        return findings

    # -----------------------------------------------------------------
    # PHASE 3: VERIFICATION (same as before)
    # -----------------------------------------------------------------

    def verify_findings(self, source_dir: Path, findings: List[Vulnerability],
                       file_contents: Dict[str, str], model: str) -> List[Vulnerability]:
        if not findings:
            return []

        console.print(f"\n[cyan]Verifying {len(findings)} findings...[/cyan]")

        verified = []
        by_file = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)

        for file_path, file_findings in by_file.items():
            content = file_contents.get(file_path, "")
            if not content:
                try:
                    with open(source_dir / file_path, 'r') as f:
                        content = f.read()
                except:
                    verified.extend(file_findings)
                    continue

            language = detect_language(Path(file_path))
            code_lang = get_code_block_lang(language)

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

For each: CONFIRM if mechanism checks out, UNCERTAIN if plausible, REJECT if wrong.

Return JSON:
{{"verifications": [{{"index": 0, "verdict": "CONFIRMED", "reasoning": "...", "adjusted_severity": "high", "adjusted_confidence": 0.8}}]}}
"""

                try:
                    response = self.inference(
                        [{"role": "system", "content": SYSTEM_VERIFY}, {"role": "user", "content": verify_prompt}],
                        model=model, timeout=120
                    )
                    result = self.clean_json(response.get('content', '{}'))

                    for i, finding in enumerate(batch):
                        v_result = next((v for v in result.get('verifications', []) if v.get('index') == i), None)

                        if v_result is None:
                            if finding.confidence >= 0.8:
                                verified.append(finding)
                        elif v_result.get('verdict', '').upper() == 'CONFIRMED':
                            if v_result.get('adjusted_severity'):
                                try: finding.severity = Severity(v_result['adjusted_severity'].lower())
                                except: pass
                            if v_result.get('adjusted_confidence') is not None:
                                try: finding.confidence = float(v_result['adjusted_confidence'])
                                except: pass
                            finding.status = "verified"
                            verified.append(finding)
                            console.print(f"[green]  V {finding.title[:50]}[/green]")
                        elif v_result.get('verdict', '').upper() == 'UNCERTAIN':
                            finding.confidence = max(finding.confidence - 0.1, 0.5)
                            if finding.confidence >= 0.7 or finding.severity.value in ('critical', 'high'):
                                finding.status = "uncertain"
                                verified.append(finding)
                                console.print(f"[yellow]  ~ {finding.title[:50]}[/yellow]")
                        else:
                            console.print(f"[dim]  X {finding.title[:50]}[/dim]")

                except Exception as e:
                    console.print(f"[yellow]  Verify error: {e}[/yellow]")
                    for f in batch:
                        if f.confidence >= 0.8:
                            verified.append(f)

        return verified

    # -----------------------------------------------------------------
    # FILE DISCOVERY & RELATED CONTENT
    # -----------------------------------------------------------------

    def find_files(self, source_dir: Path) -> List[Path]:
        exclude = {
            'node_modules', 'test', 'tests', 'script', 'scripts',
            'mocks', 'mock', 'lib', '.git', 'cache', 'out', 'forge-std',
            'interfaces'
        }

        files = []
        for pattern in ['**/*.sol', '**/*.vy', '**/*.rs']:
            files.extend(source_dir.glob(pattern))

        def should_include(f: Path) -> bool:
            if not f.is_file():
                return False
            if is_test_or_mock_file(f):
                return False
            for part in f.parts:
                if part.lower() in exclude:
                    return False
            return True

        files = [f for f in files if should_include(f)]

        oos_path = source_dir / 'out_of_scope.txt'
        if oos_path.exists():
            with open(oos_path) as f:
                oos = {l.strip() for l in f if l.strip() and not l.startswith('#')}
            files = [f for f in files if not any(s in str(f.relative_to(source_dir)) for s in oos)]

        return sorted(files, key=lambda f: (len(f.parts), str(f)))

    def get_related_content(self, file_path: Path, all_files: List[Path], source_dir: Path) -> str:
        with open(file_path, 'r') as f:
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
            term_clean = term.replace('./', '').replace('../', '').replace('.sol', '').replace('.rs', '').split('/')[-1]
            for f in all_files:
                if term_clean in f.stem and f != file_path:
                    related.append(f)

        parts = []
        total_len = 0
        max_len = 20000

        for rf in related[:6]:
            try:
                with open(rf, 'r') as f:
                    rc = f.read()
                if total_len + len(rc) < max_len:
                    rf_lang = detect_language(rf)
                    parts.append(f"\nRELATED FILE: {rf.relative_to(source_dir)}\n```{get_code_block_lang(rf_lang)}\n{rc}\n```")
                    total_len += len(rc)
            except:
                pass

        return '\n'.join(parts)

    # -----------------------------------------------------------------
    # MAIN ORCHESTRATOR
    # -----------------------------------------------------------------

    def analyze_project(self, source_dir: Path, project_name: str) -> AnalysisResult:
        console.print(f"\n[bold cyan]=== Analyzing: {project_name} ===[/bold cyan]")

        model = self.config.get('analysis_model', self.model)
        verify_model = self.config.get('verify_model', model)

        files = self.find_files(source_dir)
        if not files:
            console.print("[yellow]No files found[/yellow]")
            return AnalysisResult(
                project=project_name, timestamp=datetime.now().isoformat(),
                files_analyzed=0, files_skipped=0, total_vulnerabilities=0,
                vulnerabilities=[], token_usage={'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}
            )

        max_files = min(len(files), 15)
        files_to_analyze = files[:max_files]
        console.print(f"[dim]Found {len(files)} files, analyzing {len(files_to_analyze)}[/dim]")

        # Pre-compute context
        related_map = {}
        file_contents: Dict[str, str] = {}
        for f in files_to_analyze:
            related_map[f] = self.get_related_content(f, files, source_dir)
            rel_path = str(f.relative_to(source_dir))
            try:
                with open(f, 'r') as fh:
                    file_contents[rel_path] = fh.read()
            except:
                pass

        # Language-specific prompt selection: 3 prompts for Solidity, 1 broad for Rust
        solidity_prompts = [
            (model, SYSTEM_VALUE_FLOW, 'value_flow'),
            (model, SYSTEM_STATE_LIFECYCLE, 'state_lifecycle'),
            (model, SYSTEM_ACCESS_ENVIRONMENT, 'access_env'),
        ]

        rust_prompts = [
            (model, SYSTEM_RUST_BROAD, 'rust_broad'),
            (model, SYSTEM_STATE_LIFECYCLE, 'state_lifecycle'),  # State patterns are universal
        ]

        vyper_prompts = solidity_prompts

        all_vulns = []
        total_in = total_out = 0

        # =============================================
        # PHASE 1: BROAD SWEEP WITH COT (3 prompts/file)
        # =============================================
        total_tasks = sum(
            len(rust_prompts) if detect_language(f) == 'rust' else len(solidity_prompts)
            for f in files_to_analyze
        )
        console.print(f"\n[cyan]Phase 1: Broad Sweep with CoT ({len(files_to_analyze)} files, {total_tasks} tasks)[/cyan]")

        with ThreadPoolExecutor(max_workers=8) as executor:
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

                for m, prompt, name in prompts:
                    future = executor.submit(
                        self.analyze_file_with_prompt,
                        source_dir, rel_path, related, m, prompt, name
                    )
                    futures[future] = (rel_path, name)

            for future in as_completed(futures, timeout=15*60):
                try:
                    vulns, inp, out = future.result(timeout=240)
                    total_in += inp; total_out += out
                    all_vulns.extend(vulns)
                except Exception as e:
                    rel, name = futures[future]
                    console.print(f"[red]Task failed ({rel}/{name}): {e}[/red]")

        console.print(f"[cyan]Phase 1 found {len(all_vulns)} raw findings[/cyan]")

        # =============================================
        # PHASE 1B: ACCESS CONTROL PRE-SCAN
        # =============================================
        console.print(f"\n[cyan]Phase 1B: Access Control Scan[/cyan]")
        access_findings = self.scan_access_control(source_dir, files_to_analyze, file_contents, model)
        all_vulns.extend(access_findings)
        console.print(f"[dim]  Access scan added {len(access_findings)} findings[/dim]")

        # =============================================
        # PHASE 2: DEEP-DIVE ON VALUE FUNCTIONS
        # =============================================
        console.print(f"\n[cyan]Phase 2: Deep-Dive on Value Functions[/cyan]")
        deep_findings = self.deep_dive_value_functions(
            source_dir, files_to_analyze, file_contents, all_vulns, model
        )
        all_vulns.extend(deep_findings)
        console.print(f"[dim]  Deep-dive added {len(deep_findings)} findings[/dim]")

        # =============================================
        # DEDUP + RAW OUTPUT (no verification/quality gate)
        # =============================================
        deduped = deduplicate_findings(all_vulns)
        console.print(f"[dim]After dedup: {len(deduped)} unique findings[/dim]")

        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        deduped.sort(key=lambda v: (order.get(v.severity.value, 4), -v.confidence))

        console.print(f"\n[green]Final (RAW, no verification): {len(deduped)} findings[/green]")

        # Save human-readable text dump for grep
        raw_text_path = "raw_findings.txt"
        with open(raw_text_path, 'w') as f:
            for v in deduped:
                f.write(f"{'='*80}\n[{v.severity.value.upper()}] {v.title}\n")
                f.write(f"File: {v.file} | Location: {v.location}\n")
                f.write(f"Confidence: {v.confidence} | Prompt: {v.reported_by_model}\n")
                f.write(f"Type: {v.vulnerability_type}\n\n{v.description}\n\n")
        console.print(f"[dim]Raw findings: {raw_text_path}[/dim]")
        console.print(f"[dim]Tip: grep -i 'refund\\|receive\\|harvest\\|deploy\\|shares\\|assets' {raw_text_path}[/dim]")

        verified = deduped

        return AnalysisResult(
            project=project_name, timestamp=datetime.now().isoformat(),
            files_analyzed=len(files_to_analyze),
            files_skipped=len(files) - len(files_to_analyze),
            total_vulnerabilities=len(verified),
            vulnerabilities=verified,
            token_usage={'input_tokens': total_in, 'output_tokens': total_out,
                        'total_tokens': total_in + total_out}
        )

    def save_result(self, result: AnalysisResult, output_file: str = "agent_report.json"):
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2)
        console.print(f"[green]Saved: {output_file}[/green]")
        return output_file


# =============================================================================
# MAIN
# =============================================================================

def agent_main(project_dir: str | None = None, inference_api: str | None = None):
    config = {
        'model': "Qwen/Qwen3-Next-80B-A3B-Instruct",
        'analysis_model': "Qwen/Qwen3-Next-80B-A3B-Instruct",
        'verify_model': "Qwen/Qwen3-Next-80B-A3B-Instruct",
    }

    project_dir = project_dir or "/app/project_code"

    console.print(Panel.fit(
        "[bold cyan]Security Agent v12 - RAW DISCOVERY MODE[/bold cyan]\n"
        "[dim]3 CoT prompts | Access pre-scan | Value deep-dive | NO verification[/dim]",
        border_style="cyan"
    ))

    try:
        start = time.time()
        runner = EnhancedRunner(config, inference_api)

        source_dir = Path(project_dir)
        if not source_dir.exists():
            console.print(f"[red]Directory not found: {project_dir}[/red]")
            sys.exit(1)

        result = runner.analyze_project(source_dir, project_dir)
        runner.save_result(result)

        elapsed = time.time() - start
        console.print(Panel.fit(
            f"[bold green]COMPLETE[/bold green]\n"
            f"Files: {result.files_analyzed} analyzed, {result.files_skipped} skipped\n"
            f"Vulnerabilities: {result.total_vulnerabilities}\n"
            f"Time: {elapsed:.1f}s",
            border_style="green"
        ))

        remaining = 10*60 - elapsed
        if remaining > 30:
            console.print(f"[dim]Waiting {remaining:.0f}s for time budget...[/dim]")
            time.sleep(remaining - 30)

        return result.model_dump(mode="json")

    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
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
    time.sleep(10)
    fetch_projects()
    inference_api = 'http://localhost:8087'
    report = agent_main('projects/code4rena_secondswap_2025_02', inference_api=inference_api)
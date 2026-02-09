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
# PROMPT 1: VALUE ACCOUNTING (catches refund bugs, token flow issues)
# =============================================================================

SYSTEM_VALUE_ACCOUNTING = """
You are an expert at finding VALUE ACCOUNTING MISMATCHES in smart contracts.

============================================================
CRITICAL BUG PATTERN: Value In vs Value Out Mismatch
============================================================

Many critical bugs occur when the value TAKEN from a user doesn't match
the value USED in calculations or the value REFUNDED.

STEP-BY-STEP ANALYSIS:

1. TRACE VALUE INPUT
   For each function that takes value from users:
   - What is the REQUESTED amount (parameter)?
   - What is the ACTUAL amount taken (after slippage, fees, limits)?

2. TRACE VALUE OUTPUT
   For each function that returns/refunds value:
   - What amount is given back?
   - Is it based on REQUESTED or ACTUAL amount?

3. CHECK FOR MISMATCH
   The bug pattern is:
   - Take ACTUAL_AMOUNT but refund based on REQUESTED_AMOUNT
   - Or: Take REQUESTED_AMOUNT but only use ACTUAL_AMOUNT

4. TOKEN BALANCE PER PATH
   For EACH code path: what enters, what exits, does it balance?

5. REFUND LOGIC
   - Refund issued when NO refund should happen
   - Refund calculated on wrong base
   - Missing refund when partial execution

IMPORTANT: Only report if you can identify the EXACT functions and EXACT
mismatch. Do not report generic "missing validation" concerns.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 2: MISSING USER PROTECTIONS (slippage, deadlines)
# =============================================================================

SYSTEM_USER_PROTECTIONS = """
You are an expert at finding MISSING USER PROTECTIONS in DeFi smart contracts.

============================================================
CRITICAL: Missing Slippage/Deadline Protection
============================================================

1. IDENTIFY VALUE-CHANGING OPERATIONS
   - Swaps, liquidity add/remove, position updates, withdrawals

2. CHECK FOR MIN/MAX AMOUNT PARAMETERS
   - minAmountOut / amount0Min / amount1Min?
   - Are these enforced?

3. CHECK FOR DEADLINE
   - Can transactions be held and executed later?

4. REMOVED PROTECTIONS
   - Old function had slippage -> new function doesn't
   - Parameters exist but unused

IMPORTANT: Only report if the function ACTUALLY lacks protection.
Name the EXACT function and show WHY it's vulnerable.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 3: PRECISION/ROUNDING
# =============================================================================

SYSTEM_PRECISION = """
You are an expert at finding PRECISION and ROUNDING bugs in smart contracts.

============================================================
CRITICAL: Index/Balance Desync on Zero Rounding
============================================================

1. IDENTIFY INDEX-BASED ACCOUNTING
   - rewardIndex, accumulatedRewardPerShare, pricePerShare
   - Any division followed by state update

2. TRACE UPDATE SEQUENCE
   ```
   accrued = currentBalance - lastBalance;
   deltaIndex = accrued / totalShares;  // Can round to 0!
   index += deltaIndex;                  // Might not change
   lastBalance = currentBalance;         // ALWAYS updates!
   ```
   BUG: If deltaIndex rounds to 0, rewards are LOST.

3. LINEAR RELEASE / DRIP RATE CALCULATIONS
   - When a total amount is divided into periodic releases, does the
     rate calculation account for amounts already distributed?
   - After a position transfer or partial claim, is the remaining
     entitlement recalculated correctly (not from the original total)?

IMPORTANT: Only report if you can show the EXACT division that rounds
to zero and the EXACT state variables that desync.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 4: CONTROL FLOW (if-else bugs, direction bugs)
# =============================================================================

SYSTEM_CONTROL_FLOW = """
You are an expert at finding CONTROL FLOW bugs in smart contracts.

============================================================
PATTERN 1: Mutually Exclusive Branches That Shouldn't Be
============================================================

Look for if/else-if chains where INDEPENDENT conditions are treated
as mutually exclusive. Both branches may need to execute in the same
transaction, but the else-if structure prevents this.

Ask: Can both conditions be true simultaneously? If yes, the second
branch is silently skipped.

============================================================
PATTERN 2: Wrong Flag or Direction Calculation
============================================================

Look for boolean or bitmask values derived from token identity or
ordering assumptions. Common bug: the code assumes a fixed token
ordering (e.g., tokenA is always token0) but the actual ordering
depends on address sort order or pool configuration.

Ask: Does this flag/mask calculation hold for ALL valid input orderings?

============================================================
PATTERN 3: Unvalidated Caller-Supplied Parameters
============================================================

Look for public/external functions that accept parameters controlling
execution logic (direction flags, routing paths, target addresses)
without validation. An attacker can pass arbitrary values to manipulate
protocol behavior.

Ask: Can an attacker supply a value that changes execution in an
unintended way?

IMPORTANT: Only report if you find the EXACT if-else chain or
EXACT parameter that is wrong. Show the concrete scenario.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 5: GAS/EXECUTION + FRONT-RUNNING
# =============================================================================

SYSTEM_EXECUTION_ENV = """
You are an expert at finding EXECUTION ENVIRONMENT bugs in smart contracts.

============================================================
PATTERN 1: Gas Griefing via 63/64 Rule
============================================================
- Functions that consume a nonce or irreversible state change BEFORE
  making an external subcall
- Flags that allow silent failure (non-reverting paths) after state
  is already committed
- Signed operations where the signature is consumed even if the
  underlying operation fails

============================================================
PATTERN 2: Front-Running Signed Operations
============================================================
- Signature-based execution where anyone can submit a valid signature
- Missing msg.sender validation in the execution path
- Attacker can front-run with different execution parameters (e.g.,
  zero value, different gas, altered calldata)

============================================================
PATTERN 3: Predictable Address Front-Running
============================================================
- CREATE/CREATE2/clone with deterministic or predictable addresses
- Attacker pre-deploys or pre-initializes at the predicted address
  before the protocol does, causing permanent DoS

IMPORTANT: Only report if you can show the EXACT attack path.
Name the function, the subcall, and what happens when it fails.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 6: OPERATION REVERSAL/CANCELLATION
# =============================================================================

SYSTEM_OPERATION_REVERSAL = """
You are an expert at finding STATE REVERSAL bugs in smart contracts.

============================================================
CRITICAL: Incomplete State Restoration on Cancel/Undo
============================================================

When an operation is CANCELLED, ALL state changes must be reversed.

1. IDENTIFY REVERSIBLE OPERATIONS
   - cancel(), abort(), undo() functions
   - Timeout/expiry handlers
   - Withdrawal cancellation

2. MAP ORIGINAL STATE CHANGES
   List ALL variables modified by the original operation.

3. VERIFY COMPLETE REVERSAL
   For EACH state change: is it reversed in cancel?

   The bug pattern is: the original operation modifies N state variables,
   but the cancellation only restores N-1 of them. The missing restoration
   leaves the protocol in an inconsistent state (e.g., a buffer or counter
   is permanently decremented without being restored on cancel).

   For every cancel/undo function, enumerate the state changes in the
   original operation and verify each one has a corresponding reversal.

4. RECEIVE/FALLBACK TRAPS
   - Does receive() perform side effects (auto-staking, auto-minting)?
   - Can withdrawal refunds trigger receive() and get re-captured?

5. VESTING/ENTITLEMENT STATE ON TRANSFER
   - When a position is transferred, is historical progress preserved?
   - Are per-step or per-period counters correctly split or inherited?
   - Is the release rate recalculated accounting for already-claimed amounts?

IMPORTANT: Only report if you can show EXACTLY which state
variable is NOT reversed. Name both the original function
and the cancel function.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 7: STATE CONSISTENCY (Paired Operation Asymmetry)
# =============================================================================

SYSTEM_STATE_CONSISTENCY = """
You find bugs where STATE CHANGES ARE ASYMMETRIC between paired operations.

============================================================
PAIRED OPERATION ANALYSIS
============================================================

1. IDENTIFY OPERATION PAIRS in this contract:
   - request/cancel, queue/confirm, stake/unstake
   - deposit/withdraw, lock/unlock, mint/burn
   - create/close, open/settle

2. FOR EACH PAIR, build a STATE CHANGE TABLE:

   FORWARD OPERATION (e.g., queueWithdrawal):
   - List EVERY state variable modified (assignments, increments, decrements)
   - Include mappings, arrays, counters, balances, buffers

   REVERSE OPERATION (e.g., cancelWithdrawal):
   - List EVERY state variable modified
   - CHECK: Does each forward change have a corresponding reverse?

3. BUG PATTERN: Asymmetric State Restoration
   If forward modifies [buffer, counter, mapping, balance]
   But reverse only modifies [counter, mapping]
   Then buffer and balance are NEVER RESTORED = BUG

Example:
```
   queueWithdrawal(): buffer -= amount; requests[id] = data;
   cancelWithdrawal(): delete requests[id]; // BUG: buffer not restored!
```

============================================================
TEMPORAL ORDERING ATTACKS
============================================================

4. For operations that QUEUE state for later execution:
   - What exchange rate / value is LOCKED IN at queue time?
   - What if an EXTERNAL EVENT (slashing, fee change, price update)
     occurs BETWEEN queue and confirm?
   - Do earlier queuers get unfair advantage over later queuers?

   Example: User A queues withdrawal at exchange rate X
            Slashing event changes rate to Y
            User A confirms at rate X (locked in)
            User B can only get rate Y = UNFAIR, A drains funds

IMPORTANT: Only report if you identify:
- EXACT state variable not restored, OR
- EXACT scenario where ordering creates unfairness with fund loss

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 8: ADVERSARIAL CONTROL (Attacker-Controlled Parameters)
# =============================================================================

SYSTEM_ADVERSARIAL_CONTROL = """
You find bugs exploitable via ATTACKER-CONTROLLED parameters.

============================================================
ADVERSARIAL CONTROL POINTS
============================================================

For each external/public function, identify what an ATTACKER controls:
- msg.value (can be 0 even for payable functions)
- gasleft() at any call site (attacker chooses tx gas limit)
- calldata parameters (especially lengths, indices, addresses)
- Block timing (can delay tx to manipulate timestamp/blocknumber)

============================================================
GAS GRIEFING VIA 63/64 RULE (EIP-150)
============================================================

CRITICAL PATTERN to find:
1. Function consumes IRREVERSIBLE state BEFORE external call
   - nonce++, delete mapping, balance -= amount
2. External call uses call/delegatecall/send (NOT staticcall)
3. Function has non-reverting path when call fails
   - shouldRevert=false, try/catch, check success but don't revert
4. EIP-150 forwards only 63/64 of remaining gas to subcall

ATTACK: Attacker supplies just enough gas for outer function but NOT subcall
RESULT: State consumed (nonce used), subcall fails, attacker achieves DoS

Look for these kind of pattern:
```
nonce++;  // STATE CONSUMED FIRST
(success,) = target.call{{value: v}}(data);  // SUBCALL - gets 63/64 gas
if (!shouldRevert && !success) {{ return; }}  // NON-REVERTING PATH
// BUG: nonce consumed even though intended call failed
```

============================================================
SIGNATURE REPLAY/GRIEFING
============================================================

If function uses signatures:
- Can attacker submit valid signature with different msg.value than signer expected?
- Can attacker submit signature with carefully chosen gas limit?
- Can attacker front-run and consume signature before intended use?

============================================================
VALUE GRIEFING
============================================================

If function can be called by anyone with a valid signature:
- Can attacker call with msg.value = 0 when value was expected?
- Can attacker supply different gas than signer intended?

IMPORTANT: Only report with EXACT function name, EXACT state that gets
consumed, and EXACT attacker action that causes griefing.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 9: GENERAL SECURITY
# =============================================================================

SYSTEM_GENERAL = """
You are an EXPERT smart contract security auditor.

Find bugs that cause:
- Direct loss of user funds
- Unauthorized access to funds/privileges
- Permanent denial of service
- Broken accounting invariants

ANALYSIS APPROACH:

1. FUNCTION-BY-FUNCTION
   - STATE: All related variables updated together?
   - CALCULATIONS: Edge cases (0, max, first/last)?
   - EXTERNAL CALLS: State before or after?
   - ACCESS: Who can call?

2. DELEGATION/STAKING
   - Are reward claims routed to the correct recipient (delegator vs validator)?
   - Can an intermediary claim rewards that belong to the end user?
   - Is staked balance properly reset or checkpointed before unstaking?

3. ENUMERATION GAPS
   - If items can be burned or removed, does iteration logic still cover all live items?
   - Can loops based on a decreasing counter skip valid entries?

4. POSITION LIFECYCLE
   - When positions change hands (transfer, listing, marketplace sale),
     is per-position progress state (claimed amounts, accrued time, step counters)
     correctly scoped to the position rather than shared globally?
   - Can a new owner inherit stale or incorrect state from a prior owner?

IMPORTANT: Only report SPECIFIC bugs with CONCRETE exploit paths.
Do NOT report generic concerns like "missing validation" or "centralization risk"
unless you can show exact steps to exploit.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 10: RUST/STYLUS VALUE ACCOUNTING
# =============================================================================

SYSTEM_RUST_VALUE_ACCOUNTING = """
You are an expert at finding VALUE ACCOUNTING MISMATCHES in Rust smart contracts (Stylus, Solana, CosmWasm, etc.).

============================================================
CRITICAL BUG PATTERN: Value In vs Value Out Mismatch
============================================================

Many critical bugs occur when the value TAKEN from a user doesn't match
the value USED in calculations or the value REFUNDED.

STEP-BY-STEP ANALYSIS FOR RUST:

1. TRACE VALUE INPUT
   Look for functions that take tokens/value from users:
   - `erc20::take()`, `transfer_from()`, `deposit()`
   - `msg_value()`, `value()` for native tokens
   - What is the REQUESTED amount (parameter)?
   - What is the ACTUAL amount taken (after slippage, limits)?

2. TRACE VALUE OUTPUT
   Look for functions that return/refund value:
   - `erc20::transfer_to_sender()`, `transfer()`, `withdraw()`
   - Is refund based on REQUESTED or ACTUAL amount?

3. CHECK FOR MISMATCH
   The bug pattern is:
   - Take ACTUAL_AMOUNT (e.g., `erc20::take(from, amount_in, ...)`)
   - But refund based on ORIGINAL_AMOUNT (e.g., `original_amount - amount_in`)
   - This causes DOUBLE SPEND: take less, refund the difference you never took

4. RUST-SPECIFIC PATTERNS
   - `checked_sub()`, `saturating_sub()` - can mask calculation errors
   - Multiple return paths with different refund logic
   - `?` operator early returns before cleanup
   - Pattern: take(actual) then transfer(original - actual) = BUG if original != taken

IMPORTANT: Only report if you can identify the EXACT functions and EXACT
mismatch. Name specific Rust functions and state variables.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 11: RUST/STYLUS CONTROL FLOW
# =============================================================================

SYSTEM_RUST_CONTROL_FLOW = """
You are an expert at finding CONTROL FLOW bugs in Rust smart contracts.

============================================================
PATTERN 1: Error Handling Gaps
============================================================

Rust uses Result<T, E> for error handling. Look for:
- `unwrap()` or `expect()` that can panic in production
- `?` operator that returns early WITHOUT cleanup
- `ok()` or `unwrap_or_default()` silently ignoring errors
- Match statements that don't handle all variants

Ask: When this path errors, is all state properly restored?

============================================================
PATTERN 2: Redundant/Conflicting Logic
============================================================

Look for code that does the same thing twice differently:
- Taking amount X then also refunding (original - X) when X was already exact
- Setting a value then immediately overwriting it
- Two different "fixes" for the same problem that conflict

Example bug pattern:
```rust
// Old code: take(original_amount)
// "Fix 1": Changed to take(amount_in)  // amount_in <= original
// "Fix 2": Added refund of (original - amount_in)
// Result: Takes amount_in, refunds (original - amount_in)
//         But original was never taken! Free money to user.
```

============================================================
PATTERN 3: Ownership and Borrow Issues in State
============================================================

- State modified through one reference, read through another
- Clone() creating divergent state copies
- Mutable borrows that don't persist changes

============================================================
PATTERN 4: Integer Handling
============================================================

- `as` casts that truncate (u128 as u64)
- Unchecked arithmetic in older Rust versions
- `checked_*` operations that silently return None

IMPORTANT: Only report if you find the EXACT code path or
EXACT parameter that is wrong. Show the concrete scenario.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 12: RUST/STYLUS GENERAL SECURITY
# =============================================================================

SYSTEM_RUST_GENERAL = """
You are an EXPERT Rust smart contract security auditor (Stylus, Solana, CosmWasm).

Find bugs that cause:
- Direct loss of user funds
- Unauthorized access to funds/privileges
- Permanent denial of service
- Broken accounting invariants

RUST-SPECIFIC ANALYSIS:

1. FUNCTION-BY-FUNCTION
   - STATE: Are storage writes via `self.field.set()` properly ordered?
   - CALCULATIONS: Edge cases with `checked_*` vs raw arithmetic?
   - EXTERNAL CALLS: State before or after cross-contract calls?
   - ACCESS: `#[payable]`, `msg_sender()` checks correct?

2. TOKEN FLOW ANALYSIS
   For each function handling tokens:
   - What goes IN? (`erc20::take`, `transfer_from`, `msg_value`)
   - What goes OUT? (`erc20::transfer`, `transfer_to_sender`)
   - Does IN == OUT for the intended flow?
   - Are there paths where OUT > IN (drain) or IN > OUT (stuck)?

3. STYLUS-SPECIFIC PATTERNS
   - `sol_storage!` macro state initialization
   - `#[external]` vs `#[entrypoint]` visibility
   - `stylus_sdk::msg::*` for caller context
   - Revert behavior differences from Solidity

4. ERROR PATH ANALYSIS
   For each `?` or `return Err(...)`:
   - What state was already modified?
   - Is there cleanup or is state left inconsistent?

5. CROSS-CONTRACT CALLS
   - `RawCall::new()`, `call()` patterns
   - Return value handling (success assumed?)
   - Reentrancy through callbacks

IMPORTANT: Only report SPECIFIC bugs with CONCRETE exploit paths.
Name exact Rust functions, modules, and state fields.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 13: RUST RECEIVE/CALLBACK TRAPS
# =============================================================================

SYSTEM_RUST_CALLBACKS = """
You are an expert at finding CALLBACK and RECEIVE bugs in Rust smart contracts.

============================================================
PATTERN 1: Unintended Auto-Execution
============================================================

When native tokens are received, contracts may auto-execute logic:
- `#[payable]` fallback/receive handlers
- Default handlers that call other functions
- Auto-staking, auto-minting on receive

Bug pattern:
```rust
// Receive handler auto-stakes any incoming funds
#[payable]
fn receive(&mut self) -> Result<(), Error> {
    self.stake()?;  // BUG: Withdrawal refunds get auto-staked!
    Ok(())
}
```

2. TRACE NATIVE TOKEN FLOWS
   - Where does the contract expect to RECEIVE native tokens?
   - Where does it SEND native tokens (refunds, withdrawals)?
   - Can send destinations have receive handlers?

3. WITHDRAWAL FLOW ANALYSIS
   When user requests withdrawal:
   - Token sent from protocol to user
   - If user is a contract with receive(), what happens?
   - If protocol itself receives the tokens back, what happens?

4. SYSTEM/CORE ADDRESS INTERACTIONS
   - L1 <-> L2 bridges sending funds
   - Validator reward distributions
   - Protocol-to-protocol transfers
   - Do these trigger auto-execution?

IMPORTANT: Only report if you can show the EXACT callback path
and EXACT unintended behavior.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# VERIFICATION PROMPT - SPECIFICITY FOCUSED
# =============================================================================

SYSTEM_VERIFY = """
You are verifying potential vulnerabilities in smart contracts.

============================================================
MANDATORY SPECIFICITY CHECK
============================================================

For each finding, verify these MUST be present for CONFIRMED status:

1. CODE GROUNDING (Required)
   - Does finding reference specific function names that exist in the code?
   - Can you find the described code pattern in the actual source?
   - REJECT if finding says "could happen" without pointing to WHERE in code

2. MECHANISM VERIFICATION (Required)
   - Trace the described attack step by step through actual code
   - Does the code ACTUALLY behave as the finding claims?
   - REJECT if mechanism doesn't match code reality

3. CONCRETE EXPLOIT PATH (Required)
   - Are specific function calls named?
   - Are specific state variables mentioned?
   - REJECT generic "an attacker could..." without specifics

============================================================
CLASSIFICATION
============================================================

CONFIRMED (real bug with clear exploit):
- You can trace the exact code path in the provided source
- The mechanism matches actual code behavior
- Impact is concrete and quantifiable
- Finding names exact functions and state variables
- You can see the vulnerable code lines

UNCERTAIN (plausible but not fully verifiable):
- The function exists but mechanism is complex to fully trace
- Cross-file issue where you can't see full picture
- Plausible pattern but would need dynamic testing to confirm
- Finding is specific but code path has multiple branches

REJECTED (clearly wrong or not useful):
- Described function doesn't exist in code
- Mechanism CONTRADICTS actual code (code has protection)
- Pure informational/style/gas optimization finding
- Generic pattern without code grounding
- Finding claims "function does X" but function actually does Y
- Solidity 0.8+ overflow/underflow without unchecked block
- Test/mock contract only
- Requires malicious admin (centralization)

============================================================
CONFIDENCE ADJUSTMENT
============================================================

Start at finding's stated confidence, then adjust:
- Finding references exact function names in code: +0.1
- Finding names exact state variables: +0.1
- Finding has numeric attack scenario: +0.1
- Finding is generic pattern description: -0.3
- Finding references non-existent function: -> REJECT

IMPORTANT: When in doubt between UNCERTAIN and REJECTED, prefer UNCERTAIN.
Only REJECT when you're confident the mechanism is wrong or finding is generic.

Return JSON:
{{
    "verifications": [
        {{
            "index": 0,
            "verdict": "CONFIRMED" or "UNCERTAIN" or "REJECTED",
            "reasoning": "Brief explanation with code reference if applicable",
            "adjusted_severity": "critical/high/medium/low",
            "adjusted_confidence": 0.0-1.0
        }}
    ]
}}
"""

# =============================================================================
# PRE-FILTER PATTERNS (balanced)
# =============================================================================

KNOWN_FALSE_POSITIVE_PATTERNS = [
    # Informational (never real bugs)
    r'missing\s+events?\s+emission',
    r'floating\s+pragma',
    r'missing\s+natspec',
    r'code\s+style',
    r'gas\s+optimization',
    r'lack\s+of\s+documentation',
    r'missing\s+zero\s+address\s+check',

    # Pure centralization (no exploit)
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


def detect_language(file_path: Path) -> str:
    """Detect smart contract language from file extension."""
    suffix = file_path.suffix.lower()
    if suffix == '.sol':
        return 'solidity'
    elif suffix == '.vy':
        return 'vyper'
    elif suffix == '.rs':
        return 'rust'
    else:
        return 'solidity'  # Default


def get_code_block_lang(language: str) -> str:
    """Get markdown code block language identifier."""
    return {
        'solidity': 'solidity',
        'vyper': 'python',  # Vyper is Python-like
        'rust': 'rust',
    }.get(language, 'solidity')


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
    """Filter only truly obvious false positives."""
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


def extract_state_mapping(content: str) -> str:
    """Extract state variables and which functions modify them for grounding analysis."""
    # Find state variable declarations
    state_pattern = r'^\s*(mapping\s*\([^)]+\)|uint\d*|int\d*|bool|address|bytes\d*|string)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*[;=]'
    state_vars = re.findall(state_pattern, content, re.MULTILINE)
    var_names = [name for _, name in state_vars]

    if not var_names:
        return ""

    # Find functions and their state modifications
    func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    functions = re.findall(func_pattern, content, re.DOTALL)

    mapping_lines = ["STATE VARIABLE MAPPING:"]
    for func_name, func_body in functions[:30]:  # Limit to 30 functions
        writes = []
        for var in var_names:
            # Check for assignments (=, +=, -=, *=, /=)
            if re.search(rf'\b{re.escape(var)}\b\s*[\+\-\*\/]?=(?!=)', func_body):
                writes.append(var)
            # Check for delete
            if re.search(rf'delete\s+{re.escape(var)}', func_body):
                writes.append(f"delete:{var}")
            # Check for increment/decrement
            if re.search(rf'\b{re.escape(var)}\b\s*(\+\+|--)', func_body):
                writes.append(var)

        if writes:
            mapping_lines.append(f"  {func_name}() MODIFIES: {', '.join(set(writes))}")

    if len(mapping_lines) == 1:
        return ""  # No state modifications found
    return '\n'.join(mapping_lines[:25])  # Cap output


def extract_rust_state_mapping(content: str) -> str:
    """Extract state variables and function modifications for Rust/Stylus contracts."""
    # Find storage declarations (Stylus patterns)
    storage_patterns = [
        r'#\[storage\][^}]*\{([^}]*)\}',  # #[storage] struct
        r'(?:pub\s+)?(?:static\s+)?(?:mut\s+)?(\w+)\s*:\s*(?:Storage[A-Z]\w+|Mapping|Vec|U256|Address)',  # Storage types
        r'sol_storage!\s*\{([^}]*)\}',  # sol_storage! macro
    ]

    storage_vars = set()
    for pattern in storage_patterns:
        matches = re.findall(pattern, content, re.DOTALL)
        for match in matches:
            # Extract variable names from storage block
            var_matches = re.findall(r'(?:pub\s+)?(\w+)\s*:', match if isinstance(match, str) else str(match))
            storage_vars.update(var_matches)

    # Also look for common Stylus storage field patterns
    field_pattern = r'self\.(\w+)\s*(?:\.|\.get|\.set|\.insert|\.remove|\+=|-=|=)'
    field_vars = re.findall(field_pattern, content)
    storage_vars.update(field_vars)

    if not storage_vars:
        return ""

    # Find functions and their state modifications
    # Rust function pattern: pub fn name(...) or fn name(...)
    func_pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    functions = re.findall(func_pattern, content, re.DOTALL)

    mapping_lines = ["RUST STATE VARIABLE MAPPING:"]
    for func_name, func_body in functions[:30]:
        writes = []
        for var in storage_vars:
            # Check for modifications via self.var
            if re.search(rf'self\.{re.escape(var)}\s*(?:\.|\.set|\.insert|\+=|-=|=(?!=))', func_body):
                writes.append(var)
            # Check for storage macro patterns
            if re.search(rf'{re.escape(var)}\s*(?:\.set|\.insert|\.remove|\+=|-=|=(?!=))', func_body):
                writes.append(var)

        if writes:
            mapping_lines.append(f"  {func_name}() MODIFIES: {', '.join(set(writes))}")

    if len(mapping_lines) == 1:
        return ""
    return '\n'.join(mapping_lines[:25])


def extract_state_mapping_for_language(content: str, language: str) -> str:
    """Extract state mapping based on detected language."""
    if language == 'rust':
        return extract_rust_state_mapping(content)
    else:
        return extract_state_mapping(content)


def deduplicate_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Deduplicate by semantic root cause, keeping max 2 per root cause cluster."""
    if not vulnerabilities:
        return []

    # Sort by confidence first
    sorted_vulns = sorted(vulnerabilities, key=lambda x: -x.confidence)

    # First pass: lexical dedup
    lexical_dedup = []
    for vuln in sorted_vulns:
        is_duplicate = False
        vuln_title_lower = vuln.title.lower()
        vuln_words = set(re.findall(r'\w{4,}', vuln_title_lower))

        for existing in lexical_dedup:
            if vuln.file != existing.file:
                continue

            # Same type + similar location
            if vuln.vulnerability_type == existing.vulnerability_type:
                if vuln.location[:30] == existing.location[:30]:
                    is_duplicate = True
                    break

            # Similar title (first 40 chars)
            if vuln_title_lower[:40] == existing.title.lower()[:40]:
                is_duplicate = True
                break

            # Word overlap in title (>60% same words = duplicate)
            existing_words = set(re.findall(r'\w{4,}', existing.title.lower()))
            if vuln_words and existing_words:
                overlap = len(vuln_words & existing_words) / max(len(vuln_words | existing_words), 1)
                if overlap > 0.6:
                    is_duplicate = True
                    break

            # Same function mentioned in both descriptions (likely same bug)
            vuln_funcs = set(re.findall(r'(\w+)\s*\(', vuln.description[:200]))
            existing_funcs = set(re.findall(r'(\w+)\s*\(', existing.description[:200]))
            common_funcs = vuln_funcs & existing_funcs - {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return'}
            if len(common_funcs) >= 2 and vuln.vulnerability_type == existing.vulnerability_type:
                is_duplicate = True
                break

        if not is_duplicate:
            lexical_dedup.append(vuln)

    # Second pass: semantic root-cause clustering
    # Key = (file, primary_function, bug_category)
    clusters: dict[tuple, List[Vulnerability]] = {}
    stopwords = {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return', 'memory', 'storage', 'calldata', 'msg', 'sender', 'value'}

    for v in lexical_dedup:
        # Extract primary function mentioned
        funcs = re.findall(r'(\w+)\s*\(', f"{v.title} {v.description[:300]}")
        funcs = [f for f in funcs if f.lower() not in stopwords and len(f) > 2]
        primary_func = funcs[0] if funcs else "unknown"

        # Classify bug category
        desc_lower = v.description.lower()
        if any(x in desc_lower for x in ['reentran', 'callback', 're-enter']):
            category = 'reentrancy'
        elif any(x in desc_lower for x in ['refund', 'value mismatch', 'amount taken', 'amount returned', 'value in', 'value out']):
            category = 'value_accounting'
        elif any(x in desc_lower for x in ['cancel', 'not reversed', 'not restored', 'asymmetric', 'state restoration']):
            category = 'state_reversal'
        elif any(x in desc_lower for x in ['gas', '63/64', 'griefing', 'out of gas']):
            category = 'gas_griefing'
        elif any(x in desc_lower for x in ['front-run', 'sandwich', 'mev', 'signature', 'replay']):
            category = 'frontrunning'
        elif any(x in desc_lower for x in ['slippage', 'deadline', 'minAmount', 'maxAmount']):
            category = 'slippage'
        elif any(x in desc_lower for x in ['overflow', 'underflow', 'precision', 'rounding', 'truncat']):
            category = 'precision'
        elif any(x in desc_lower for x in ['access', 'unauthorized', 'privilege', 'role', 'onlyOwner']):
            category = 'access_control'
        else:
            category = 'other'

        key = (v.file, primary_func, category)
        if key not in clusters:
            clusters[key] = []
        clusters[key].append(v)

    # Keep max 2 per cluster
    result = []
    for key, group in clusters.items():
        group.sort(key=lambda x: -x.confidence)
        result.extend(group[:2])

    return result


def compute_specificity_score(finding: Vulnerability, file_content: str = "") -> float:
    """Score finding specificity for quality gate ranking."""
    score = 0.0
    desc = finding.description

    # Code quotes that actually exist in file
    if file_content:
        quotes = re.findall(r'`([^`]+)`', desc)
        for quote in quotes:
            if len(quote) > 5 and quote in file_content:
                score += 0.15
                break  # Cap at one match

    # Specific function name mentions (pattern: word followed by parentheses)
    func_mentions = len(re.findall(r'\b[a-zA-Z_]\w+\s*\(\)', desc))
    score += min(func_mentions * 0.08, 0.24)

    # Specific state variables (common naming patterns)
    state_vars = len(re.findall(r'\b\w+(?:Amount|Balance|Counter|Index|Rate|Buffer|Total|Supply|Nonce|Limit|Fee)\b', desc, re.I))
    score += min(state_vars * 0.1, 0.2)

    # Numeric attack scenario (values with units)
    if re.search(r'\d+\s*(?:wei|ether|gwei|gas|%|x\b)', desc, re.I):
        score += 0.1

    # Step-by-step attack description
    if re.search(r'(?:step\s*\d|1\.\s*\w|first\s*,.*then\s*,|1\)|2\))', desc, re.I):
        score += 0.1

    # Line number references
    if re.search(r'line\s*\d+|L\d+|:\d+', desc, re.I):
        score += 0.1

    return min(score * finding.confidence, 1.0)


def apply_quality_gate(findings: List[Vulnerability],
                       file_contents: Dict[str, str],
                       max_findings: int = 80) -> List[Vulnerability]:
    """Keep top findings by specificity if over limit."""
    if len(findings) <= max_findings:
        return findings

    console.print(f"[dim]  Quality gate: {len(findings)} findings -> max {max_findings}[/dim]")

    # Score each finding
    scored = []
    for f in findings:
        content = file_contents.get(f.file, "")
        spec_score = compute_specificity_score(f, content)
        scored.append((spec_score, f))

    # Sort by specificity score descending, then by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    scored.sort(key=lambda x: (-x[0], severity_order.get(x[1].severity.value, 4)))

    # Keep top max_findings
    return [f for _, f in scored[:max_findings]]


# =============================================================================
# RUNNER
# =============================================================================

class EnhancedRunner:
    def __init__(self, config: dict | None = None, inference_api: str | None = None):
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
        return {"error": "Max retries exceeded"}  # Unreachable but satisfies type checker

    def clean_json(self, response: str) -> dict:
        response = response.strip()
        if "```" in response:
            lines = response.split('\n')
            lines = [l for l in lines if not l.strip().startswith("```")]
            response = '\n'.join(lines)

        start = response.find('{')
        if start == -1:
            return {"vulnerabilities": []}

        depth = 0
        end = start
        for i, c in enumerate(response[start:], start):
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        extracted = response[start:end]
        if not extracted:
            return {"vulnerabilities": []}
        return json.loads(extracted)

    def analyze_file_with_prompt(
        self,
        source_dir: Path,
        relative_path: str,
        related_content: str,
        model: str,
        system_prompt: str,
        prompt_name: str,
    ) -> Tuple[List[Vulnerability], int, int]:
        file_path = Path(relative_path)

        with open(source_dir / file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Detect language for appropriate code blocks and state extraction
        language = detect_language(file_path)
        code_lang = get_code_block_lang(language)

        console.print(f"[dim]  -> {file_path.name} ({prompt_name}) [{language}][/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        system = system_prompt.format(format_instructions=parser.get_format_instructions())

        # Extract state variable mapping for grounding analysis (language-aware)
        state_mapping = extract_state_mapping_for_language(content, language)
        state_mapping_section = f"\n{state_mapping}\n" if state_mapping else ""

        # Language-specific analysis hints
        lang_hint = ""
        if language == 'rust':
            lang_hint = """
RUST/STYLUS CONTRACT ANALYSIS:
- Look for erc20::take(), erc20::transfer_to_sender() patterns
- Check self.field.set(), self.field.get() for storage access
- Trace Result<T, E> and ? operator error paths
- Watch for checked_sub(), saturating_sub() masking errors
"""
        elif language == 'vyper':
            lang_hint = """
VYPER CONTRACT ANALYSIS:
- Look for @external, @internal decorators for visibility
- Check send(), raw_call() for external calls
- Trace self.variable for storage access
"""

        user_msg = f"""
Analyze this smart contract for security vulnerabilities:

PRIMARY FILE: {file_path}
```{code_lang}
{content}
```
{state_mapping_section}
{lang_hint}
{related_content}

Find SPECIFIC, exploitable vulnerabilities. For each finding:
- Name the EXACT function
- Describe the EXACT code behavior with specific state variable names
- Give CONCRETE exploit steps
- Show REAL impact with specific values
"""

        try:
            response = self.inference(
                [{"role": "system", "content": system}, {"role": "user", "content": user_msg}],
                model=model
            )

            result = self.clean_json(response.get('content', '{}'))
            vulns = Vulnerabilities(**result)

            validated = []
            for v in vulns.vulnerabilities:
                v.file = str(file_path)
                v.reported_by_model = f"{model}_{prompt_name}"

                should_filter, reason = pre_filter_finding(v, content)
                if should_filter:
                    console.print(f"[dim]    Pre-filtered: {v.title[:40]}... ({reason})[/dim]")
                    continue

                if v.confidence >= 0.7:
                    validated.append(v)

            if validated:
                console.print(f"[green]    Found {len(validated)} potential issues[/green]")

            return validated, response.get('input_tokens', 0), response.get('output_tokens', 0)

        except Exception as e:
            console.print(f"[red]    Error: {e}[/red]")
            return [], 0, 0

    def verify_findings(
        self,
        source_dir: Path,
        findings: List[Vulnerability],
        file_contents: Dict[str, str],
        model: str
    ) -> List[Vulnerability]:
        """Verify with SPECIFICITY focus - reject generic, keep specific."""
        if not findings:
            return []

        console.print(f"\n[cyan]Verifying {len(findings)} findings (specificity filter)...[/cyan]")

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

            # Detect language for this file
            language = detect_language(Path(file_path))
            code_lang = get_code_block_lang(language)

            # Verify in batches of 5 to avoid overwhelming the LLM
            for batch_start in range(0, len(file_findings), 5):
                batch = file_findings[batch_start:batch_start + 5]

                findings_json = json.dumps([
                    {
                        "index": i,
                        "title": f.title,
                        "description": f.description[:400],
                        "vulnerability_type": f.vulnerability_type,
                        "severity": f.severity.value,
                        "location": f.location,
                    }
                    for i, f in enumerate(batch)
                ], indent=2)

                # Give verifier enough code context - truncate intelligently
                code_for_verify = content
                if len(content) > 25000:
                    # Include relevant portions: find functions mentioned in findings
                    mentioned_funcs = set()
                    for f in batch:
                        mentioned_funcs.update(re.findall(r'(\w+)\s*\(', f.description[:500]))
                        mentioned_funcs.update(re.findall(r'(\w+)\s*\(', f.title))

                    # Always include first 15K, then search for mentioned functions in the rest
                    code_for_verify = content[:15000]
                    remaining = content[15000:]
                    for func_name in mentioned_funcs:
                        # Language-aware function pattern matching
                        if language == 'rust':
                            func_patterns = [f'fn {func_name}', f'pub fn {func_name}', f'pub async fn {func_name}']
                        elif language == 'vyper':
                            func_patterns = [f'def {func_name}', f'@external\ndef {func_name}']
                        else:
                            func_patterns = [f'function {func_name}']

                        for func_pattern in func_patterns:
                            idx = remaining.find(func_pattern)
                            if idx != -1:
                                # Include 500 chars before and 2000 after the function
                                start = max(0, idx - 500)
                                end = min(len(remaining), idx + 2000)
                                comment = '//' if language in ('solidity', 'rust') else '#'
                                code_for_verify += f"\n\n{comment} ... (code continues) ...\n\n{remaining[start:end]}"
                                break

                    if len(code_for_verify) > 30000:
                        code_for_verify = code_for_verify[:30000]

                verify_prompt = f"""
Verify these findings against the code. Focus on SPECIFICITY.

CODE ({file_path}):
```{code_lang}
{code_for_verify}
```

FINDINGS:
{findings_json}

For each finding:
1. Does the described function/code path exist in this code? (If unsure, mark UNCERTAIN not REJECTED)
2. Is the bug mechanism plausible given the code logic?
3. Would exploitation lead to real impact (fund loss, DoS, broken invariants)?

Rules:
- CONFIRM if the bug mechanism checks out against the code
- UNCERTAIN if the function exists but you can't fully verify the bug, OR if you can't find the function but the mechanism is plausible
- REJECT ONLY if the mechanism is clearly wrong, or the finding is purely informational/gas/style

Return JSON:
{{
    "verifications": [
        {{"index": 0, "verdict": "CONFIRMED" or "UNCERTAIN" or "REJECTED", "reasoning": "...", "adjusted_severity": "high"}}
    ]
}}
"""

                try:
                    response = self.inference(
                        [{"role": "system", "content": SYSTEM_VERIFY}, {"role": "user", "content": verify_prompt}],
                        model=model,
                        timeout=120
                    )

                    result = self.clean_json(response.get('content', '{}'))

                    for i, finding in enumerate(batch):
                        v_result = None
                        for v in result.get('verifications', []):
                            if v.get('index') == i:
                                v_result = v
                                break

                        if v_result is None:
                            # No result - keep high confidence only
                            if finding.confidence >= 0.8:
                                verified.append(finding)
                                console.print(f"[yellow]  ? No verification: {finding.title[:50]} - keeping (high conf)[/yellow]")
                        elif v_result.get('verdict', '').upper() == 'CONFIRMED':
                            if v_result.get('adjusted_severity'):
                                try:
                                    finding.severity = Severity(v_result['adjusted_severity'].lower())
                                except:
                                    pass
                            # Apply adjusted confidence if provided
                            if v_result.get('adjusted_confidence') is not None:
                                try:
                                    finding.confidence = float(v_result['adjusted_confidence'])
                                except:
                                    pass
                            finding.status = "verified"
                            verified.append(finding)
                            console.print(f"[green]  V Verified: {finding.title[:50]}[/green]")
                        elif v_result.get('verdict', '').upper() == 'UNCERTAIN':
                            # Apply adjusted confidence if provided
                            if v_result.get('adjusted_confidence') is not None:
                                try:
                                    finding.confidence = float(v_result['adjusted_confidence'])
                                except:
                                    finding.confidence = max(finding.confidence - 0.1, 0.5)
                            else:
                                finding.confidence = max(finding.confidence - 0.1, 0.5)
                            # Keep uncertain findings only if high confidence or high severity
                            keep = finding.confidence >= 0.7 or finding.severity.value in ('critical', 'high')
                            if keep:
                                if v_result.get('adjusted_severity'):
                                    try:
                                        finding.severity = Severity(v_result['adjusted_severity'].lower())
                                    except:
                                        pass
                                finding.status = "uncertain"
                                verified.append(finding)
                                console.print(f"[yellow]  ~ Uncertain (kept): {finding.title[:50]}[/yellow]")
                            else:
                                console.print(f"[dim]  ~ Uncertain (dropped, low conf): {finding.title[:50]}[/dim]")
                        else:
                            reason = v_result.get('reasoning', '')[:60]
                            console.print(f"[dim]  X Rejected: {finding.title[:50]} - {reason}[/dim]")

                except Exception as e:
                    console.print(f"[yellow]  Verification error: {e}[/yellow]")
                    # On error, keep high-confidence findings only
                    for finding in batch:
                        if finding.confidence >= 0.8:
                            verified.append(finding)

        return verified

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

        # Language-specific import patterns
        if language == 'rust':
            # Rust: use crate::module, mod module, use super::*
            import_pattern = r'(?:use\s+(?:crate|super|self)::(\w+)|mod\s+(\w+))'
            imports = [m[0] or m[1] for m in re.findall(import_pattern, content)]
            inherits = []  # Rust doesn't have inheritance like Solidity
        elif language == 'vyper':
            # Vyper: from vyper.interfaces import X, import X
            import_pattern = r'(?:from\s+\S+\s+import\s+(\w+)|import\s+(\w+))'
            imports = [m[0] or m[1] for m in re.findall(import_pattern, content)]
            inherits = []
        else:
            # Solidity
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
        max_len = 25000  # Increased from 10000 for better cross-file context

        for rf in related[:8]:  # Increased from 5 to include more related files
            try:
                with open(rf, 'r') as f:
                    rc = f.read()
                if total_len + len(rc) < max_len:
                    rf_lang = detect_language(rf)
                    rf_code_lang = get_code_block_lang(rf_lang)
                    parts.append(f"\nRELATED FILE: {rf.relative_to(source_dir)}\n```{rf_code_lang}\n{rc}\n```")
                    total_len += len(rc)
            except:
                pass

        return '\n'.join(parts)

    def _boost_cross_prompt_findings(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Boost confidence for findings reported by multiple analysis prompts."""
        if not vulns:
            return vulns

        # Group by file + key functions mentioned
        by_file = {}
        for v in vulns:
            by_file.setdefault(v.file, []).append(v)

        for _file_path, file_vulns in by_file.items():
            # Extract key functions from each finding
            for i, v1 in enumerate(file_vulns):
                v1_funcs = set(re.findall(r'(\w+)\s*\(', v1.description[:300]))
                v1_funcs -= {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return'}
                v1_prompt = v1.reported_by_model.split('_')[-1] if v1.reported_by_model else ''

                corroborating_prompts = {v1_prompt}
                for j, v2 in enumerate(file_vulns):
                    if i == j:
                        continue
                    v2_prompt = v2.reported_by_model.split('_')[-1] if v2.reported_by_model else ''
                    if v2_prompt == v1_prompt:
                        continue

                    v2_funcs = set(re.findall(r'(\w+)\s*\(', v2.description[:300]))
                    v2_funcs -= {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return'}

                    # If they share 2+ function names, they're about the same issue
                    common = v1_funcs & v2_funcs
                    if len(common) >= 2:
                        corroborating_prompts.add(v2_prompt)

                if len(corroborating_prompts) >= 2:
                    old_conf = v1.confidence
                    v1.confidence = min(v1.confidence + 0.1, 1.0)
                    if old_conf != v1.confidence:
                        console.print(f"[dim]  Cross-prompt boost: {v1.title[:50]} ({len(corroborating_prompts)} prompts)[/dim]")

        return vulns

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

        console.print(f"[dim]Found {len(files)} files to analyze[/dim]")

        max_files = min(len(files), 15)
        files_to_analyze = files[:max_files]

        console.print("[dim]Computing file relationships...[/dim]")
        related_map = {}
        for f in files_to_analyze:
            related_map[f] = self.get_related_content(f, files, source_dir)

        # Language-specific prompt sets
        solidity_prompts = [
            (model, SYSTEM_VALUE_ACCOUNTING, 'value_accounting'),
            (model, SYSTEM_USER_PROTECTIONS, 'user_protections'),
            (model, SYSTEM_PRECISION, 'precision'),
            (model, SYSTEM_CONTROL_FLOW, 'control_flow'),
            (model, SYSTEM_EXECUTION_ENV, 'execution_env'),
            (model, SYSTEM_OPERATION_REVERSAL, 'operation_reversal'),
            (model, SYSTEM_STATE_CONSISTENCY, 'state_consistency'),
            (model, SYSTEM_ADVERSARIAL_CONTROL, 'adversarial_control'),
            (model, SYSTEM_GENERAL, 'general'),
        ]

        rust_prompts = [
            (model, SYSTEM_RUST_VALUE_ACCOUNTING, 'rust_value_accounting'),
            (model, SYSTEM_RUST_CONTROL_FLOW, 'rust_control_flow'),
            (model, SYSTEM_RUST_CALLBACKS, 'rust_callbacks'),
            (model, SYSTEM_RUST_GENERAL, 'rust_general'),
            # Also run some general prompts that apply to all languages
            (model, SYSTEM_PRECISION, 'precision'),
            (model, SYSTEM_STATE_CONSISTENCY, 'state_consistency'),
        ]

        # Vyper can use Solidity prompts with some adaptations (similar patterns)
        vyper_prompts = solidity_prompts

        all_vulns = []
        total_in = total_out = 0
        file_contents = {}

        # Count files by language for reporting
        lang_counts = {'solidity': 0, 'rust': 0, 'vyper': 0}
        for f in files_to_analyze:
            lang = detect_language(f)
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        console.print(f"[dim]Files by language: {lang_counts}[/dim]")

        # Calculate total tasks for progress reporting
        total_tasks = sum(
            len(rust_prompts) if detect_language(f) == 'rust' else len(solidity_prompts)
            for f in files_to_analyze
        )
        console.print(f"\n[cyan]Phase 1: Analysis ({len(files_to_analyze)} files, {total_tasks} total tasks)[/cyan]")

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}

            for file_path in files_to_analyze:
                rel_path = str(file_path.relative_to(source_dir))
                related = related_map.get(file_path, "")

                try:
                    with open(file_path, 'r') as f:
                        file_contents[rel_path] = f.read()
                except:
                    pass

                # Select prompts based on file language
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
                        source_dir, rel_path, related,
                        m, prompt, name
                    )
                    futures[future] = (rel_path, name)

            for future in as_completed(futures, timeout=15*60):
                try:
                    vulns, inp, out = future.result(timeout=180)
                    total_in += inp
                    total_out += out
                    all_vulns.extend(vulns)
                except Exception as e:
                    rel_path, name = futures[future]
                    console.print(f"[red]Task failed ({rel_path}/{name}): {e}[/red]")

        console.print(f"\n[cyan]Found {len(all_vulns)} raw findings[/cyan]")

        # Cross-prompt correlation: boost findings reported by multiple prompts
        all_vulns = self._boost_cross_prompt_findings(all_vulns)

        # Aggressive deduplication
        deduped = deduplicate_findings(all_vulns)
        console.print(f"[dim]After dedup: {len(deduped)} unique findings[/dim]")

        # Specificity-based verification
        console.print(f"\n[cyan]Phase 2: Verification (specificity filter)[/cyan]")
        verified = self.verify_findings(source_dir, deduped, file_contents, verify_model)

        # Apply quality gate (cap at 80 findings)
        console.print(f"\n[cyan]Phase 3: Quality Gate (max 80 findings)[/cyan]")
        verified = apply_quality_gate(verified, file_contents, max_findings=80)

        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        verified.sort(key=lambda v: (order.get(v.severity.value, 4), -v.confidence))

        console.print(f"\n[green]Final: {len(verified)} verified vulnerabilities[/green]")

        return AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=len(files_to_analyze),
            files_skipped=len(files) - len(files_to_analyze),
            total_vulnerabilities=len(verified),
            vulnerabilities=verified,
            token_usage={
                'input_tokens': total_in,
                'output_tokens': total_out,
                'total_tokens': total_in + total_out
            }
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
        "[bold cyan]Security Agent v11[/bold cyan]\n"
        "[dim]Multi-language (Solidity/Rust/Vyper) | 13 prompts | State mapping | Quality gate[/dim]",
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
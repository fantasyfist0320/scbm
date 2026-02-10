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
# PHASE 0: DESIGN INFERENCE + COT PREAMBLE
# Prepended to every user message to force structured reasoning
# =============================================================================

PHASE_0_PREAMBLE = """
============================================================
STEP 1 — UNDERSTAND THE DESIGN (do this FIRST, before looking for bugs)
============================================================

Reason about the protocol's design:

1. What assets/values are managed? How does value enter and exit the system?
2. What are the trust boundaries? (users vs admins vs keepers vs anyone)
3. What accounting invariants MUST hold? (e.g., totalDeposited >= totalWithdrawn)
4. Are resources created at predictable identifiers? (CREATE, CREATE2, clones, factory)
5. What external contracts/oracles does this depend on?
6. What paired operations exist? (deposit/withdraw, stake/unstake, lock/unlock, queue/confirm)

============================================================
STEP 2 — TRACE CALL CHAINS AND VALUE FLOWS
============================================================

For each external/public function:
1. What internal/external functions does it call?
2. What do those return? How is the return value USED? Is the UNIT correct?
3. For each value transfer: what goes IN, what goes OUT, does it balance?
4. What state variables change? Build a STATE CHANGE TABLE for the function.

============================================================
STEP 3 — FIND VULNERABILITIES
============================================================

Using your understanding from Steps 1-2, find bugs matching the system prompt patterns.
For each finding:
- Name the EXACT function(s) and call chain
- Describe the EXACT code behavior with specific state variable names
- Give CONCRETE exploit steps (e.g., "1. Call deposit(100), 2. Call transfer(victim, 50), 3. Call claim()")
- Explain WHY the invariant breaks with specific values

============================================================
OUTPUT FORMAT
============================================================

First write your ANALYSIS NOTES — trace value flows, call chains, state transitions,
and access control observations. Think step by step. This is your scratchpad.

Then output your findings as JSON:
{{"vulnerabilities": [...]}}
"""

# =============================================================================
# PROMPT 1: VALUE FLOW AND ACCOUNTING
# Distilled from: precision_analyzer, arithmetic_analyzer, defi_pattern_recognizer
# =============================================================================

SYSTEM_VALUE_FLOW = """
You are an expert smart contract security auditor focused on VALUE FLOW correctness.
Only report vulnerabilities that cause loss of funds, stolen value, or broken accounting.
Severity must be critical or high — skip informational/low findings.

============================================================
A. SETTLEMENT AND REFUND SAFETY
============================================================

For EACH function that takes value then returns/refunds:
1. What is the REQUESTED amount (parameter) vs ACTUAL amount consumed?
2. Is refund computed from REQUESTED or ACTUAL?
3. CRITICAL BUG PATTERN: take(actual_amount) then refund(requested - actual) = free money
   - This happens when the debit uses actual AND a refund of the difference is issued
   - Both corrections applied simultaneously = double benefit to user
4. Is there a path where tokens are transferred OUT without being transferred IN first?

For Rust/Stylus specifically:
- erc20::take(from, amount_in) takes the actual amount
- erc20::transfer_to_sender(original - amount_in) refunds the difference
- BUG if the original was never taken — refund is pure protocol loss
- Watch for checked_sub() / saturating_sub() masking arithmetic errors silently

============================================================
B. RETURN VALUE UNIT CONFUSION
============================================================

Trace return values through EVERY call chain:
- Does _deploy() return ASSETS deposited or SHARES received? Does the caller treat it correctly?
- Does _undeploy() return ASSETS withdrawn or SHARES burned? Does the caller treat it correctly?
- ERC4626: vault.deposit(assets) returns SHARES. vault.redeem(shares) returns ASSETS.
- If function A calls function B and uses B's return as "assets" but B returns "shares" = BUG

============================================================
C. PRECISION AND ROUNDING
============================================================

1. DIVISION BEFORE MULTIPLICATION: Look for patterns like (a / b) * c — should be (a * c) / b
2. PRO-RATED TRUNCATION TO ZERO: When accrued amount is small relative to totalShares,
   accrued.divDown(totalShares) can round to ZERO. The index never advances, but
   lastBalance still updates. Result: rewards permanently lost.
   - Pattern: rewardPerToken = totalRewards * PRECISION / totalSupply
   - If totalSupply >> totalRewards * PRECISION, rewardPerToken = 0
3. INDEX/BALANCE DESYNC: Global index advances only when division yields > 0.
   If it rounds to 0, index stays stale BUT balance tracking moves forward.
4. FEE ON WRONG BASE: Fee calculated on gross instead of net, or vice versa.

============================================================
D. MISSING SLIPPAGE AND DEADLINE PROTECTION
============================================================

For swaps, liquidity operations, withdrawals, and any value-changing operation:
- Is there a minAmountOut / amount0Min / amount1Min parameter? Is it enforced?
- Is there a deadline parameter? Can transactions be held in mempool and executed later at stale prices?
- Did an older version of this function have slippage protection that the new version removed?

IMPORTANT: Only report if you identify the EXACT functions, EXACT mismatch, and EXACT exploit path.

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 2: STATE INTEGRITY AND LIFECYCLE
# Distilled from: initialization_detector, defi_pattern_recognizer, state patterns
# =============================================================================

SYSTEM_STATE_LIFECYCLE = """
You are an expert smart contract security auditor focused on STATE INTEGRITY across operations.
Only report vulnerabilities with concrete impact — fund loss, permanent DoS, or broken invariants.
Severity must be critical or high.

============================================================
A. PAIRED OPERATION ASYMMETRY (CRITICAL)
============================================================

For each pair of forward/reverse operations (deposit/withdraw, stake/unstake, lock/unlock,
queue/cancel, open/close):

1. Build a STATE CHANGE TABLE for the FORWARD operation:
   List EVERY state variable modified: [varA, varB, varC, ...]

2. Build a STATE CHANGE TABLE for the REVERSE operation:
   List EVERY state variable modified: [varB, varC, ...]

3. COMPARE: If forward modifies [A, B, C] but reverse only restores [B, C],
   then variable A is LEAKED — it accumulates incorrectly across cycles.

4. Check: Can repeated forward+reverse cycles corrupt accounting?
   Example: deposit() increments totalDeposited and sets lastRate,
   but withdraw() only decrements totalDeposited — lastRate stays stale.

============================================================
B. STATE UPDATE OMISSIONS ON CANCEL/UNDO
============================================================

When an operation is cancelled or reversed:
- Are ALL intermediate state changes properly rolled back?
- If cancel() sends a refund via .transfer() or .call{}, does receive()/fallback()
  on the recipient auto-execute logic (like auto-staking)?
  - Pattern: receive() { stake(msg.value) } — a withdrawal refund triggers auto-stake,
    trapping the user's funds

============================================================
C. TEMPORAL ORDERING ATTACKS
============================================================

For multi-step operations (queue → wait → confirm):
1. What rate/price is locked at queue time?
2. Can an adverse event happen between queue and confirm?
   - Slashing/penalty between queue and confirm = user confirms at stale rate
   - Fee change between queue and confirm = user avoids new fee
3. Can an attacker front-run the confirm step?

============================================================
D. POSITION/ENTITLEMENT STATE ON TRANSFER
============================================================

When a position (NFT, vesting schedule, staking position) is transferred:
1. Is accumulated progress (e.g., stepsClaimed, rewardsAccrued) properly scoped to the position?
2. Or is it shared/inherited, allowing: mint → claim → transfer → claim again?
3. Can transfer reset a cooldown or lock period?

============================================================
E. INITIALIZATION VULNERABILITIES
============================================================

For initialize()/init() functions:
1. Is there access control? (Must have onlyOwner, initializer modifier, or equivalent)
2. Can it be front-run? (Public init without protection = attacker sets critical params)
3. In upgradeable contracts: is the `initializer` modifier from OpenZeppelin used?
4. Can init be called multiple times? (Reinitialization risk)

============================================================
F. BUFFER AND RESERVE TRACKING
============================================================

- Are withdrawal-pending funds separated from operational reserves?
- Can a buffer meant for pending withdrawals be used for new deposits or strategy execution?
- Does the system track "committed but not yet distributed" amounts separately?

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 3: ACCESS CONTROL AND AUTHORIZATION
# Distilled from: access_control_context_analyzer, delegation_analyzer
# =============================================================================

SYSTEM_ACCESS_CONTROL = """
You are an expert smart contract security auditor focused on ACCESS CONTROL and AUTHORIZATION.
Only report vulnerabilities where unrestricted access causes concrete harm — fund theft,
unauthorized state changes with economic impact, or privilege escalation.
Do NOT report: missing events, centralization risks, admin trust assumptions, or governance design choices.

============================================================
A. UNPROTECTED STATE-MODIFYING FUNCTIONS
============================================================

For each external/public function that modifies state:
1. What access control is present? (onlyOwner, onlyRole, require(msg.sender == X), etc.)
2. If NONE: What happens if ANYONE calls it?
3. CRITICAL PATTERNS — functions that MUST be restricted but aren't:
   - harvest(), compound(), rebalance(), sync() — front-run to steal rewards or manipulate rates
   - setFee(), setRate(), setOracle() — manipulate protocol parameters
   - pause(), unpause() — DoS or bypass safety checks
   - mint(), burn() with no caller validation
   - execute(), multicall() with arbitrary calldata

============================================================
B. CONDITIONAL RECIPIENT SELECTION
============================================================

In functions that send funds:
1. WHO receives the funds? Is the recipient derived from msg.sender or from a parameter?
2. Can an attacker control the recipient address?
3. Pattern: transferFrom(from, to, amount) where `from` is a parameter — attacker can
   specify any address as `from` if there's no allowance check
4. Pattern: function claims rewards "on behalf of" user but sends to msg.sender

============================================================
C. SIGNATURE AND PERMIT VERIFICATION
============================================================

For signature-based operations (EIP-712, permit, meta-transactions):
1. Is the signature bound to the correct parameters? (amount, recipient, nonce, deadline)
2. Can an attacker front-run with different execution parameters using the same signature?
3. Is replay protection implemented? (Nonce increment, deadline check)
4. Is the recovered signer checked against the expected authorizer?

============================================================
D. PROXY AND DELEGATION PATTERNS
============================================================

For upgradeable/proxy contracts:
1. Are implementation functions protected? (onlyProxy, onlyDelegateCall)
2. Can the implementation be initialized directly? (Bypassing proxy access control)
3. In diamond/facet patterns: can selectors be overwritten to point to malicious facets?
4. delegatecall to user-controlled address = arbitrary code execution

============================================================
E. AUTHORIZATION BYPASS THROUGH CALLBACK
============================================================

If a function calls an external contract that calls back:
1. Does the callback re-enter with elevated privileges?
2. Can the callback path skip validation that the direct path enforces?
3. Pattern: Token with transfer hooks (ERC777, ERC1155) — transfer triggers callback
   before state is finalized

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 4: EXTERNAL INTERACTIONS AND ORDERING
# Distilled from: reentrancy_guard_detector, mev_detector, cross_protocol_patterns
# =============================================================================

SYSTEM_EXTERNAL_INTERACTIONS = """
You are an expert smart contract security auditor focused on EXTERNAL INTERACTIONS,
REENTRANCY, and TRANSACTION ORDERING vulnerabilities.
Only report vulnerabilities with concrete exploit paths. Severity must be critical or high.

============================================================
A. CHECKS-EFFECTS-INTERACTIONS VIOLATIONS
============================================================

For each function with external calls (.call, .transfer, .send, delegatecall, safeTransfer,
token transfers, oracle reads):
1. Are state changes made BEFORE or AFTER the external call?
2. If state changes AFTER: Can the external call re-enter and exploit stale state?
3. Is there a reentrancy guard (nonReentrant modifier)?
4. Cross-function reentrancy: Function A calls external, re-enters through function B
   which reads stale state that A hasn't updated yet.

============================================================
B. GAS GRIEFING VIA 63/64 RULE
============================================================

Pattern:
1. Function consumes state (marks as claimed, decrements balance) BEFORE external call
2. External call is made with forwarded gas
3. The call path has a non-reverting fallback (try/catch, low-level call with bool check)
4. ATTACK: Provide just enough gas for state consumption but not enough for the external
   call to succeed. State is consumed, external call fails silently, attacker profits.

Check: Is state consumed (irreversibly updated) before an external call that can fail without reverting the whole transaction?

============================================================
C. PREDICTABLE IDENTIFIER FRONT-RUNNING
============================================================

For CREATE, CREATE2, Clones.clone(), factory patterns:
1. Is the deployed address deterministic/predictable?
2. Can an attacker pre-deploy a contract at the predicted address?
3. Pattern: Protocol uses CREATE2 with known salt — attacker deploys malicious contract
   at that address first, causing permanent DoS or hijacking.
4. Pool/pair creation: Can attacker front-run createPair() to create a malicious pool?

============================================================
D. FRONT-RUNNING ECONOMIC OPERATIONS
============================================================

For functions that change rates, fees, or exchange ratios:
1. Can an attacker see a pending rate change and front-run to profit?
   - Deposit before rate increase, withdraw after
   - Harvest rewards before fee increase takes effect
   - Liquidate before oracle price update
2. Sandwich attacks: Does any function read and act on a spot price that can be
   manipulated in the same block?

============================================================
E. SILENT FAILURE HANDLING
============================================================

1. Low-level calls: .call() returns (bool success, bytes data) — is `success` checked?
2. try/catch: What happens in the catch block? Is state properly rolled back?
3. Non-reverting patterns: If a transfer fails silently, does the function continue
   as if it succeeded? (State committed before success verification)
4. Return value not checked: ERC20.transfer() returns bool — is it checked or ignored?
   (Use SafeERC20 or check return value)

============================================================
F. CROSS-CONTRACT STATE ASSUMPTIONS
============================================================

When contract A calls contract B:
1. Does A assume B's state is consistent? Can B's state change between A's calls?
2. Does A cache a value from B and use it later? Can B's value change in between?
3. Pattern: Read oracle price, do computation, read oracle price again — different values
4. Pattern: Check balance, do operation, assume balance changed by exact amount
   (ignores fee-on-transfer tokens, rebasing tokens)

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# PROMPT 5: ECONOMIC AND PROTOCOL LOGIC
# Distilled from: defi_vulnerability_detector, oracle_manipulation_detector,
#                 cross_protocol_pattern_recognizer
# =============================================================================

SYSTEM_ECONOMIC_LOGIC = """
You are an expert smart contract security auditor focused on ECONOMIC LOGIC and
PROTOCOL-LEVEL vulnerabilities in DeFi systems.
Only report vulnerabilities with concrete economic impact. Severity must be critical or high.

============================================================
A. REWARD AND YIELD DISTRIBUTION
============================================================

1. FAIRNESS: Can a user deposit right before reward distribution and claim a disproportionate share?
   - Is there a minimum lock period or deposit delay?
   - Are rewards pro-rated by time, or just by balance at snapshot?
2. REWARD DEBT: When a user's balance changes, is their reward debt properly updated?
   - Pattern: rewardDebt = user.amount * accRewardPerShare — must update on every balance change
3. ROUNDING EXPLOITATION: Can dust amounts be used to extract value over many transactions?
4. CLAIM AFTER EXIT: Can a user withdraw all stake and still claim pending rewards?

============================================================
B. EXCHANGE RATE AND SHARE MANIPULATION
============================================================

1. FIRST DEPOSITOR ATTACK: In vault/pool with shares:
   - Can first depositor inflate the share price by donating tokens directly?
   - Pattern: deposit 1 wei → donate 1M tokens → next depositor gets 0 shares
   - Is there a minimum deposit or virtual offset to prevent this?
2. DONATION ATTACK: Can anyone send tokens directly to the contract to manipulate
   the exchange rate (totalAssets / totalShares)?
3. SHARE CALCULATION: Are shares calculated with proper rounding direction?
   - Deposits should round DOWN (protocol keeps rounding dust)
   - Withdrawals should round UP (protocol keeps rounding dust)
   - Reversed rounding = users can extract more than deposited

============================================================
C. LIQUIDATION AND BAD DEBT
============================================================

1. Does the liquidation bonus exceed the shortfall? (Liquidator profit > bad debt covered)
2. Can bad debt be repeatedly socialized? (Written off, then accrued again)
3. Is there a path where seized collateral value < debt being repaid? (Protocol takes loss)
4. Can a user self-liquidate for profit? (Borrow → manipulate → liquidate own position)
5. Are all debt components (principal + interest + fees) accounted in liquidation?

============================================================
D. ORACLE AND PRICE FEED SAFETY
============================================================

1. STALENESS: Is there a maximum age check on oracle prices?
2. MANIPULATION: Does the contract use spot price (manipulable) or TWAP (resistant)?
3. DECIMAL MISMATCH: Oracle returns price with X decimals, contract assumes Y decimals
4. SEQUENCER CHECK: On L2s, is the sequencer uptime checked before using oracle data?
5. FALLBACK: If primary oracle fails, is there a fallback? Can the fallback be manipulated?

============================================================
E. ECONOMIC INVARIANT VIOLATIONS
============================================================

For the protocol's key invariants, verify they hold across ALL code paths:
- totalSupply == sum of all balances
- totalAssets >= totalLiabilities (solvency)
- totalClaimed <= totalVested (vesting)
- sum of user shares == totalShares
- buffer + delegated == totalStaked (staking)

Check: Can ANY sequence of valid transactions break these invariants?
Focus on edge cases: zero amounts, maximum values, empty pools, single-user scenarios.

============================================================
F. MULTI-STEP ECONOMIC EXPLOITS
============================================================

Consider attack sequences that span multiple transactions:
1. Flash loan → manipulate price → liquidate → repay flash loan
2. Deposit → manipulate exchange rate → withdraw at inflated rate
3. Borrow → transfer collateral → default without consequence
4. Stake → immediately unstake → claim rewards earned during 0-time stake

Return ONLY valid JSON:
{{"vulnerabilities": [...]}}

{format_instructions}
"""

# =============================================================================
# RUST/STYLUS BROAD PROMPT (applied instead of individual prompts for .rs files)
# =============================================================================

SYSTEM_RUST_BROAD = """
You are an expert smart contract security auditor for Rust/Stylus smart contracts.
Only report vulnerabilities with concrete impact — fund loss, broken invariants, or DoS.

============================================================
RUST-SPECIFIC PATTERNS TO CHECK
============================================================

A. VALUE FLOW (same as Solidity, but watch for):
   - erc20::take(from, amount) — takes actual amount from sender
   - erc20::transfer_to_sender(amount) — sends amount to caller
   - BUG: transfer_to_sender(original - actual) when original was never taken = free money
   - checked_sub() / saturating_sub() can SILENTLY mask underflow to 0
   - ? operator early returns: Does the function clean up state on early return?

B. STATE MANAGEMENT:
   - self.field.set(value) vs self.field.get() — ordering matters
   - StorageMap/StorageVec .get() returns default (0) for missing keys — not an error
   - Clone() on storage types can create divergent state copies
   - sol_storage! macro: Are all fields properly initialized?

C. ACCESS CONTROL:
   - msg::sender() checks — are they present on all state-modifying pub fns?
   - #[payable] attribute — is msg::value() properly handled?
   - RawCall: return values from raw calls — are they checked?

D. CONTROL FLOW:
   - unwrap() / expect() can panic = DoS if attacker controls input
   - ok() / unwrap_or_default() can silently swallow errors
   - ? operator + early return: Does state remain consistent if function exits early?

E. PAIRED OPERATIONS: Same as Solidity — check forward/reverse state change tables
F. ECONOMIC LOGIC: Same as Solidity — check reward distribution, exchange rates, invariants

{format_instructions}
"""

# =============================================================================
# VERIFICATION PROMPT
# =============================================================================

SYSTEM_VERIFY = """
You are a smart contract security SKEPTIC. Your job is to DISPROVE findings.
Play devil's advocate: try to find reasons each finding is WRONG.

For each finding, attempt to construct a COUNTERARGUMENT:

1. CODE GROUNDING: Does the described function/pattern actually exist? Check exact names.
2. EXISTING PROTECTION: Is there already a guard, modifier, or check that prevents this?
   - Look for require(), assert(), modifier, SafeMath, nonReentrant that the finding missed.
   - Look for Solidity 0.8+ automatic overflow protection (unless unchecked block).
3. MECHANISM TRACE: Trace the attack step by step through actual code. Does EACH step work?
   - Does the function actually modify the claimed state variable?
   - Is the claimed call sequence actually possible given access control?
4. IMPACT REALITY: Even if the mechanism works, is impact real?
   - Is the affected amount dust (< $1)?
   - Does the protocol have a recovery mechanism?
   - Is the attacker cost higher than profit?

If you CANNOT construct a valid counterargument → CONFIRMED (the bug is real).
If your counterargument is partial → UNCERTAIN (might be real).
If your counterargument fully disproves the finding → REJECTED.

IMPORTANT: Centralization risks, missing events, gas optimizations, admin trust assumptions,
and Solidity 0.8+ overflow without unchecked are ALWAYS REJECTED.

Return JSON:
{{
    "verifications": [
        {{
            "index": 0,
            "verdict": "CONFIRMED",
            "counterargument": "I tried to disprove this by checking for X but found no protection",
            "reasoning": "Brief explanation of why the bug is real despite my skepticism",
            "adjusted_severity": "critical",
            "adjusted_confidence": 0.85
        }}
    ]
}}
"""

# =============================================================================
# ACCESS CONTROL SCAN PROMPT (for targeted scan of unprotected functions)
# =============================================================================

SYSTEM_ACCESS_SCAN = """
You are a smart contract access control specialist. Analyze functions that lack access
control modifiers and determine if unrestricted access poses a security risk.

Focus on ECONOMIC IMPACT:
- Can anyone call this to steal/redirect funds?
- Can anyone call this to manipulate rates, prices, or accounting?
- Can anyone call this to grief other users (DoS, front-run rewards)?

Do NOT flag: view/pure functions, standard ERC20/ERC721 functions (transfer, approve),
functions where public access is by design (deposit, withdraw with proper accounting).

{format_instructions}
"""

# =============================================================================
# FILE RANKING PROMPT
# =============================================================================

SYSTEM_FILE_RANKER = """
You are a smart contract security auditor prioritizing files for audit.

Given a list of smart contract files with summaries, rank them by SECURITY AUDIT PRIORITY.

Highest priority:
- Files that handle value transfers (deposits, withdrawals, swaps, liquidations)
- Files with complex state transitions (staking, vesting, multi-step operations)
- Files that interact with external contracts (oracles, other protocols, bridges)
- Files with access control logic (role management, permissions)

Lower priority:
- Pure utility/math libraries
- Interface definitions
- Simple storage/getter contracts
- Event-only contracts

Return a JSON array of filenames in order of priority (highest first):
{{"ranked_files": ["file1.sol", "file2.sol", ...]}}
"""

# =============================================================================
# PRE-FILTER PATTERNS (known false positives)
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
# DATA MODELS
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
    name = file_path.name
    if name.startswith('I') and len(name) > 1 and name[1].isupper() and file_path.suffix == '.sol':
        return True
    if content and 'interface ' in content and 'function ' in content:
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
    suspects = []

    if language == 'solidity':
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s+((?:(?:external|public|internal|private|view|pure|payable|virtual|override|nonReentrant|onlyOwner|onlyRole\([^)]*\)|onlyAdmin|onlyOperator|onlyKeeper|onlyVault|onlyStrategy|auth|restricted|returns\s*\([^)]*\))\s*)*)\{'
        for name, params, modifiers in re.findall(func_pattern, content):
            if 'external' not in modifiers and 'public' not in modifiers:
                continue
            if 'view' in modifiers or 'pure' in modifiers:
                continue
            access_keywords = ['onlyOwner', 'onlyRole', 'onlyAdmin', 'onlyOperator',
                             'onlyKeeper', 'onlyVault', 'onlyStrategy', 'auth', 'restricted',
                             'onlyGovernance', 'onlyGuardian', 'onlyManager', 'requiresAuth']
            has_access = any(kw in modifiers for kw in access_keywords)
            if not has_access:
                suspects.append({
                    'name': name,
                    'visibility': 'external' if 'external' in modifiers else 'public',
                    'params': params.strip()[:80],
                })

    elif language == 'rust':
        func_pattern = r'pub\s+fn\s+(\w+)\s*\(([^)]*)\)'
        for name, params in re.findall(func_pattern, content):
            func_body_match = re.search(
                rf'pub\s+fn\s+{name}\s*\([^)]*\)[^{{]*\{{((?:[^{{}}]|\{{(?:[^{{}}]|\{{[^{{}}]*\}})*\}})*)\}}',
                content, re.DOTALL
            )
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


# =============================================================================
# CONTEXT EXTRACTORS
# =============================================================================

def extract_state_mapping(content: str, language: str) -> str:
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
    lines = content.split('\n')

    if language == 'solidity':
        pattern = f'function {func_name}'
    elif language == 'rust':
        pattern = f'fn {func_name}'
    else:
        pattern = f'def {func_name}'

    for i, line in enumerate(lines):
        if pattern in line:
            start = max(0, i - context_lines)
            depth = 0
            end = i
            for j in range(i, len(lines)):
                depth += lines[j].count('{') - lines[j].count('}')
                if language == 'vyper':
                    if j > i and lines[j].strip() and not lines[j].startswith(' ') and not lines[j].startswith('\t'):
                        end = j
                        break
                elif depth <= 0 and j > i:
                    end = j + 1
                    break
            end = min(end + context_lines, len(lines))
            return '\n'.join(f"{n+1:4d}: {l}" for n, l in enumerate(lines[start:end], start))

    return ""


# =============================================================================
# SOLUTION #1 & #2: PAIRED-OPERATION STATE DIFF
# Programmatically finds forward/reverse pairs and diffs their state changes.
# Turns "reasoning about absence" into "reasoning about presence" for the LLM.
# =============================================================================

def _extract_function_state_writes(content: str, language: str) -> Dict[str, set]:
    """Extract which state variables each function modifies. Returns {func_name: {var1, var2, ...}}."""
    result = {}

    if language == 'solidity':
        # Collect ALL state variable names (simple types AND mappings/arrays)
        state_vars = set()
        # Simple state vars: uint256 public foo;
        for _, name in re.findall(
            r'^\s*(?:mapping\s*\([^)]+\)|uint\d*|int\d*|bool|address|bytes\d*|string|address\s+payable)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*([;=])',
            content, re.MULTILINE
        ):
            pass
        for match in re.findall(
            r'^\s*(?:mapping\s*\([^)]+\)|uint\d*|int\d*|bool|address|bytes\d*|string)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*[;=]',
            content, re.MULTILINE
        ):
            state_vars.add(match)
        # Also catch mapping declarations separately (they're common state vars)
        for match in re.findall(r'^\s*mapping\s*\([^)]+\)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;', content, re.MULTILINE):
            state_vars.add(match)

        func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
        for func_name, func_body in re.findall(func_pattern, content, re.DOTALL):
            writes = set()
            for var in state_vars:
                # Direct assignment: var = x, var += x, var -= x
                if re.search(rf'\b{re.escape(var)}\b\s*[\+\-\*\/]?=(?!=)', func_body):
                    writes.add(var)
                # Mapping/array write: var[key] = x, var[key][key2] = x
                if re.search(rf'\b{re.escape(var)}\b\s*\[', func_body) and re.search(rf'\b{re.escape(var)}\b\s*\[[^\]]*\]\s*[\+\-\*\/]?=(?!=)', func_body):
                    writes.add(var)
                # Delete
                if re.search(rf'delete\s+{re.escape(var)}', func_body):
                    writes.add(var)
            if writes:
                result[func_name] = writes

    elif language == 'rust':
        field_vars = set(re.findall(r'self\.(\w+)\s*(?:\.|\.get|\.set|\.insert|\.remove|\+=|-=|=)', content))
        func_pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
        for func_name, func_body in re.findall(func_pattern, content, re.DOTALL):
            writes = set()
            for var in field_vars:
                if re.search(rf'self\.{re.escape(var)}\s*(?:\.|\.set|\.insert|\+=|-=|=(?!=))', func_body):
                    writes.add(var)
            if writes:
                result[func_name] = writes

    return result


# Canonical pairs: (forward_keywords, reverse_keywords)
_PAIRED_OP_PATTERNS = [
    (['deposit', 'stake', 'lock', 'open', 'queue', 'subscribe', 'enter', 'mint'],
     ['withdraw', 'unstake', 'unlock', 'close', 'cancel', 'unsubscribe', 'exit', 'burn', 'redeem']),
    (['borrow', 'lend'],
     ['repay', 'liquidate']),
    (['add', 'increase', 'create'],
     ['remove', 'decrease', 'delete']),
]


def extract_paired_operation_diffs(content: str, language: str) -> str:
    """Find forward/reverse operation pairs and diff their state modifications.

    Returns a structured text like:
      PAIRED OPERATION DIFF:
        deposit() modifies: [totalDeposited, lastRate, balances]
        withdraw() modifies: [totalDeposited, balances]
        >>> ASYMMETRY: deposit() modifies [lastRate] which withdraw() does NOT restore
    """
    func_writes = _extract_function_state_writes(content, language)
    if not func_writes:
        return ""

    func_names = set(func_writes.keys())
    lines = ["PAIRED OPERATION STATE DIFF:"]
    found_pairs = set()

    for forward_kws, reverse_kws in _PAIRED_OP_PATTERNS:
        for fname in func_names:
            fname_lower = fname.lower()
            # Check if this function matches a forward keyword
            matched_forward_kw = None
            for kw in forward_kws:
                if kw in fname_lower:
                    matched_forward_kw = kw
                    break
            if not matched_forward_kw:
                continue

            # Find corresponding reverse function
            for rname in func_names:
                rname_lower = rname.lower()
                for rkw in reverse_kws:
                    if rkw in rname_lower:
                        pair_key = tuple(sorted([fname, rname]))
                        if pair_key in found_pairs:
                            continue
                        found_pairs.add(pair_key)

                        fw = func_writes.get(fname, set())
                        rv = func_writes.get(rname, set())

                        forward_only = fw - rv
                        reverse_only = rv - fw

                        lines.append(f"  {fname}() modifies: [{', '.join(sorted(fw))}]")
                        lines.append(f"  {rname}() modifies: [{', '.join(sorted(rv))}]")

                        if forward_only:
                            lines.append(f"  >>> ASYMMETRY: {fname}() modifies [{', '.join(sorted(forward_only))}] which {rname}() does NOT restore")
                        if reverse_only:
                            lines.append(f"  >>> ASYMMETRY: {rname}() modifies [{', '.join(sorted(reverse_only))}] which {fname}() does NOT set")
                        if not forward_only and not reverse_only:
                            lines.append(f"  (symmetric — both modify same variables)")
                        lines.append("")

    return '\n'.join(lines) if len(lines) > 1 else ""


# =============================================================================
# SOLUTION #3: ARITHMETIC PRE-ANALYSIS
# Extracts all division/multiplication operations, identifies operand types,
# and flags truncation-to-zero and precision-loss risks.
# =============================================================================

def extract_arithmetic_annotations(content: str, language: str) -> str:
    """Analyze division operations for truncation risks.

    Returns structured annotations like:
      ARITHMETIC ANALYSIS:
        Line 142: reward * PRECISION / totalSupply
          - Division may truncate to 0 if totalSupply >> reward * PRECISION
          - Operands: reward (uint256), PRECISION (constant 1e18), totalSupply (uint256)
        Line 208: amount / shares * price
          - DIVISION BEFORE MULTIPLICATION — precision loss
    """
    if language not in ('solidity', 'rust'):
        return ""

    lines_list = content.split('\n')
    annotations = ["ARITHMETIC RISK ANALYSIS:"]

    # Known precision constants
    precision_constants = {
        '1e18', '1e27', '1e6', '1e8', '1e12', '1e36',
        '1000000000000000000', '1000000', '100000000',
        'WAD', 'RAY', 'PRECISION', 'SCALE', 'MULTIPLIER', 'BASE',
        'DECIMAL_FACTOR', 'PRICE_PRECISION', 'RATE_PRECISION',
    }

    # Skip if using safe math libraries
    safe_libs = ['SafeMath', 'FixedPoint', 'PRBMath', 'ABDKMath', 'Math.mulDiv', 'FullMath']
    for lib in safe_libs:
        if lib in content:
            annotations.append(f"  Note: Uses {lib} library (some operations may be safe)")
            break

    # Check for unchecked blocks
    unchecked_ranges = []
    depth = 0
    in_unchecked = False
    uc_start = 0
    for i, line in enumerate(lines_list):
        if 'unchecked' in line and '{' in line:
            in_unchecked = True
            uc_start = i
            depth = 0
        if in_unchecked:
            depth += line.count('{') - line.count('}')
            if depth <= 0:
                unchecked_ranges.append((uc_start, i))
                in_unchecked = False

    def is_in_unchecked(line_num: int) -> bool:
        return any(s <= line_num <= e for s, e in unchecked_ranges)

    found_risks = []

    for i, line in enumerate(lines_list):
        stripped = line.strip()

        # Skip comments and empty lines
        if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*') or not stripped:
            continue

        # Pattern 1: Division before multiplication — (a / b) * c
        div_before_mul = re.findall(r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)', stripped)
        for a, b, c in div_before_mul:
            # Skip if divisor is a precision constant (deliberate scaling)
            if b in precision_constants or b.upper() in precision_constants:
                continue
            found_risks.append(
                f"  Line {i+1}: {a} / {b} * {c}\n"
                f"    DIVISION BEFORE MULTIPLICATION — should be ({a} * {c}) / {b} to preserve precision"
            )

        # Pattern 2: Pro-rated division that can truncate to zero
        # e.g., reward * factor / totalSupply, amount * elapsed / duration
        prorated = re.findall(r'(\w+)\s*\*\s*(\w+)\s*/\s*(\w+)', stripped)
        for a, b, c in prorated:
            # If divisor looks like a total/supply/duration (large denominator)
            c_lower = c.lower()
            large_denom_hints = ['total', 'supply', 'duration', 'period', 'shares', 'balance', 'weight']
            if any(hint in c_lower for hint in large_denom_hints):
                found_risks.append(
                    f"  Line {i+1}: {a} * {b} / {c}\n"
                    f"    TRUNCATION RISK: If {c} >> {a} * {b}, result truncates to 0\n"
                    f"    Example: if {a}=100, {b}=1e18, {c}=200_000_000e18, result = 0"
                )

        # Pattern 3: Standalone division with small numerator risk
        simple_div = re.findall(r'(\w+)\s*/\s*(\w+)', stripped)
        for a, b in simple_div:
            if a == b:
                continue
            # Check if this is inside a known safe pattern
            b_lower = b.lower()
            a_lower = a.lower()
            if b_lower in [x.lower() for x in precision_constants]:
                continue
            # Flag if numerator looks like per-user amount and denominator looks like total
            if any(h in a_lower for h in ['reward', 'fee', 'interest', 'accrued', 'earned', 'pending']):
                if any(h in b_lower for h in ['total', 'supply', 'shares', 'weight']):
                    found_risks.append(
                        f"  Line {i+1}: {a} / {b}\n"
                        f"    ZERO DIVISION RESULT: Small per-user {a} divided by large {b} → 0\n"
                        f"    Check: Is this inside an accumulator update? If result=0, index never advances"
                    )

        # Pattern 4: Unchecked arithmetic with value operations
        if is_in_unchecked(i):
            if re.search(r'[\+\-\*]', stripped) and not stripped.startswith('//'):
                has_value_context = any(kw in stripped.lower() for kw in
                    ['balance', 'amount', 'value', 'total', 'supply', 'shares', 'debt', 'reward'])
                if has_value_context:
                    found_risks.append(
                        f"  Line {i+1}: UNCHECKED arithmetic with value-related variable\n"
                        f"    Code: {stripped[:100]}\n"
                        f"    Overflow/underflow possible in Solidity 0.8+ unchecked block"
                    )

    # Cap at 15 most important
    for risk in found_risks[:15]:
        annotations.append(risk)

    return '\n'.join(annotations) if len(annotations) > 1 else ""


# =============================================================================
# SOLUTION #1 (continued): MULTI-STEP SCENARIO GENERATOR
# Builds concrete 2-3 step attack traces from call graph + state mapping.
# =============================================================================

def generate_attack_scenarios(content: str, language: str) -> str:
    """Generate multi-step attack scenario traces from the contract's functions.

    Identifies sequences of calls that could violate invariants:
    - deposit → transfer → claim (entitlement leak)
    - stake → earn → unstake without updating rewards
    - queue → (adverse event) → confirm at stale rate
    """
    func_writes = _extract_function_state_writes(content, language)
    if not func_writes:
        return ""

    # Classify functions by role
    value_in = []     # Functions that bring value in
    value_out = []    # Functions that send value out
    state_transfer = []  # Functions that transfer state between users
    rate_changers = []   # Functions that change rates/prices

    for fname, writes in func_writes.items():
        fl = fname.lower()
        writes_lower = {w.lower() for w in writes}

        if any(kw in fl for kw in ['deposit', 'stake', 'mint', 'subscribe', 'enter', 'lock', 'borrow']):
            value_in.append(fname)
        if any(kw in fl for kw in ['withdraw', 'unstake', 'burn', 'redeem', 'exit', 'unlock', 'claim', 'repay']):
            value_out.append(fname)
        if any(kw in fl for kw in ['transfer', 'move', 'assign', 'delegate', 'migrate']):
            state_transfer.append(fname)
        if any(kw in wl for kw in ['rate', 'price', 'index', 'factor', 'ratio', 'exchange'] for wl in writes_lower):
            rate_changers.append(fname)

    scenarios = ["ATTACK SCENARIO TRACES:"]

    # Scenario type 1: deposit → transfer → claim (entitlement leak)
    for vin in value_in:
        for xfer in state_transfer:
            for vout in value_out:
                vin_writes = func_writes.get(vin, set())
                xfer_writes = func_writes.get(xfer, set())
                vout_reads_or_writes = func_writes.get(vout, set())

                # Find state that deposit sets but transfer might not properly scope
                shared = vin_writes & vout_reads_or_writes
                if shared and xfer_writes:
                    scenarios.append(
                        f"  SCENARIO: {vin}() -> {xfer}() -> {vout}()\n"
                        f"    {vin}() sets: [{', '.join(sorted(shared))}]\n"
                        f"    {xfer}() modifies: [{', '.join(sorted(xfer_writes))}]\n"
                        f"    {vout}() uses: [{', '.join(sorted(shared))}]\n"
                        f"    QUESTION: After {xfer}(), does the NEW owner inherit accumulated state from {vin}()?\n"
                        f"    Can attacker: {vin}(100) -> {vout}() -> {xfer}(new_addr) -> {vout}() again?"
                    )

    # Scenario type 2: rate change between queue and confirm
    for rc in rate_changers:
        for vin in value_in:
            for vout in value_out:
                rc_writes = func_writes.get(rc, set())
                vout_writes = func_writes.get(vout, set())
                # If rate changer modifies variables that withdrawal uses
                rate_vars = rc_writes & vout_writes
                if rate_vars:
                    scenarios.append(
                        f"  SCENARIO: {vin}() -> [adverse: {rc}()] -> {vout}()\n"
                        f"    {vin}() locks user into position\n"
                        f"    {rc}() changes: [{', '.join(sorted(rate_vars))}]\n"
                        f"    {vout}() reads stale values from when {vin}() was called?\n"
                        f"    QUESTION: Does {vout}() use the rate from {vin}()-time or current rate?"
                    )

    # Scenario type 3: value_in → value_out without full state cleanup
    for vin in value_in:
        for vout in value_out:
            vin_w = func_writes.get(vin, set())
            vout_w = func_writes.get(vout, set())
            leaked = vin_w - vout_w
            if leaked:
                scenarios.append(
                    f"  SCENARIO: {vin}() -> {vout}() cycle\n"
                    f"    {vin}() sets but {vout}() doesn't clear: [{', '.join(sorted(leaked))}]\n"
                    f"    QUESTION: After repeated {vin}() -> {vout}() cycles, do leaked vars accumulate incorrectly?"
                )

    # Cap scenarios
    if len(scenarios) > 12:
        scenarios = scenarios[:12]
        scenarios.append("  ... (additional scenarios truncated)")

    return '\n'.join(scenarios) if len(scenarios) > 1 else ""


# =============================================================================
# SOLUTION #4: ENHANCED CROSS-CONTRACT RESOLUTION
# Finds related files via shared type references, external call targets,
# and interface usage — not just direct imports.
# =============================================================================

def find_cross_contract_references(content: str, all_files: Dict[str, str], current_file: str) -> List[str]:
    """Find files related by shared type references, external call targets, and events.

    Goes beyond import-based resolution to catch indirect interactions.
    """
    related = set()

    # 1. Extract external call targets: token.transfer(), vault.deposit(), etc.
    ext_call_targets = set()
    for match in re.findall(r'(\w+)\s*\.\s*(\w+)\s*\(', content):
        obj, method = match
        if obj.lower() not in ('msg', 'block', 'abi', 'tx', 'type', 'super', 'this', 'self'):
            ext_call_targets.add(method)

    # 2. Extract type references: IERC20(token), IVault(vault), etc.
    type_refs = set(re.findall(r'([A-Z]\w+)\s*\(', content))
    type_refs -= {'require', 'assert', 'revert', 'emit', 'Severity', 'Error'}

    # 3. Extract interface names used in state variables
    interface_vars = set(re.findall(r'(I[A-Z]\w+)\s+(?:public\s+|private\s+|internal\s+)?(\w+)', content))
    for iface, _ in interface_vars:
        type_refs.add(iface)

    # 4. Extract event names
    events = set(re.findall(r'event\s+(\w+)', content))

    # 5. Match against all other files
    for other_file, other_content in all_files.items():
        if other_file == current_file:
            continue

        score = 0

        # Check if other file defines a type/interface that current file uses
        for tref in type_refs:
            # Strip leading 'I' for interface matching
            base_name = tref[1:] if tref.startswith('I') and len(tref) > 1 and tref[1].isupper() else tref
            if re.search(rf'(?:contract|interface|library)\s+{re.escape(tref)}\b', other_content):
                score += 3
            elif re.search(rf'(?:contract|interface|library)\s+{re.escape(base_name)}\b', other_content):
                score += 2

        # Check if other file implements functions that current file calls externally
        for method in ext_call_targets:
            if re.search(rf'function\s+{re.escape(method)}\s*\(', other_content):
                score += 1

        # Check if other file emits events that current file defines (or vice versa)
        for event in events:
            if re.search(rf'emit\s+{re.escape(event)}\s*\(', other_content):
                score += 1

        if score >= 2:
            related.add((other_file, score))

    # Return top related files by score
    sorted_related = sorted(related, key=lambda x: -x[1])
    return [f for f, _ in sorted_related[:6]]


# =============================================================================
# DEDUPLICATION AND QUALITY GATE
# =============================================================================

def deduplicate_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
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

    # Cluster by root cause, keep max 2 per cluster
    stopwords = {'function', 'if', 'for', 'while', 'require', 'revert', 'emit', 'return', 'memory', 'storage'}
    clusters: dict[tuple, List[Vulnerability]] = {}
    for v in deduped:
        funcs = re.findall(r'(\w+)\s*\(', f"{v.title} {v.description[:300]}")
        funcs = [f for f in funcs if f.lower() not in stopwords and len(f) > 2]
        primary = funcs[0] if funcs else "unknown"

        desc = v.description.lower()
        if any(x in desc for x in ['refund', 'value mismatch', 'amount taken', 'precision', 'rounding']):
            cat = 'value'
        elif any(x in desc for x in ['cancel', 'not reversed', 'not restored', 'state', 'lifecycle']):
            cat = 'state'
        elif any(x in desc for x in ['gas', '63/64', 'griefing']):
            cat = 'gas'
        elif any(x in desc for x in ['access', 'anyone', 'permissionless', 'no.*modifier']):
            cat = 'access'
        elif any(x in desc for x in ['front-run', 'predictable', 'create.*pair', 'sandwich']):
            cat = 'frontrun'
        elif any(x in desc for x in ['receive', 'fallback', 'auto-stak']):
            cat = 'receive'
        elif any(x in desc for x in ['reward', 'incentive', 'oracle', 'exchange rate', 'share']):
            cat = 'economic'
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
# FILE HEURISTIC SCORER (for pre-LLM ranking)
# =============================================================================

def compute_file_heuristic(content: str, language: str) -> dict:
    """Compute heuristic metrics for file ranking."""
    metrics = {
        'size': len(content),
        'external_fns': 0,
        'value_ops': 0,
        'financial_keywords': 0,
        'external_calls': 0,
    }

    if language == 'solidity':
        metrics['external_fns'] = len(re.findall(r'function\s+\w+[^;]*(?:external|public)[^;]*\{', content))
        value_patterns = [r'\.transfer\(', r'\.call\{value', r'transferFrom\(', r'\.safeTransfer\(',
                         r'\.safeTransferFrom\(', r'mint\(', r'burn\(', r'\.deposit\(', r'\.withdraw\(']
    elif language == 'rust':
        metrics['external_fns'] = len(re.findall(r'pub\s+fn\s+\w+', content))
        value_patterns = [r'erc20::take', r'erc20::transfer', r'transfer_to_sender',
                         r'msg_value', r'raw_call.*value']
    else:
        value_patterns = []

    for p in value_patterns:
        metrics['value_ops'] += len(re.findall(p, content))

    financial_keywords = ['balance', 'reward', 'stake', 'deposit', 'withdraw', 'liquidat',
                         'swap', 'vault', 'collateral', 'debt', 'oracle', 'price', 'fee',
                         'slash', 'penalty', 'claim', 'vest', 'unlock', 'borrow', 'repay']
    content_lower = content.lower()
    for kw in financial_keywords:
        metrics['financial_keywords'] += content_lower.count(kw)

    metrics['external_calls'] = len(re.findall(r'\.\w+\s*\(', content))

    return metrics


def compute_file_score(metrics: dict) -> float:
    """Combine heuristic metrics into a single priority score."""
    score = 0.0
    score += min(metrics['external_fns'] * 2.0, 20.0)
    score += min(metrics['value_ops'] * 3.0, 30.0)
    score += min(metrics['financial_keywords'] * 0.5, 15.0)
    score += min(metrics['size'] / 1000, 10.0)
    score += min(metrics['external_calls'] * 0.3, 10.0)
    return score


# =============================================================================
# RUNNER
# =============================================================================

class AuditRunner:
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
        response = response.strip()
        if "```" in response:
            lines = response.split('\n')
            lines = [l for l in lines if not l.strip().startswith("```")]
            response = '\n'.join(lines)

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

    def _safe_parse_vulns(self, result: dict) -> List[Vulnerability]:
        try:
            raw_vulns = result.get('vulnerabilities', [])
            if not isinstance(raw_vulns, list):
                return []
            vulns = Vulnerabilities(vulnerabilities=raw_vulns)
            return list(vulns.vulnerabilities)
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
            'interfaces', 'artifacts', 'dist', 'build', 'libraries'
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

    # -----------------------------------------------------------------
    # LLM-BASED FILE RANKING
    # -----------------------------------------------------------------

    def rank_files(self, source_dir: Path, files: List[Path], file_contents: Dict[str, str]) -> List[Tuple[Path, int]]:
        """Rank files by audit priority. Returns list of (file, tier) where tier is 1/2/3."""
        if len(files) <= 3:
            return [(f, 1) for f in files]

        # Step 1: Heuristic scoring
        scored = []
        for f in files:
            rel_path = str(f.relative_to(source_dir))
            content = file_contents.get(rel_path, "")
            language = detect_language(f)
            metrics = compute_file_heuristic(content, language)
            score = compute_file_score(metrics)
            scored.append((f, score, metrics))

        scored.sort(key=lambda x: -x[1])

        # Step 2: LLM ranking of top candidates
        summaries = []
        for f, score, metrics in scored[:20]:
            rel_path = str(f.relative_to(source_dir))
            content = file_contents.get(rel_path, "")
            # Extract contract/struct names
            if detect_language(f) == 'solidity':
                contracts = re.findall(r'contract\s+(\w+)', content)
                contract_str = f" (contracts: {', '.join(contracts[:3])})" if contracts else ""
            else:
                contract_str = ""
            summaries.append(
                f"- {rel_path}{contract_str}: {metrics['external_fns']} external fns, "
                f"{metrics['value_ops']} value ops, {metrics['financial_keywords']} financial terms, "
                f"{metrics['size']} bytes"
            )

        summary_text = '\n'.join(summaries)

        try:
            response = self.inference(
                [
                    {"role": "system", "content": SYSTEM_FILE_RANKER},
                    {"role": "user", "content": f"Rank these files by security audit priority:\n\n{summary_text}"}
                ],
                timeout=60,
            )
            result = self.clean_json(response.get('content', '{}'))
            ranked_names = result.get('ranked_files', [])

            if ranked_names:
                # Build tier map from LLM ranking
                file_map = {str(f.relative_to(source_dir)): f for f in files}
                ranked_files = []
                seen = set()

                for name in ranked_names:
                    if name in file_map and name not in seen:
                        ranked_files.append(file_map[name])
                        seen.add(name)

                # Add any files the LLM missed
                for f in files:
                    rel = str(f.relative_to(source_dir))
                    if rel not in seen:
                        ranked_files.append(f)

                # Assign tiers
                total = len(ranked_files)
                tier1_cutoff = max(1, int(total * 0.4))
                tier2_cutoff = max(tier1_cutoff + 1, int(total * 0.7))

                result_tiers = []
                for i, f in enumerate(ranked_files):
                    if i < tier1_cutoff:
                        result_tiers.append((f, 1))
                    elif i < tier2_cutoff:
                        result_tiers.append((f, 2))
                    else:
                        result_tiers.append((f, 3))

                console.print(f"[cyan]File ranking: {tier1_cutoff} tier-1, {tier2_cutoff - tier1_cutoff} tier-2, {total - tier2_cutoff} tier-3[/cyan]")
                return result_tiers

        except Exception as e:
            console.print(f"[yellow]LLM ranking failed ({e}), using heuristic only[/yellow]")

        # Fallback: heuristic-only ranking
        total = len(scored)
        tier1_cutoff = max(1, int(total * 0.4))
        tier2_cutoff = max(tier1_cutoff + 1, int(total * 0.7))

        result_tiers = []
        for i, (f, _score, _metrics) in enumerate(scored):
            if i < tier1_cutoff:
                result_tiers.append((f, 1))
            elif i < tier2_cutoff:
                result_tiers.append((f, 2))
            else:
                result_tiers.append((f, 3))

        return result_tiers

    # -----------------------------------------------------------------
    # RELATED CONTENT
    # -----------------------------------------------------------------

    def get_related_content(self, file_path: Path, all_files: List[Path], source_dir: Path,
                            file_contents: Dict[str, str] = None) -> str:
        with open(file_path, 'r') as f:
            content = f.read()

        language = detect_language(file_path)
        rel_path = str(file_path.relative_to(source_dir))

        # Method 1: Import/inheritance-based resolution
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

        import_related = []
        for term in imports + inherits:
            term_clean = term.replace('./', '').replace('../', '').replace('.sol', '').replace('.rs', '').split('/')[-1]
            for f in all_files:
                if term_clean in f.stem and f != file_path:
                    import_related.append(f)

        # Method 2: Cross-contract reference resolution (Solution #4)
        cross_ref_files = []
        if file_contents:
            cross_refs = find_cross_contract_references(content, file_contents, rel_path)
            for cr in cross_refs:
                cr_path = source_dir / cr
                if cr_path.exists() and cr_path not in import_related:
                    cross_ref_files.append(cr_path)

        # Merge: import-based first, then cross-ref additions
        all_related = list(dict.fromkeys(import_related + cross_ref_files))

        parts = []
        total_len = 0
        max_len = 24000  # Slightly increased to accommodate cross-contract context

        for rf in all_related[:8]:
            try:
                with open(rf, 'r') as f:
                    rc = f.read()
                if total_len + len(rc) < max_len:
                    rf_lang = detect_language(rf)
                    source_label = "IMPORTED" if rf in import_related else "CROSS-REFERENCED"
                    parts.append(f"\n{source_label} FILE: {rf.relative_to(source_dir)}\n```{get_code_block_lang(rf_lang)}\n{rc}\n```")
                    total_len += len(rc)
            except:
                pass

        return '\n'.join(parts)

    # -----------------------------------------------------------------
    # ANALYZE FILE WITH PROMPT
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

        if is_interface_file(file_path, content):
            console.print(f"[dim]  -> {file_path.name} (skipped: interface)[/dim]")
            return [], 0, 0

        console.print(f"[dim]  -> {file_path.name} ({prompt_name}) [{language}][/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        system = system_prompt.format(format_instructions=parser.get_format_instructions())

        state_mapping = extract_state_mapping(content, language)
        call_graph = extract_call_graph(content, language)
        paired_diffs = extract_paired_operation_diffs(content, language)
        arith_annotations = extract_arithmetic_annotations(content, language)
        attack_scenarios = generate_attack_scenarios(content, language)

        context_sections = ""
        if state_mapping:
            context_sections += f"\n{state_mapping}\n"
        if call_graph:
            context_sections += f"\n{call_graph}\n"
        if paired_diffs:
            context_sections += f"\n{paired_diffs}\n"
        if arith_annotations:
            context_sections += f"\n{arith_annotations}\n"
        if attack_scenarios:
            context_sections += f"\n{attack_scenarios}\n"

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
                timeout=240,
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

                if v.confidence >= 0.6:
                    validated.append(v)

            if validated:
                console.print(f"[green]    Found {len(validated)} potential issues[/green]")

            return validated, response.get('input_tokens', 0), response.get('output_tokens', 0)

        except Exception as e:
            console.print(f"[red]    Error: {e}[/red]")
            return [], 0, 0

    # -----------------------------------------------------------------
    # ACCESS CONTROL PRE-SCAN
    # -----------------------------------------------------------------

    def scan_access_control(
        self, source_dir: Path, files_to_analyze: List[Path],
        file_contents: Dict[str, str], model: str
    ) -> List[Vulnerability]:
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
    # VERIFICATION PHASE
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
    # MAIN ORCHESTRATOR
    # -----------------------------------------------------------------

    def analyze_project(self, source_dir: Path, project_name: str) -> AnalysisResult:
        console.print(f"\n[bold cyan]=== Analyzing: {project_name} ===[/bold cyan]")

        model = self.config.get('analysis_model', self.model)
        verify_model = self.config.get('verify_model', model)

        # Step 1: Find files
        files = self.find_files(source_dir)
        if not files:
            console.print("[yellow]No files found[/yellow]")
            return AnalysisResult(
                project=project_name, timestamp=datetime.now().isoformat(),
                files_analyzed=0, files_skipped=0, total_vulnerabilities=0,
                vulnerabilities=[], token_usage={'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}
            )

        console.print(f"[dim]Found {len(files)} in-scope files[/dim]")

        # Step 2: Read all file contents
        file_contents: Dict[str, str] = {}
        for f in files:
            rel_path = str(f.relative_to(source_dir))
            try:
                with open(f, 'r') as fh:
                    file_contents[rel_path] = fh.read()
            except:
                pass

        # Step 3: Rank files
        console.print(f"\n[cyan]Phase 0: Ranking files by audit priority...[/cyan]")
        ranked = self.rank_files(source_dir, files, file_contents)

        # Step 4: Pre-compute related content (with enhanced cross-contract resolution)
        related_map = {}
        for f, _tier in ranked:
            related_map[f] = self.get_related_content(f, files, source_dir, file_contents)

        # Step 5: Build prompt assignments based on tier
        solidity_prompts_full = [
            (model, SYSTEM_VALUE_FLOW, 'value_flow'),
            (model, SYSTEM_STATE_LIFECYCLE, 'state_lifecycle'),
            (model, SYSTEM_ACCESS_CONTROL, 'access_control'),
            (model, SYSTEM_EXTERNAL_INTERACTIONS, 'external_interactions'),
            (model, SYSTEM_ECONOMIC_LOGIC, 'economic_logic'),
        ]

        solidity_prompts_medium = [
            (model, SYSTEM_VALUE_FLOW, 'value_flow'),
            (model, SYSTEM_STATE_LIFECYCLE, 'state_lifecycle'),
            (model, SYSTEM_ECONOMIC_LOGIC, 'economic_logic'),
        ]

        solidity_prompts_light = [
            (model, SYSTEM_VALUE_FLOW, 'value_flow'),
        ]

        rust_prompts_full = [
            (model, SYSTEM_RUST_BROAD, 'rust_broad'),
            (model, SYSTEM_STATE_LIFECYCLE, 'state_lifecycle'),
            (model, SYSTEM_EXTERNAL_INTERACTIONS, 'external_interactions'),
        ]

        rust_prompts_light = [
            (model, SYSTEM_RUST_BROAD, 'rust_broad'),
        ]

        all_vulns = []
        total_in = total_out = 0

        # =============================================
        # PHASE 1: PARALLEL MULTI-PROMPT ANALYSIS
        # =============================================
        tasks = []
        for file_path, tier in ranked:
            rel_path = str(file_path.relative_to(source_dir))
            related = related_map.get(file_path, "")
            language = detect_language(file_path)

            if language == 'rust':
                prompts = rust_prompts_full if tier <= 2 else rust_prompts_light
            else:
                if tier == 1:
                    prompts = solidity_prompts_full
                elif tier == 2:
                    prompts = solidity_prompts_medium
                else:
                    prompts = solidity_prompts_light

            for m, prompt, name in prompts:
                tasks.append((rel_path, related, m, prompt, name))

        console.print(f"\n[cyan]Phase 1: Multi-Prompt Analysis ({len(ranked)} files, {len(tasks)} tasks)[/cyan]")

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            for rel_path, related, m, prompt, name in tasks:
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
        # PHASE 2: ACCESS CONTROL PRE-SCAN
        # =============================================
        console.print(f"\n[cyan]Phase 2: Access Control Scan[/cyan]")
        files_to_scan = [f for f, tier in ranked]
        access_findings = self.scan_access_control(source_dir, files_to_scan, file_contents, model)
        all_vulns.extend(access_findings)
        console.print(f"[dim]  Access scan added {len(access_findings)} findings[/dim]")

        # =============================================
        # DEDUP BEFORE VERIFICATION
        # =============================================
        deduped = deduplicate_findings(all_vulns)
        console.print(f"[dim]After dedup: {len(deduped)} unique findings[/dim]")

        # =============================================
        # PHASE 3: VERIFICATION
        # =============================================
        console.print(f"\n[cyan]Phase 3: Verification[/cyan]")
        verified = self.verify_findings(source_dir, deduped, file_contents, verify_model)

        # =============================================
        # QUALITY GATE
        # =============================================
        final = apply_quality_gate(verified, file_contents, max_findings=80)

        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        final.sort(key=lambda v: (order.get(v.severity.value, 4), -v.confidence))

        console.print(f"\n[green]Final: {len(final)} verified findings[/green]")

        # Save raw text dump for debugging
        raw_text_path = "raw_findings.txt"
        with open(raw_text_path, 'w') as f:
            for v in final:
                f.write(f"{'='*80}\n[{v.severity.value.upper()}] {v.title}\n")
                f.write(f"File: {v.file} | Location: {v.location}\n")
                f.write(f"Confidence: {v.confidence} | Prompt: {v.reported_by_model}\n")
                f.write(f"Type: {v.vulnerability_type}\n\n{v.description}\n\n")
        console.print(f"[dim]Raw findings: {raw_text_path}[/dim]")

        return AnalysisResult(
            project=project_name, timestamp=datetime.now().isoformat(),
            files_analyzed=len(ranked),
            files_skipped=len(files) - len(ranked),
            total_vulnerabilities=len(final),
            vulnerabilities=final,
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
        'model': 'Qwen/Qwen3-Next-80B-A3B-Instruct',
        'analysis_model': 'Qwen/Qwen3-Next-80B-A3B-Instruct',
        'verify_model': 'Qwen/Qwen3-Next-80B-A3B-Instruct',
    }

    project_dir = project_dir or "/app/project_code"

    console.print(Panel.fit(
        "[bold cyan]Smart Contract Security Agent[/bold cyan]\n"
        "[dim]5 audit dimensions | LLM file ranking | Access pre-scan | Verification[/dim]",
        border_style="cyan"
    ))

    try:
        start = time.time()
        runner = AuditRunner(config, inference_api)

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

        remaining = 18*60 - elapsed
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
    project_root = Path(__file__).parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # Support command-line args
    project = sys.argv[1] if len(sys.argv) > 1 else None
    api = sys.argv[2] if len(sys.argv) > 2 else None
    report = agent_main(project, api)

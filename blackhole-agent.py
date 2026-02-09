import hashlib
import json
import logging
import os
import re
import requests
import sys
import time
import traceback
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List
from textwrap import dedent


from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


console = Console()
#Audit protocol - Core Protocol Safety & State Invariants

SYSTEM_1 = """
You are an EXPERT DeFi smart contract security auditor.

Your task is to identify REAL vulnerabilities that can lead to:
- Loss or misallocation of funds or value
- Unauthorized access or privilege escalation
- Permanent or long-term denial of service of core functionality
- Broken accounting or violated state invariants
- Economically unfair or manipulable protocol behavior

============================================================
PHASE 0 — DESIGN INFERENCE (MANDATORY)
============================================================

Before evaluating security, infer the protocol’s design from the code:

1. What assets or values are being managed?
2. How is value funded, minted, escrowed, or sourced?
3. What are the trust and permission boundaries (users, admins, keepers)?
4. What are the core accounting invariants the protocol intends to uphold?
5. What external dependencies exist (tokens, contracts, runtimes)?
6. Are any resources created via predictable identifiers (deployment nonce, CREATE2,
   clones, factory-derived pool/pair IDs), and are there external parties who can
   create those resources first?

ALL subsequent checks must be evaluated relative to this inferred design.
Do NOT assume standard ERC20, pre-funded balances, or linear execution unless implied by the code.

============================================================
PHASE 1 — SYSTEMATIC VERIFICATION (PER FUNCTION)
============================================================

Access Control & Authorization
1. Does this function perform critical operations (value movement, mint/burn, parameter changes)?
2. Are those operations restricted consistently with the inferred permission model?

Input Validation & Execution Safety
3. Are all parameters validated for correctness and bounds?
4. Are caller-provided parameters validated against computed or actual execution values?
5. Is validation performed before irreversible state changes or external effects?

State & Invariant Correctness
6. Do related state variables update together and remain synchronized?
7. Can state transitions be repeated, skipped, or partially applied?
8. Can state from one user, position, or phase influence another improperly?

External Interactions
9. Are external calls or callbacks possible under the execution model?
10. If so, are invariants preserved across re-entrancy or cross-module execution?
11. If the code creates or relies on externally created resources whose identifiers
    can be predicted in advance (e.g., addresses derived from deployment nonce,
    CREATE2 salts, clones, deterministic factories, pool/pair IDs), does it:
    - check whether the resource already exists, and
    - handle “already exists” safely (avoid permanent DoS)?
12. If the contract has fallback/receive handlers, do they have side effects that can mis-handle inbound value (e.g., auto-staking, auto-minting, or state changes) in a way that breaks withdrawal/settlement invariants or causes liveness failures?

Mathematics & Precision
12. Are arithmetic operations safe under the language/runtime rules?
13. Can rounding, truncation, or precision loss cause permanent value drift?

Control Flow & Edge Cases
14. Are independent conditions handled independently (not incorrectly mutually exclusive)?
15. Are zero values, max values, empty states, or terminal states handled correctly?

============================================================
PHASE 2 — HIGH-RISK PATTERN CHECKS (CHECK FIRST)
============================================================

- Validation occurring after state changes
- Missing access control on critical operations
- Accounting using requested values instead of actual executed values
- Conditional updates causing state desynchronization
- Invariant breaks enabled by re-entrancy or callbacks
- Predictable-identifier front-running: attacker pre-creates or pre-initializes a
  resource (pair/pool/vault/escrow/address) at a predictable identifier causing
  subsequent core operations to revert or become permanently unusable.
- Receive/fallback side effects: inbound value triggers logic that re-routes funds, changes accounting, or blocks withdrawals/settlements unexpectedly.

============================================================
VERIFICATION REQUIREMENTS (MANDATORY)
============================================================

For each vulnerability:
1. Exact function name(s) and variables involved
2. Concrete exploit or failure scenario with specific steps
3. Clear impact: who loses what, where value goes, or what becomes blocked
4. Confidence score (0.0–1.0) reflecting how likely the issue is exploitable in practice

MANDATORY PRE-REPORT CHECKS:
- Before reporting "missing access control": verify the function does NOT
  already have an access modifier (onlyOwner, onlyRole, onlyAdmin, etc.)
- Before reporting "fund theft" or "drain": verify the function can actually
  modify state (is NOT view/pure) AND can be called by an untrusted user
- Before reporting "reentrancy": verify there is actually an external call
  to an untrusted address AND state is modified after that call
- Before reporting any vulnerability about an admin function: ask yourself
  "does this require the admin to act against their own protocol?" If yes,
  DO NOT REPORT IT.

============================================================
WHAT NOT TO REPORT
============================================================

- Style, naming, or readability issues
- Gas-only optimizations
- Hypothetical issues without realistic exploit or failure paths
- Admin/owner key compromise scenarios — if the attack requires a trusted
  admin to act maliciously, this is a governance risk, NOT a code vulnerability.
  Examples: "admin changes feeCollector", "owner sets parameter to zero",
  "governance updates implementation"

============================================================
OUTPUT FORMAT
============================================================

Return ONLY raw valid JSON. Begin with:
{{"vulnerabilities":

{format_instructions}
"""

#Audit protocol - Time-based Entitlements & Claims
SYSTEM_2 = """
You are an EXPERT DeFi smart contract security auditor specializing in
vesting, entitlement tracking, and transferable or time-based claims.

============================================================
PHASE 0 — DESIGN INFERENCE (MANDATORY)
============================================================

Infer:
1. What constitutes an entitlement (tokens, shares, claim units)?
2. How entitlement accrues (time-based, progress-based, event-based)?
3. Whether entitlements are transferable, splittable, or mergeable
4. How total entitlement value is funded or guaranteed

============================================================
PHASE 1 — SYSTEMATIC VERIFICATION
============================================================

Entitlement Isolation
1. Is progress or already-realized entitlement scoped per position?
2. Can history from one position influence another after transfer or split?

Transfer / Split / Merge Correctness
3. When positions are split or reassigned, is historical progress preserved proportionally?
4. Can transfer → claim → transfer cycles recreate or double-count entitlement?

Sequencing & Boundary Conditions
5. Are entitlement boundaries defined and enforced relative to the schedule model?
6. Are rounding and interval boundaries consistent across functions?

Accounting & Value Conservation
7. Is total released entitlement bounded by what the protocol has committed to deliver?
8. Can entitlement become permanently unclaimable contrary to protocol guarantees?

============================================================
HIGH-RISK PATTERNS
============================================================

- Shared claimed/progress state across positions
- Recomputing remaining entitlement without accounting for prior realization
- Boundary rounding causing silent loss or gain
- Validation after claim or transfer

============================================================
VERIFICATION REQUIREMENTS
============================================================

Include:
- Exact functions and entitlement variables
- Concrete numeric/time-based scenario
- Over- or under-claim arithmetic
- Confidence score

MANDATORY PRE-REPORT CHECK:
- Before reporting any vulnerability about an admin function: ask yourself
  "does this require the admin to act against their own protocol?" If yes,
  DO NOT REPORT IT.

============================================================
WHAT NOT TO REPORT
============================================================

- Admin/owner key compromise scenarios — governance risk, not code vulnerability
- Gas-only optimizations
- Style, naming, or readability issues
- Hypothetical issues without realistic exploit or failure paths

============================================================
OUTPUT FORMAT
============================================================

IMPORTANT: Begin your response with `{{"vulnerabilities":`

{format_instructions}
"""

#Audit protocol - Reward Distribution & Cumulative Accounting

SYSTEM_3 = """
You are an EXPERT DeFi smart contract security auditor specializing in
reward distribution and cumulative accounting systems.

============================================================
PHASE 0 — DESIGN INFERENCE (MANDATORY)
============================================================

Infer:
1. How rewards are sourced (balances, minting, external distributor, epochs)
2. How rewards are accounted (indices, snapshots, checkpoints)
3. What guarantees exist about eventual claimability

============================================================
PHASE 1 — SYSTEMATIC VERIFICATION
============================================================

Eventual Claimability
1. Can all accrued reward value become claimable by someone?
2. Can rounding or update logic permanently strand value?

Conservation of Value
3. Is total user-claimable reward bounded by the maximum deliverable value
   under the protocol’s funding or issuance model?

Update Ordering & Fairness
4. Are updates ordered to prevent front-running or griefing?
5. Are balances and reward checkpoints updated consistently?

Accounting Correctness
6. Do deposits, withdrawals, and transfers update reward state atomically?
7. Are actual received values used instead of expected values?

============================================================
HIGH-RISK PATTERNS
============================================================

- Reward debt not updated on balance changes
- Index updated using expected rather than actual value
- Rounding that permanently discards rewards
- Claim paths exceeding deliverable rewards

============================================================
VERIFICATION REQUIREMENTS
============================================================

Include:
- Exact accounting variables involved
- Concrete numeric example
- Failure or exploit steps
- Impact arithmetic
- Confidence score (0.0–1.0) reflecting how likely the issue is exploitable in practice

MANDATORY PRE-REPORT CHECKS:
- Before reporting "missing access control": verify the function does NOT
  already have an access modifier
- Before reporting "fund theft": verify the function can modify state AND is
  user-callable (not admin-only)
- Before reporting any admin-function issue: "does this require the admin to
  act against their own protocol?" If yes, DO NOT REPORT IT.

============================================================
WHAT NOT TO REPORT
============================================================

- Admin/owner key compromise scenarios — governance risk, not code vulnerability
- Gas-only optimizations
- Style, naming, or readability issues
- Hypothetical issues without realistic exploit or failure paths

============================================================
OUTPUT FORMAT
============================================================

IMPORTANT: Begin your response with `{{"vulnerabilities":`

{format_instructions}
"""

#Audit protocol - Liquidation Flows, Bad-Debt Handling, and Profit/Loss Attribution
SYSTEM_4 = """
You are an EXPERT DeFi smart contract security auditor specializing in
liquidation flows, bad-debt handling, and profit/loss attribution.

============================================================
PHASE 0 — DESIGN INFERENCE (MANDATORY)
============================================================

Infer:
1. How obligations, collateral, and risk are defined
2. How losses are allocated when obligations exceed value
3. Who bears risk (users, LPs, protocol, external backstops)

============================================================
PHASE 1 — SYSTEMATIC VERIFICATION
============================================================

PnL Attribution
1. Are profits and losses measured relative to the correct obligation baseline?
2. Are all components of obligation accounted for consistently?
3. If there are loss events that reduce backing assets (e.g., slashing, penalties, bad debt), does the protocol allocate that loss fairly across claimants according to its intended model?

Simultaneous Adjustments
3. Can multiple economic adjustments apply in the same operation?
4. Does control flow allow all required adjustments to apply?

Bad Debt Handling
5. Is shortfall allocation consistent with the protocol’s loss model?
6. Can debt forgiveness or write-offs be repeated?

External Inputs
7. If pricing or external inputs are used, are they validated relative to design?

============================================================
HIGH-RISK PATTERNS
============================================================

- Value paid out exceeding seized value
- Debt reduced without asset inflow
- Repeated bad-debt forgiveness
- Skipped adjustments due to branching

MANDATORY PRE-REPORT CHECK:
- Before reporting any vulnerability about an admin function: ask yourself
  "does this require the admin to act against their own protocol?" If yes,
  DO NOT REPORT IT.

============================================================
WHAT NOT TO REPORT
============================================================

- Admin/owner key compromise scenarios — governance risk, not code vulnerability
- Gas-only optimizations
- Style, naming, or readability issues
- Hypothetical issues without realistic exploit or failure paths

============================================================
OUTPUT FORMAT
============================================================

IMPORTANT: Begin your response with `{{"vulnerabilities":`

{format_instructions}
"""

#Audit protocol - Deposit, Minting, and Strategy Execution Logic
SYSTEM_5 = """
You are an EXPERT DeFi smart contract security auditor specializing in
deposit, minting, and strategy execution logic.

============================================================
PHASE 0 — DESIGN INFERENCE (MANDATORY)
============================================================

Infer:
1. How value enters the system
2. How credit or shares are issued
3. What asset behaviors are supported
4. Who is trusted to execute strategy logic

============================================================
PHASE 1 — SYSTEMATIC VERIFICATION
============================================================

Deposit vs Credit Consistency
1. Is credit based on actual received value?
2. Are all asset behaviors handled correctly?

Multi-Asset Safety
3. Are native and tokenized asset paths symmetric?
4. Can accounting update without successful transfer?

Strategy Safety
5. Are strategy/rebalance entrypoints restricted or validated?
6. Can caller parameters cause economic harm?

============================================================
HIGH-RISK PATTERNS
============================================================

- Minting based on expected rather than received value
- Missing slippage or bounds on strategy execution
- Permissionless harmful strategy execution

MANDATORY PRE-REPORT CHECK:
- Before reporting any vulnerability about an admin function: ask yourself
  "does this require the admin to act against their own protocol?" If yes,
  DO NOT REPORT IT.

============================================================
WHAT NOT TO REPORT
============================================================

- Admin/owner key compromise scenarios — governance risk, not code vulnerability
- Gas-only optimizations
- Style, naming, or readability issues
- Hypothetical issues without realistic exploit or failure paths

============================================================
OUTPUT FORMAT
============================================================

IMPORTANT: Begin your response with `{{"vulnerabilities":`

{format_instructions}
"""

#Audit protocol - Interface Compatibility and Settlement Accounting
SYSTEM_6 = """
You are an EXPERT DeFi smart contract security auditor specializing in
interface compatibility and settlement accounting.

============================================================
PHASE 0 — DESIGN INFERENCE (MANDATORY) 
============================================================

Infer:
1. Which public entrypoints are intended to be callable
2. How calls are dispatched or routed (direct delegate, fallback router, selector-byte dispatch, etc.)
3. How value is debited, escrowed, and returned (including partial fills)
4. Whether any required resources are created or referenced at predictable identifiers
   (deployment nonce, CREATE2, clones, deterministic factories, pool/pair IDs), and
   whether external parties could create them first
5. Whether the system spans multiple languages/runtimes/modules (e.g., Solidity <-> Rust/Stylus),
   and which entrypoints are wrappers that forward execution elsewhere

============================================================
PHASE 1 — SYSTEMATIC VERIFICATION
============================================================

Interface Reachability (MECHANICAL VERIFICATION REQUIRED)
1. Can exposed entrypoints reach their intended implementation?
2. Are call signatures and decoding consistent across the entire call path?
3. For EVERY externally exposed function that forwards execution (directDelegate / dispatcher / fallback):
   - Identify the intended target implementation (module/contract/runtime)
   - Compare the wrapper's declared parameters (count, types, order) to the target's expected parameters
   - Verify call-data decoding/routing matches (e.g., selector-byte dispatch, ABI encoding, struct layout)
   Flag ANY mismatch as a HIGH-severity functional DoS risk, EVEN IF there exists an alternative fallback path.
4. Treat wrapper functions with unused/commented parameters, placeholder arguments, or "extra" parameters
   as strong indicators of ABI/signature mismatch and verify them explicitly.
5. If an entrypoint depends on creating or interacting with an external resource at a predictable identifier,
   does it verify existence and fail safely (avoid permanent DoS)?

Settlement & Refund Safety (EXECUTED-VS-REQUESTED CONSISTENCY)
6. Does settlement logic ensure that any value returned to a caller is bounded by the value actually
   debited or escrowed under the protocol’s execution and accounting model?
7. If a function partially executes (e.g., partial fill due to insufficient liquidity), verify that:
   - the debit uses the executed amount
   - any refund is computed ONLY relative to amounts that were actually debited/escrowed
   - refunds are NOT computed from requested/original amounts unless those requested amounts were first debited
8. Can refunds or reconciliation be replayed, double-counted, or triggered multiple times?

Execution Consistency
9. Are actual executed values used in all downstream accounting, events, and state updates (not requested values)?
10. Is validation performed before irreversible effects?

============================================================
HIGH-RISK PATTERNS
============================================================

- Cross-runtime ABI / signature mismatch (Solidity <-> Stylus/Rust/other) causing entrypoints to be unusable
- Wrapper/dispatcher functions with unused/commented/extra parameters indicating ABI mismatch
- Selector/dispatch-byte routing mismatches (wrong byte/index, wrong mapping, wrong executor target)
- Predictable-identifier front-running: attacker pre-creates or pre-initializes a required resource
  (pair/pool/vault/escrow/address) at a predictable identifier causing entrypoints to revert or become unusable
- Refund inconsistency: debit uses executed amount but refund uses requested/original amount (protocol pays extra)
- Refunds exceeding debits or exceeding escrowed value
- Replayable settlement or refund logic

============================================================
VERIFICATION REQUIREMENTS
============================================================

For each vulnerability:
1. Exact function name(s) and variables involved
2. Concrete exploit or failure scenario with specific steps
3. Clear impact: who loses what, where value goes, or what becomes blocked
4. Confidence score (0.0–1.0) with these constraints:
   Confidence score (0.0–1.0) reflecting how likely the issue is exploitable in practice

MANDATORY PRE-REPORT CHECKS:
- Before reporting ABI mismatch: verify BOTH sides of the interface and confirm
  the parameter count/types genuinely differ
- Before reporting "fund theft": verify the function can modify state AND is
  user-callable (not admin-only)
- Before reporting any admin-function issue: "does this require the admin to
  act against their own protocol?" If yes, DO NOT REPORT IT.

============================================================
WHAT NOT TO REPORT
============================================================

- Admin/owner key compromise scenarios — governance risk, not code vulnerability
- Gas-only optimizations
- Style, naming, or readability issues
- Hypothetical issues without realistic exploit or failure paths

============================================================
OUTPUT FORMAT
============================================================

Return ONLY raw valid JSON. Begin with:
{{"vulnerabilities":

{format_instructions}
"""

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Vulnerability(BaseModel):
    """A security vulnerability finding."""
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
            id_source = f"{self.file}:{self.title}"
            self.id = hashlib.md5(id_source.encode()).hexdigest()[:16]
        # Semantic key for cross-prompt dedup (same file + function + vuln type)
        func_name = self._extract_func_for_dedup()
        vtype_norm = re.sub(r'[^a-z]', '', (self.vulnerability_type or '').lower())
        self._semantic_key = hashlib.md5(
            f"{self.file}:{func_name}:{vtype_norm}".encode()
        ).hexdigest()[:16]

    def _extract_func_for_dedup(self) -> str:
        """Extract primary function name for semantic dedup."""
        for field in [self.location, self.title, self.description]:
            if not field:
                continue
            m = re.search(r'\b(\w+)\s*\(', field)
            if m and m.group(1) not in (
                'function', 'require', 'assert', 'revert', 'emit',
                'event', 'error', 'if', 'for', 'while', 'return',
            ):
                return m.group(1).lower()
        return ''

class Vulnerabilities(BaseModel):
    """A collection of security vulnerability vulnerabilities."""
    vulnerabilities: list[Vulnerability]

class AnalysisResult(BaseModel):
    """Result from analyzing a project."""
    project: str
    timestamp: str
    files_analyzed: int
    files_skipped: int
    total_vulnerabilities: int
    vulnerabilities: list[Vulnerability]
    token_usage: dict[str, int]


# ---------------------------------------------------------------------------
# Self-contained false-positive filter (no external imports)
# ---------------------------------------------------------------------------

class FalsePositiveFilter:
    """Deterministic, zero-dependency false-positive filter.

    Runs the highest-impact checks that the full validation pipeline uses,
    but entirely self-contained so the agent has no imports outside stdlib
    and its existing dependencies.
    """

    # -- Access-control modifiers that indicate governance protection ----------
    ACCESS_MODIFIERS = [
        'onlyOwner', 'onlyGovernor', 'onlyGuardian', 'onlyGov',
        'onlyRole', 'restricted', 'onlyAdmin', 'onlyController',
        'onlyGovernance', 'onlyAuthorized', 'onlyOperator', 'onlyKeeper',
        'onlyMinter', 'onlyManager', 'onlyVault', 'onlyStrategy',
        'whenNotPaused',
    ]

    # -- Reentrancy-guard modifier names ---------------------------------------
    REENTRANCY_MODIFIERS = [
        'nonReentrant', 'noReentrancy', 'nonreentrant',
        'reentrancyGuard', 'lock', 'mutex',
    ]

    REENTRANCY_LIBRARIES = [
        'ReentrancyGuard', 'ReentrancyGuardUpgradeable',
    ]

    # -- Vulnerability-type keywords used to match checks ----------------------
    _ARITHMETIC_KEYWORDS = [
        'overflow', 'underflow', 'arithmetic', 'integer',
        'safemath', 'safe math', 'unchecked',
    ]
    _REENTRANCY_KEYWORDS = [
        'reentrancy', 're-entrancy', 'reentrant',
    ]
    _ACCESS_KEYWORDS = [
        'access control', 'missing access', 'unauthorized', 'privilege',
        'permission', 'unprotected',
    ]
    _GOVERNANCE_KEYWORDS = [
        'centrali', 'admin', 'owner', 'governance', 'privileged',
        'setter', 'parameter change', 'fee change', 'config change',
    ]

    # -- Admin key compromise phrases (filter these as governance risk) ------
    _ADMIN_COMPROMISE_PHRASES = [
        'compromised admin', 'compromises the admin', 'malicious owner',
        'malicious admin', 'rogue admin', 'compromised owner',
        'admin private key', 'owner private key',
        'trusted admin acts maliciously', 'malicious governance',
        'compromised governance', 'compromised proxy admin',
        'compromised proxy_admin', 'malicious proxy admin',
    ]

    # -- Title-level admin/centralization patterns (FP indicators) ----------
    _ADMIN_TITLE_PATTERNS = [
        'admin can ', 'owner can ', 'admin is able to', 'owner is able to',
        'centralization risk', 'centralisation risk',
        'centralization:', 'centralisation:',
        'single point of failure', 'privileged role can',
    ]
    # Escape-hatch: if description contains these, the finding may be a real
    # access-control bug rather than an admin-feature complaint.
    _ADMIN_TITLE_ESCAPE = [
        'anyone can', 'any user', 'external user', 'attacker',
        'unauthorized', 'missing access control', 'no access control',
        'should be restricted', 'missing restriction', 'permissionless',
    ]

    # -- View/pure function keywords ----------------------------------------
    _VIEW_PURE_KEYWORDS = ['view', 'pure']

    # -- Impact keywords that require state modification ---------------------
    _STATE_IMPACT_KEYWORDS = [
        'fund theft', 'drain', 'steal', 'loss of funds', 'reentrancy',
        'state corruption', 'double spend', 'unauthorized mint',
        'unauthorized transfer', 'fund loss', 'funds stolen',
        'funds drained', 'funds lost',
    ]

    def __init__(self):
        self._solidity_version: str = ''
        self._has_safemath: bool = False
        self._has_reentrancy_guard: bool = False
        self._protected_functions: Dict[str, List[str]] = {}   # func_name -> [modifiers]
        self._functions_with_require: Dict[str, bool] = {}
        self._view_pure_functions: Dict[str, bool] = {}
        self._immutables: set = set()
        self._has_initializer: bool = False
        self._event_only_functions: Dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Pre-analysis: run once per contract file
    # ------------------------------------------------------------------

    def analyze(self, contract_code: str) -> None:
        """Pre-analyse a contract to extract protections (call once per file)."""
        self._solidity_version = ''
        self._has_safemath = False
        self._has_reentrancy_guard = False
        self._protected_functions = {}
        self._functions_with_require = {}
        self._view_pure_functions = {}
        self._immutables = set()
        self._has_initializer = False
        self._event_only_functions = {}

        if not contract_code:
            return

        # Solidity version
        ver = re.search(r'pragma\s+solidity\s+[\^>=]*\s*(0\.\d+)', contract_code)
        if ver:
            self._solidity_version = ver.group(1)

        # SafeMath
        self._has_safemath = bool(re.search(r'using\s+SafeMath\s+for', contract_code))

        # Reentrancy guard inheritance
        for lib in self.REENTRANCY_LIBRARIES:
            if lib in contract_code:
                self._has_reentrancy_guard = True
                break

        # Map functions → modifiers & require presence
        for m in re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\{',
            contract_code,
            re.DOTALL,
        ):
            fn_name = m.group(1)
            modifiers_section = m.group(2)

            # Collect access-control modifiers
            mods = [mod for mod in self.ACCESS_MODIFIERS if mod in modifiers_section]

            # Collect reentrancy modifiers
            re_mods = [mod for mod in self.REENTRANCY_MODIFIERS if mod in modifiers_section]
            mods.extend(re_mods)

            if mods:
                self._protected_functions[fn_name] = mods

            # Check for require/assert inside the body
            body_start = m.end()
            body_end = self._find_brace_end(body_start, contract_code)
            body = contract_code[body_start:body_end]
            self._functions_with_require[fn_name] = bool(
                re.search(r'(require|assert|revert)\s*\(', body)
            )

            # Check if function is view/pure
            mod_lower = modifiers_section.lower()
            self._view_pure_functions[fn_name] = any(
                kw in mod_lower for kw in self._VIEW_PURE_KEYWORDS
            )

            # Check if function body only emits events (+ require/revert)
            body_clean = re.sub(r'//[^\n]*', '', body)
            body_clean = re.sub(r'/\*.*?\*/', '', body_clean, flags=re.DOTALL)
            stmts = [s.strip() for s in body_clean.split(';') if s.strip()]
            if stmts and all(
                re.match(r'^(emit\s|require\s*\(|revert\s|$)', s)
                for s in stmts
            ):
                self._event_only_functions[fn_name] = True

        # Immutable / constant variable declarations
        for im in re.finditer(r'\b(\w+)\s+(?:immutable|constant)\s+(\w+)', contract_code):
            self._immutables.add(im.group(2).lower())

        # Initializer pattern detection (proxy / upgradeable contracts)
        self._has_initializer = bool(
            re.search(r'function\s+initialize\s*\(', contract_code)
            or 'Initializable' in contract_code
        )

    # ------------------------------------------------------------------
    # Per-vulnerability check
    # ------------------------------------------------------------------

    def check(self, vuln: 'Vulnerability', contract_code: str) -> Dict[str, Any]:
        """Return ``{is_false_positive, reason, adjusted_severity}``."""
        vtype = (vuln.vulnerability_type or '').lower()
        desc = (vuln.description or '').lower()
        title = (vuln.title or '').lower()
        combined = f"{vtype} {desc} {title}"

        # 1. Solidity >=0.8 overflow/underflow protection
        if self._matches_any(combined, self._ARITHMETIC_KEYWORDS):
            fp = self._check_arithmetic_protection(combined, contract_code)
            if fp:
                return fp

        # 2. Reentrancy guard detection
        if self._matches_any(combined, self._REENTRANCY_KEYWORDS):
            fp = self._check_reentrancy_protection(vuln, contract_code)
            if fp:
                return fp

        # 3. Access-control / governance already present
        if self._matches_any(combined, self._ACCESS_KEYWORDS):
            fp = self._check_access_control(vuln, contract_code)
            if fp:
                return fp

        # 4. Governance / centralisation findings on protected setters
        if self._matches_any(combined, self._GOVERNANCE_KEYWORDS):
            fp = self._check_governance_setter(vuln, contract_code)
            if fp:
                return fp

        # 5. Input-validation findings where require already exists
        if 'validation' in combined or 'input' in combined or 'bounds' in combined:
            fp = self._check_existing_validation(vuln, contract_code)
            if fp:
                return fp

        # 6. View/pure function check — cannot cause state changes
        fp = self._check_view_pure_impact(vuln, contract_code)
        if fp:
            return fp

        # 7. Admin key compromise phrase detector
        fp = self._check_admin_compromise_phrases(vuln)
        if fp:
            return fp

        # 8. Admin/centralization title pattern
        fp = self._check_admin_centralization_title(vuln)
        if fp:
            return fp

        # 9. Constructor-only issues in initialized/proxy contracts
        fp = self._check_constructor_context(vuln)
        if fp:
            return fp

        # 10. Immutable/constant variable modification claims
        fp = self._check_immutable_constant(vuln)
        if fp:
            return fp

        # 11. Event-only function severity cap
        fp = self._check_event_only_function(vuln)
        if fp:
            return fp

        # 12. Confidence threshold
        if vuln.confidence < 0.3:
            return {
                'is_false_positive': True,
                'reason': f'low confidence ({vuln.confidence:.0%}), below 0.3 threshold',
                'adjusted_severity': None,
            }

        return {'is_false_positive': False, 'reason': '', 'adjusted_severity': None}

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    def _check_arithmetic_protection(self, combined: str, code: str) -> Dict[str, Any] | None:
        """Filter arithmetic FPs when Solidity >=0.8 or SafeMath is used."""
        # Check for explicit unchecked block mention (those bypass 0.8 protection)
        if 'unchecked' in combined and 'unchecked' in code:
            return None  # Could be real

        is_08_plus = False
        if self._solidity_version:
            try:
                minor = int(self._solidity_version.split('.')[1])
                is_08_plus = minor >= 8
            except (IndexError, ValueError):
                pass

        if is_08_plus:
            return {
                'is_false_positive': True,
                'reason': f'Solidity {self._solidity_version} has built-in overflow protection',
                'adjusted_severity': None,
            }
        if self._has_safemath:
            return {
                'is_false_positive': True,
                'reason': 'SafeMath library protects arithmetic operations',
                'adjusted_severity': None,
            }
        return None

    def _check_reentrancy_protection(self, vuln: 'Vulnerability', code: str) -> Dict[str, Any] | None:
        """Filter reentrancy FPs when the function has a guard."""
        fn = self._extract_function_name(vuln)

        # Contract-wide guard
        if self._has_reentrancy_guard:
            # Check if the specific function uses the modifier
            if fn and fn in self._protected_functions:
                mods = self._protected_functions[fn]
                if any(m in self.REENTRANCY_MODIFIERS for m in mods):
                    return {
                        'is_false_positive': True,
                        'reason': f'{fn}() protected by reentrancy guard',
                        'adjusted_severity': None,
                    }

            # Even without per-function proof, guard is inherited
            if fn:
                # Search directly in code for function + nonReentrant in signature
                pat = rf'function\s+{re.escape(fn)}\s*\([^)]*\)[^{{]*nonReentrant'
                if re.search(pat, code):
                    return {
                        'is_false_positive': True,
                        'reason': f'{fn}() has nonReentrant modifier',
                        'adjusted_severity': None,
                    }
        return None

    def _check_access_control(self, vuln: 'Vulnerability', _code: str) -> Dict[str, Any] | None:
        """Filter access-control FPs when function already has a modifier."""
        fn = self._extract_function_name(vuln)
        if not fn:
            return None

        if fn in self._protected_functions:
            mods = self._protected_functions[fn]
            access_mods = [m for m in mods if m in self.ACCESS_MODIFIERS]
            if access_mods:
                return {
                    'is_false_positive': True,
                    'reason': f'{fn}() protected by {", ".join(access_mods)}',
                    'adjusted_severity': None,
                }
        return None

    def _check_governance_setter(self, vuln: 'Vulnerability', _code: str) -> Dict[str, Any] | None:
        """Filter governance/centralisation FPs for protected setter functions."""
        fn = self._extract_function_name(vuln)

        # If the finding is about a specific setter, check its protection
        setter_match = re.search(r'\b(set|update)\w+', (vuln.title or '') + ' ' + (vuln.location or ''), re.IGNORECASE)
        check_name = fn or (setter_match.group(0) if setter_match else None)
        if not check_name:
            return None

        if check_name in self._protected_functions:
            mods = self._protected_functions[check_name]
            access_mods = [m for m in mods if m in self.ACCESS_MODIFIERS]
            if access_mods:
                return {
                    'is_false_positive': True,
                    'reason': f'{check_name}() is governance-protected ({", ".join(access_mods)})',
                    'adjusted_severity': None,
                }

        # Also look for require-based validation inside the setter
        if check_name and self._functions_with_require.get(check_name, False):
            return {
                'is_false_positive': False,
                'reason': '',
                'adjusted_severity': 'low',  # Downgrade — has validation, not unprotected
            }
        return None

    def _check_existing_validation(self, vuln: 'Vulnerability', _code: str) -> Dict[str, Any] | None:
        """Filter input-validation FPs when the function already has require/assert."""
        fn = self._extract_function_name(vuln)
        if fn and self._functions_with_require.get(fn, False):
            # The function already has validation — downgrade rather than filter
            return {
                'is_false_positive': False,
                'reason': '',
                'adjusted_severity': 'low',
            }
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_any(text: str, keywords: List[str]) -> bool:
        return any(kw in text for kw in keywords)

    @staticmethod
    def _extract_function_name(vuln: 'Vulnerability') -> str:
        """Best-effort extraction of a function name from vuln metadata."""
        for field in [vuln.location, vuln.title, vuln.description]:
            if not field:
                continue
            m = re.search(r'\b(\w+)\s*\(', field)
            if m and m.group(1) not in ('function', 'require', 'assert', 'revert', 'emit', 'event', 'error'):
                return m.group(1)
        return ''

    @staticmethod
    def _find_brace_end(start: int, code: str) -> int:
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
            i += 1
        return i

    # ------------------------------------------------------------------
    # Additional objective checks
    # ------------------------------------------------------------------

    def _check_view_pure_impact(self, vuln: 'Vulnerability', code: str) -> Dict[str, Any] | None:
        """Filter findings claiming fund loss/reentrancy on view/pure functions."""
        fn = self._extract_function_name(vuln)
        if not fn:
            return None
        if self._view_pure_functions.get(fn, False):
            combined = f"{vuln.vulnerability_type} {vuln.description} {vuln.title}".lower()
            if self._matches_any(combined, self._STATE_IMPACT_KEYWORDS):
                return {
                    'is_false_positive': True,
                    'reason': f'{fn}() is view/pure — cannot cause state changes or fund loss',
                    'adjusted_severity': None,
                }
            # Even if not filtered, cap severity for view/pure
            if vuln.severity in (Severity.CRITICAL, Severity.HIGH):
                return {
                    'is_false_positive': False,
                    'reason': '',
                    'adjusted_severity': 'low',
                }
        return None

    def _check_admin_compromise_phrases(self, vuln: 'Vulnerability') -> Dict[str, Any] | None:
        """Filter findings whose description assumes admin key compromise."""
        combined = f"{vuln.description} {vuln.title}".lower()
        for phrase in self._ADMIN_COMPROMISE_PHRASES:
            if phrase in combined:
                return {
                    'is_false_positive': True,
                    'reason': f'admin key compromise scenario ("{phrase}")',
                    'adjusted_severity': None,
                }
        return None

    def _check_constructor_context(self, vuln: 'Vulnerability') -> Dict[str, Any] | None:
        """Filter constructor-only issues in contracts that use initializer pattern."""
        if not self._has_initializer:
            return None
        combined = f"{vuln.title} {vuln.description} {vuln.location or ''}".lower()
        # Only filter if the finding is purely about constructor behaviour
        if 'constructor' not in combined:
            return None
        # Escape: if the finding mentions runtime impact, don't filter
        runtime_hints = ['initialize', 'runtime', 'exploit', 'drain', 'after deployment']
        if any(h in combined for h in runtime_hints):
            return None
        return {
            'is_false_positive': True,
            'reason': 'constructor-only issue in initialized/proxy contract',
            'adjusted_severity': None,
        }

    def _check_immutable_constant(self, vuln: 'Vulnerability') -> Dict[str, Any] | None:
        """Filter findings claiming immutable/constant variables can be modified."""
        combined = f"{vuln.title} {vuln.description}".lower()
        if not any(kw in combined for kw in ['immutable', 'constant']):
            return None
        change_claims = [
            'can be changed', 'can be modified', 'can be updated',
            'not protected', 'mutable', 'can be set after',
        ]
        if any(kw in combined for kw in change_claims):
            return {
                'is_false_positive': True,
                'reason': 'immutable/constant variable cannot be modified at runtime',
                'adjusted_severity': None,
            }
        return None

    def _check_event_only_function(self, vuln: 'Vulnerability') -> Dict[str, Any] | None:
        """Cap severity for findings on functions that only emit events."""
        fn = self._extract_function_name(vuln)
        if not fn:
            return None
        if self._event_only_functions.get(fn, False):
            if vuln.severity in (Severity.CRITICAL, Severity.HIGH):
                return {
                    'is_false_positive': False,
                    'reason': '',
                    'adjusted_severity': 'low',
                }
        return None

    def _check_admin_centralization_title(self, vuln: 'Vulnerability') -> Dict[str, Any] | None:
        """Filter findings whose *title* frames the issue as admin-can-do-X.

        This catches the ~40% of FPs that are centralization/admin-feature
        complaints while preserving real access-control bugs.  The escape
        hatch checks whether the *description* indicates a genuine
        missing-access-control or attacker-exploitable issue.
        """
        title = (vuln.title or '').lower()
        # Does the title match an admin/centralization pattern?
        if not any(pat in title for pat in self._ADMIN_TITLE_PATTERNS):
            return None
        # Escape hatch: description signals a real access-control bug
        desc = (vuln.description or '').lower()
        if any(esc in desc for esc in self._ADMIN_TITLE_ESCAPE):
            return None
        return {
            'is_false_positive': True,
            'reason': f'admin/centralization feature complaint in title',
            'adjusted_severity': None,
        }


class BaselineRunner:
    def __init__(self, config: dict[str, Any] | None = None, inference_api: str = None):
        self.config = config or {}
        self.model = self.config['model']
        self.inference_api = inference_api or os.getenv('INFERENCE_API', "http://bitsec_proxy:8000")
        self.project_id = os.getenv('PROJECT_ID', "local")
        self.job_id = os.getenv('JOB_ID', "local")

        console.print(f"Inference: {self.inference_api}")

    def inference(self, messages: dict[str, Any], model: str = None) -> dict[str, Any]:
        payload = {
            "model": model or self.config['model'],
            "messages": messages,
            "temperature": 0.01,
            #"max_tokens": 10000,
            #"top_p": 0.95,
            #"top_k": 40,
        }
        
        retry_wait_time = 30

        headers = {
            "x_project_id": self.project_id or "local",
            "x_job_id": self.job_id,
        }

        resp = None
        
        #print(f"Inference URL: {self.inference_api}/inference")
        #print(f"Headers: {headers}")
        #print(f"Payload: {payload}")

        for attempt in range(3):
            try:
                inference_url = f"{self.inference_api}/inference"
                resp = requests.post(
                    inference_url,
                    headers=headers,
                    json=payload,
                    timeout=120,
                )
                resp.raise_for_status()
                return resp.json()

            except requests.exceptions.HTTPError as e:
                # This prevents the AttributeError when requests.post() raises a RequestException before returning
                if resp is not None:
                    try:
                        error_detail = resp.json()
                    except (ValueError, AttributeError):
                        error_detail = resp.text if hasattr(resp, 'text') else str(resp)
                else:
                    error_detail = "No response received"
                console.print(f"Inference Proxy Error: {e} {error_detail}")
                if attempt < 2:
                    console.print(f"Retrying in 30 seconds... (attempt {attempt + 1}/3)")
                    time.sleep(retry_wait_time)
                    retry_wait_time += 10
                else:
                    raise

            except requests.exceptions.RequestException as e:
                if resp is not None:
                    try:
                        error_detail = resp.json()
                    except (ValueError, AttributeError):
                        error_detail = resp.text if hasattr(resp, 'text') else str(resp)
                else:
                    error_detail = "No response received"
                console.print(f"Inference Error: {e} {error_detail}")
                if attempt < 2:
                    console.print(f"Retrying in 30 seconds... (attempt {attempt + 1}/3)")
                    time.sleep(retry_wait_time)
                    retry_wait_time += 10
                else:
                    raise

    def clean_json_response(self, response_content: str) -> dict[str, Any]:
        while response_content.startswith("_\n"):
            response_content = response_content[2:]

        response_content = response_content.strip()

        if response_content.startswith("return"):
            response_content = response_content[6:]

        response_content = response_content.strip()

        # Remove code block markers if present
        if response_content.startswith("```") and response_content.endswith("```"):
            lines = response_content.splitlines()

            if lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            response_content = "\n".join(lines).strip()

        resp_json = json.loads(response_content)

        return resp_json

    def analyze_file(self, source_dir: Path, relative_path: str, related_files_list: list[str], model: str = None, system_prompt: str = None, prompt_name: str = None, context: str = None, sleep_timeout: int = 5)  -> tuple[Vulnerabilities, int, int]:
        """Analyze a single file for security vulnerabilities.
        
        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens)
        """
        start_time = time.time()
        
        file_path = Path(relative_path)
        print("file_path: ", file_path)
        main_file_content = ""
        with open(source_dir / file_path, 'r', encoding='utf-8') as f:
            main_file_content = f.read()

        console.print(f"[dim]  → Analyzing {file_path} with model {model} and prompt {prompt_name} ({len(related_files_list)} related files)[/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        format_instructions = parser.get_format_instructions()

        system_prompt = dedent(system_prompt.format(format_instructions=format_instructions))#, examples=EXAMPLES))

        #print(system_prompt)
        
        file_content_for_user_prompt = f"""
            Main File: {file_path}
            ```{file_path.suffix[1:] if file_path.suffix else 'txt'}
            {main_file_content}
            ```
        """
        
        related_files_content_for_user_prompt = ""
        for related_file_path in related_files_list:
            try:
                related_file_path = Path(related_file_path)
                with open(related_file_path, 'r', encoding='utf-8') as f:
                    related_files_content = f.read()
                related_files_content_for_user_prompt += f"""
                    Related File: {related_file_path}
                    ```{related_file_path.suffix[1:] if related_file_path.suffix else 'txt'}
                    {related_files_content}
                    ```
                """
            except Exception as e:
                console.print(f"[red]Error reading related file {related_file_path}: {e}[/red]")
                continue
        
        user_prompt = dedent(f"""
            Analyze this {file_path.suffix} file for security vulnerabilities:

            {file_content_for_user_prompt}
            
            {related_files_content_for_user_prompt}

            Identify and report security vulnerabilities found.
        """)
        
        
        #print("user_prompt: \n", user_prompt)
        
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages, model=model)
            response_content = response['content'].strip()

            msg_json = self.clean_json_response(response_content)

            vulnerabilities = Vulnerabilities(**msg_json)
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = model + "_" + prompt_name

            if vulnerabilities:
                console.print(f"[green]  → Found {len(vulnerabilities.vulnerabilities)} vulnerabilities[/green]")
            else:
                console.print("[yellow]  → No vulnerabilities found[/yellow]")


            input_tokens = response.get('input_tokens', 0)
            output_tokens = response.get('output_tokens', 0)

            end_time = time.time()
            time_taken = end_time - start_time
            console.print(f"Time taken to analyze {file_path.name}: {time_taken} seconds")
            if sleep_timeout - time_taken > 0:
                time.sleep(sleep_timeout - time_taken) # slow down!

            return vulnerabilities, input_tokens, output_tokens
            
        except Exception as e:
            console.print(f"[red]Error analyzing {file_path.name}: {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0


    def find_files_to_analyze(self, source_dir: Path, file_patterns: list[str] | None = None) -> list[Path]:
        """Find files to analyze based on file patterns."""
        # Find files to analyze
        if file_patterns:
            files = []
            for pattern in file_patterns:
                files.extend(source_dir.glob(pattern))

        else:
            # Default to common smart contract patterns
            patterns = ['**/*.sol', '**/*.vy', '**/*.cairo', '**/*.rs', '**/*.move']
            files = []
            for pattern in patterns:
                files.extend(source_dir.glob(pattern))
        
        # Remove duplicates and filter
        exclude_dirs = {"testing", "mocks", "examples"}
        exclude_dirs = {
            'node_modules', 'test', 'tests', 'script', 'scripts', 
            'mocks', 'mock', 'interfaces', 'lib', 'libraries',
            '.git', 'artifacts', 'cache', 'out', 'dist', 'build'
        }
        files = set(files)
        files = [
            f for f 
            in files 
            if f.is_file() and 'test' not in f.name.lower()
            and not any(part.lower() in exclude_dirs for part in f.parts)
        ]
        
        filter_out_of_scope = True
        if filter_out_of_scope:
            # Read out_of_scope.txt if it exists in the source directory
            out_of_scope = set()
            out_of_scope_path = source_dir / 'out_of_scope.txt'
            if out_of_scope_path.is_file():
                try:
                    with open(out_of_scope_path, 'r', encoding='utf-8') as f:
                        out_of_scope = set(line.strip() for line in f if line.strip() and not line.strip().startswith('#'))
                except Exception as e:
                    console.print(f"[yellow]Warning: Failed to read out_of_scope.txt: {e}[/yellow]")

            #print(f"out_of_scope: {out_of_scope}")
            
            # Remove files that match any out_of_scope entry (direct match or pattern)
            def is_out_of_scope(file_path):
                rel = file_path.relative_to(source_dir)
                rel_path = f"./{rel.as_posix()}"
                #print(f"rel_path: {rel_path}")
                return (
                    rel_path in out_of_scope or
                    rel.as_posix() in out_of_scope or
                    file_path.name in out_of_scope
                )

            #print(f"files: {files}")
            files = [f for f in files if not is_out_of_scope(f)]
            #print(f"files after out of scope removed: {files}")
        
         # First: place .sol, .vy, .cairo files at the top in that order
        def ext_priority(f):
            ext = f.suffix.lower()
            if ext == '.sol':
                return (0, 0)
            if ext == '.vy':
                return (1, 0)
            if ext == '.cairo':
                return (2, 0)
            # For all others, their priority is after .sol/.vy/.cairo and by number of '/' (i.e., folder depth)
            return (3, str(f).count('/'))

        files = sorted(files, key=ext_priority)

        return files
    
    def find_related_files(self, file_path: Path, files_in_scope: list[Path], model: str = None, sleep_timeout: int = 3) -> list[Path]:
        star_time = time.time()
        """Find related files based on file path."""
        
        console.print(f"Finding related files for {file_path.name}")
        
        model = model or self.config['model']
        related_files = []
        
        content = ""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        format_instructions = """
{
    "related_files": [
        "path/to/file1",
        "path/to/file2"
    ]
}
        """
            
        user_prompt = dedent(f"""
            You are helping build context for a smart contract security audit.

Your task is to select ONLY the files that MUST or SHOULD be analyzed together
with the main file to correctly detect vulnerabilities.

============================================================
MAIN FILE (PRIMARY SUBJECT)
============================================================
Path: {file_path}
```{file_path.suffix[1:] if file_path.suffix else 'txt'}
{content}
```
============================================================
FILES IN SCOPE
============================================================
{list(map(str, files_in_scope))}

============================================================
SELECTION RULES (IMPORTANT)
============================================================

You MUST include a file IF ANY of the following are true:

1. The main file forwards execution to another file via:
   - delegatecall
   - directDelegate / dispatcher
   - fallback-based routing
   - selector / dispatch-byte logic

2. The main file is a wrapper or interface for logic implemented elsewhere
   (e.g., Solidity calling into Rust/Stylus/Vyper/Cairo).

3. The main file and another file define the SAME or CORRESPONDING function
   names, selectors, or ABI-facing entrypoints (even if parameter lists differ).

4. The main file imports another file AND that imported file:
   - defines logic (not just constants/types), OR
   - affects execution, accounting, or authorization.

You MAY include a file IF:

5. It defines shared storage, accounting variables, or core invariants
   used by the main file.

6. It defines interfaces or libraries whose behavior is essential
   to understanding value flow or settlement.

You MUST NOT include a file IF:

- It is unrelated boilerplate, config, deployment, or tests
- It does not affect execution, accounting, or security
- It is only loosely related by directory or naming
- It is the main file itself

============================================================
SPECIAL NOTE ON MIXED-LANGUAGE CODEBASES
============================================================

If the main file is Solidity and execution is forwarded to Rust/Stylus
(or another language), you MUST identify and include the target implementation
file so ABI and parameter consistency can be analyzed.

============================================================
OUTPUT FORMAT
============================================================

Return ONLY a JSON object of the form:

{format_instructions}

Do NOT include explanations.
Do NOT include the main file.
Do NOT include files unless they satisfy the rules above.""")
        
        #print("user_prompt: \n", user_prompt)
        
        try:
            messages = [
                {"role": "user", "content": user_prompt},
            ]
            response = self.inference(messages=messages, model=model)
            response_content = response['content'].strip()
            msg_json = self.clean_json_response(response_content)
            related_files = msg_json['related_files']
        except Exception as e:
            console.print(f"[red]Error finding related files: {e}[/red]")
            return []

        #print(f"Original file: {file_path.name} Related files: {related_files}")
        end_time = time.time()
        time_taken = end_time - star_time
        console.print(f"Time taken to find related files: {time_taken} seconds")
        if sleep_timeout - time_taken > 0:
            time.sleep(sleep_timeout - time_taken) # slow down!
        
        return related_files
    
    def analyze_project(
        self, 
        source_dir: Path,
        project_name: str,
        file_patterns: list[str] | None = None
    ) -> AnalysisResult:
        """Analyze a project for security vulnerabilities.
        
        Args:
            source_dir: Directory containing source files
            project_name: Name of the project
            file_patterns: List of glob patterns for files to analyze
            
        Returns:
            AnalysisResult with vulnerabilities
        """
        console.print("\n[bold cyan]Analyzing project[/bold cyan]")
            
        model = 'Qwen/Qwen3-Next-80B-A3B-Instruct'
        
        max_threads = 6
        
        # Find files to analyze
        files = self.find_files_to_analyze(source_dir, file_patterns)
        
        related_files = {}
        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = {}
            for f in files[:20]: # look at top 20 files only
                future = executor.submit(self.find_related_files, f, files, model, sleep_timeout = 100 / len(files[:20]))
                futures[future] = f
            for future in as_completed(futures):
                try:
                    related_files[futures[future]] = future.result()
                except Exception as e:
                    console.print(f"[red]Error finding related files: {e}[/red]")
        
        import random
        wait_time = random.randint(15, 25)
        time.sleep(wait_time) # just to be sure
        #console.print(f"related_files: {related_files}")

        if not files:
            console.print("[yellow]No files found to analyze[/yellow]")
            return AnalysisResult(
                project=project_name,
                timestamp=datetime.now().isoformat(),
                files_analyzed=0,
                files_skipped=0,
                total_vulnerabilities=0,
                vulnerabilities=[],
                token_usage={'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}
            )

        console.print(f"[dim]Found {len(files)} files to analyze[/dim]")

        # Analyze files
        all_vulnerabilities = []
        files_analyzed = 0
        files_skipped = 0
        total_input_tokens = 0
        total_output_tokens = 0
        
        # Read README.md from the project directory (source_dir)
        readme_path = source_dir / "README.md"
        readme_content = ""
        if readme_path.exists() and readme_path.is_file():
            try:
                with open(readme_path, "r", encoding="utf-8") as readme_file:
                    readme_content = readme_file.read()
                console.print("[dim]Loaded README.md for context[/dim]")
            except Exception as e:
                console.print(f"[yellow]Could not read README.md: {e}[/yellow]")
        else:
            console.print("[yellow]README.md file not found in project directory[/yellow]")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            console.print(f"Analyzing {len(files)} files...")

            for file_path, related_files_list in related_files.items():
                relative_path = str(file_path.relative_to(source_dir))

                console.print(f"Analyzing {relative_path}...")

                try:

                    prompts = [
                        (model, SYSTEM_1, 'system_1'),
                        (model, SYSTEM_2, 'system_2'),
                        (model, SYSTEM_3, 'system_3'),
                        (model, SYSTEM_4, 'system_4'),
                        (model, SYSTEM_5, 'system_5'),
                        (model, SYSTEM_6, 'system_6'),
                    ]
                    
                    for model, system_prompt, prompt_name in prompts:
                        future = executor.submit(self.analyze_file, source_dir, relative_path, related_files_list, model=model, system_prompt=system_prompt, prompt_name=prompt_name, context=readme_content, sleep_timeout=60*10/len(files[:20]))
                        futures.append(future)
                        
                    files_analyzed += 1

                except Exception as e:
                    console.print(f"[red]Error processing {file_path.name}: {e}[/red]")
                    files_skipped += 1
                    continue

            try:
                start_time = time.time()
                timeout_minutes = 18
                for future in as_completed(futures, timeout = timeout_minutes*60):
                    try:
                        vulnerabilities, input_tokens, output_tokens = future.result(timeout = 3 * 60)
                            
                        total_input_tokens += input_tokens
                        total_output_tokens += output_tokens
                        
                        if vulnerabilities:
                            all_vulnerabilities.extend(vulnerabilities.vulnerabilities)
                        
                        #self.save_partial_result(all_vulnerabilities, total_input_tokens, total_output_tokens, project_name, files_analyzed, files_skipped)
                        
                        if time.time() - start_time > timeout_minutes*60:
                            console.print(f"[yellow]Timeout reached ({timeout_minutes} min), continuing with {len(all_vulnerabilities)} vulnerabilities found so far[/yellow]")
                            for f in futures:
                                f.cancel()  # Cancel pending futures
                            break

                    except Exception as e:
                        console.print(f"[red]Error processing {file_path.name}: {e}[/red]")
            except TimeoutError:
                console.print(f"[yellow]Timeout reached (20 min), continuing with {len(all_vulnerabilities)} vulnerabilities found so far[/yellow]")
                for f in futures:
                    f.cancel()  # Cancel pending futures
        
        # Deduplicate vulnerabilities — two passes
        # Pass 1: exact title dedup (existing behavior)
        unique_by_id = {}
        for v in all_vulnerabilities:
            if v.id not in unique_by_id:
                unique_by_id[v.id] = v

        # Pass 2: semantic dedup — same file + function + vuln type from different prompts
        # Keep only the highest-confidence finding per semantic key
        semantic_groups: Dict[str, Vulnerability] = {}
        for v in unique_by_id.values():
            key = getattr(v, '_semantic_key', v.id)
            if key not in semantic_groups or v.confidence > semantic_groups[key].confidence:
                semantic_groups[key] = v

        vulns = list(semantic_groups.values())

        # Run validation pipeline to filter false positives
        vulns = self.validate_findings(vulns, source_dir)

        result = AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            total_vulnerabilities=len(vulns),
            vulnerabilities=vulns,
            token_usage={
                'input_tokens': total_input_tokens,
                'output_tokens': total_output_tokens,
                'total_tokens': total_input_tokens + total_output_tokens
            }
        )

        self.print_summary(result)
        
        return result

    def print_summary(self, result: AnalysisResult):
        """Print analysis summary."""
        console.print(f"\n[bold]Summary for {result.project}:[/bold]")
        console.print(f"  Files analyzed: {result.files_analyzed}")
        console.print(f"  Files skipped: {result.files_skipped}")
        console.print(f"  Total vulnerabilities: {result.total_vulnerabilities}")
        console.print(f"  Token usage: {result.token_usage['total_tokens']:,}")
        console.print(f"    Input tokens: {result.token_usage['input_tokens']:,}")
        console.print(f"    Output tokens: {result.token_usage['output_tokens']:,}")

        if result.vulnerabilities:
            # Count by severity
            severity_counts = {}
            for vulnerability in result.vulnerabilities:
                sev = vulnerability.severity
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            """
            console.print("  By severity:")
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                if sev.value in severity_counts:
                    color = {
                        Severity.CRITICAL: 'red',
                        Severity.HIGH: 'orange1',
                        Severity.MEDIUM: 'yellow',
                        Severity.LOW: 'green'
                    }[sev]
                    console.print(f"    [{color}]{sev.value.capitalize()}:[/{color}] {severity_counts[sev.value]}")
            """
    def save_result(self, result: AnalysisResult, output_file: str = "agent_report.json"):
        result_dict = result.model_dump()

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2)

        console.print(f"\n[green]Results saved to: {output_file}[/green]")
        return output_file

    def validate_findings(
        self,
        vulnerabilities: List[Vulnerability],
        source_dir: Path,
    ) -> List[Vulnerability]:
        """Run vulnerabilities through the self-contained FP filter.

        Groups vulnerabilities by file, analyses the contract code once per file,
        and filters out findings that are flagged as false positives.
        """
        if not vulnerabilities:
            return vulnerabilities

        console.print(f"\n[bold cyan]Running false-positive filter on {len(vulnerabilities)} findings...[/bold cyan]")

        fp_filter = FalsePositiveFilter()

        # Group vulnerabilities by their source file
        vulns_by_file: Dict[str, List[Vulnerability]] = {}
        for v in vulnerabilities:
            vulns_by_file.setdefault(v.file, []).append(v)

        validated = []
        filtered_count = 0

        for file_key, file_vulns in vulns_by_file.items():
            # Read the contract code for this file
            contract_code = ""
            file_path = source_dir / file_key
            if file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        contract_code = f.read()
                except Exception as e:
                    logger.warning(f"Could not read {file_path} for validation: {e}")

            # Pre-analyse the contract once for this batch
            fp_filter.analyze(contract_code)

            for vuln in file_vulns:
                try:
                    result = fp_filter.check(vuln, contract_code)
                    if result['is_false_positive']:
                        console.print(
                            f"[dim]  Filtered FP: {vuln.title} "
                            f"(reason={result['reason']})[/dim]"
                        )
                        filtered_count += 1
                    else:
                        if result.get('adjusted_severity'):
                            vuln.severity = Severity(result['adjusted_severity'])

                        # Soft confidence cap: low-confidence survivors
                        # get capped to MEDIUM (not filtered)
                        if (vuln.confidence < 0.4
                                and vuln.severity in (Severity.CRITICAL, Severity.HIGH)):
                            vuln.severity = Severity.MEDIUM

                        validated.append(vuln)
                except Exception as e:
                    logger.warning(f"Validation error for '{vuln.title}': {e}")
                    validated.append(vuln)

        console.print(
            f"[bold green]Validation complete: "
            f"{filtered_count} false positives filtered, "
            f"{len(validated)} findings remain[/bold green]"
        )
        return validated


def agent_main(project_dir: str = None, inference_api: str = None):
    config = {
        'model': "deepseek-ai/DeepSeek-V3.1-Terminus"
    }

    if not project_dir:
        project_dir = "/app/project_code"

    console.print(Panel.fit(
        "[bold cyan]SCABENCH BASELINE RUNNER[/bold cyan]\n"
        f"[dim]Model: {config['model']}[/dim]\n",
        border_style="cyan"
    ))

    try:
        start_time = time.time()
        runner = BaselineRunner(config, inference_api)

        source_dir = Path(project_dir) if project_dir else None
        if not source_dir or not source_dir.exists() or not source_dir.is_dir():
            console.print(f"[red]Error: Invalid source directory: {project_dir}[/red]")
            sys.exit(1)
        
        result = runner.analyze_project(
            source_dir=source_dir,
            project_name=project_dir,
        )
        
        output_file = runner.save_result(result)
        
        # Final summary
        console.print("\n" + ("=" * 60))
        console.print(Panel.fit(
            f"[bold green]ANALYSIS COMPLETE[/bold green]\n\n"
            f"Project: {result.project}\n"
            f"Files analyzed: {result.files_analyzed}\n"
            f"Total vulnerabilities: {result.total_vulnerabilities}\n"
            f"Results saved to: {output_file}",
            border_style="green"
        ))
        end_time = time.time()
        time_left = 19*60 - (end_time - start_time)
        
        if time_left > 0:
            time.sleep(time_left-30)

        return result.model_dump(mode="json")
        
    except ValueError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        print(traceback.print_exc())
        sys.exit(1)


if __name__ == '__main__':
    # Add project root to path for imports
    import sys
    from pathlib import Path
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    from scripts.projects import fetch_projects
    from validator.manager import SandboxManager

    SandboxManager(is_local=True)
    time.sleep(10) # wait for proxy to start
    fetch_projects()
    inference_api = 'http://localhost:8087'
    report = agent_main('projects/code4rena_secondswap_2025_02', inference_api=inference_api)
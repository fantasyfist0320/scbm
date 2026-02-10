import hashlib
import json
import os
import requests
import sys
import time
import traceback
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from textwrap import dedent


from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.panel import Panel
from concurrent.futures import ThreadPoolExecutor, as_completed


console = Console()

SYSTEM_ATTACKER = """
Your task is to perform a detailed security audit of a given smart contract. Your primary goal is to identify potential vulnerabilities, risks, and logical errors that an attacker might exploit. Assume the mindset of an attacker when analyzing the contract, focusing on how funds can be drained, state can be manipulated, or contract operations disrupted.

***Audit Methodology***
1. Attacker's Mindset
Think like an attacker attempting to exploit the contract. Focus on areas that could be manipulated for malicious purposes such as draining funds, bypassing controls, or disrupting contract operations.
2. Key Areas for Analysis
Analyze the following areas and identify vulnerabilities:
- Drainage of Funds
Can an attacker drain funds from the contract? Look for reentrancy attacks, flash loans, unauthorized calls, or any other weaknesses that could be exploited.
- AMO Protocol Integrity
Is the Automated Market Operations (AMO) protocol integrated correctly? Does it handle backward compatibility? Can attackers exploit changes or failures in this integration?
- Rebalance Logic
Does the contract handle zero-collateral markets properly? Can attackers exploit tiny collateral to manipulate the rebalance logic?
- createPair Function (Factory Contracts)
Does the createPair function handle errors appropriately? Can it be manipulated to lock or prevent further contract interactions?
- Centralization Risks
Is the contract centralized in a way that the owner could manipulate it (e.g., rug pull or unauthorized actions)?
- Order Modification
Once an order is canceled, can an attacker still modify or interact with it? Ensure that once canceled, orders can't be exploited.
- External Calls and Arbitrary Functionality
Can users make arbitrary external calls to drain or manipulate other users' funds? Look for potential attack vectors here.
- External Contract Validation
Does the contract properly validate external contract calls or callbacks? Look for missing checks or insecure integrations with oracles or other external systems.
- Slashing/Penalty Mechanisms
Are the slashing or penalty mechanisms robust? Do they properly reset or update states? Can an attacker circumvent the penalties through incomplete mechanisms?
- Asset Freezing
Can any user or attacker freeze assets or blacklist others through privileged functions, like pausing the contract, without proper access control?
- Flash Loan Attack Potential
Could an attacker use flash loans to inflate their share of the reward pool by depositing assets and quickly withdrawing them? Ensure the contract doesn't improperly calculate rewards in this scenario.

***High-Risk Vulnerability Patterns***
- Draining Funds: Look for reentrancy, flash loans, or unauthorized external calls that could drain funds.
- AMO Protocol Issues: Check for issues in integrating the AMO protocol, backward compatibility problems, or exploitable protocol changes.
- Centralization/Rug Pull Risk: Identify functions that give too much control to the owner or any centralized risks that could allow manipulation or unauthorized actions.
- createPair Function Vulnerabilities: Check if this function allows attackers to lock or manipulate the contract state, preventing further interactions.
- Zero Collateral Rebalancing Exploits: Make sure the contract doesn't allow for infinite rebalancing in markets with negligible collateral.
- Incomplete Penalty Functions: Ensure slashing or penalty mechanisms fully reset balances and states, preventing circumvention.
- External Contract Exploits: Identify any malicious external contract integrations or insufficient validation that could be exploited.

***Reporting Requirements***
For each vulnerability you identify, provide the following details:
- Exact Function(s) and Variables Involved:
Clearly specify which functions and variables are affected by the vulnerability.
- Exploit Scenario:
Describe how an attacker could exploit the vulnerability. Include a step-by-step exploit scenario if possible.
- Impact:
What happens as a result of the exploit? Who loses funds, what value is drained, or what actions are blocked?
- Confidence Level (0.0 to 1.0):
Rate your confidence in the exploit being feasible. A confidence level of 1.0 indicates a highly likely exploit, while 0.0 indicates no risk.

***Reporting Guidelines***
- High-Risk Vulnerabilities Must Be Reported:
If a vulnerability is critical, report it with a confidence level between 0.9 and 1.0.
- External Calls are High Risk:
Report vulnerabilities related to external calls (such as oracles or other contract interactions) with a confidence score of 0.9 or higher.
- Do Not Report Edge Cases:
Do not report issues that are adequately protected by guards, modifiers, or standard patterns (e.g., onlyOwner modifier).
- Focus on Security:
Avoid reporting issues unrelated to security (e.g., gas optimizations, code quality issues, or standard pattern usage).

***OUTPUT FORMAT***

Return ONLY raw valid JSON. Begin with:
{{"vulnerabilities":

{format_instructions}
"""

SYSTEM_DEVELOPER = """
Your primary role is to conduct a comprehensive vulnerability assessment of the provided smart contract code (e.g., Solidity) for potential risks, flaws, and exploitable conditions. This process involves structured auditing based on both developer-side issues (implementation errors) and user-side concerns (security, attack vectors).

***Audit Methodology***
Focus on implementation errors and coding patterns that may result in vulnerabilities. Verify the following checks:
- Approval Management
Ensure that the contract properly resets or manages approvals when tokens or assets are no longer required, used, or revoked. Improper approval management may result in stolen or stuck assets.
- Gas Consumption & Failures
Check that contract functions do not run out of gas during execution. Excessive gas consumption can make the contract fail unexpectedly or be exploited by attackers to cause DoS (Denial of Service).
- Validation of Parameters for Price Exploitation
Ensure market coordinators' inputs such as prices or slippage are validated. Exploiters could manipulate unverified inputs to steal market collateral or trigger price discrepancies.
- Factory/Deployment Functions & DoS
Analyze functions like createPair, deploy, and other factory/deployment mechanisms for Denial-of-Service (DoS) risks. Ensure they cannot be front-run, reverted, or exploited via reversible calls or unchecked external dependencies.
- Math & Calculation Logic Errors
Verify that custom math operations (e.g., sqrt, pow, div) handle edge cases (zero inputs, overflow, fixed-point numbers) correctly.
Ensure that custom math libraries or comparison functions handle packed floats, special flags, and mantissas without incorrect equality checks or silent failures.
- Proper Normalization of Mantissa and Exponent
Ensure that the mantissa and exponent are properly normalized during packed float equality comparisons. Failure to do so can lead to false negatives when comparing equivalent values that have different internal representations.
- Accurate Profit and Loss Calculations
Ensure accurate profit and loss calculations during liquidation. Incorrect calculations during liquidation could lead to users losing collateral or debts being incorrectly written off.
- State Updates for Strategies
Verify that state variables (e.g., totalStakedAmount, totalSupply) are updated when strategies are deployed or undeployed. Missing updates can cause incorrect fee calculations or incomplete state updates.
- Reentrancy & safeTransfer
Ensure that external calls (e.g., safeTransfer) are made after state updates to prevent reentrancy vulnerabilities. Attackers can exploit this to gain control over contract state before it's properly updated.
- Reward Distribution Logic
Inspect reward distribution logic to ensure it doesn't favor the first claimant or enable disproportionate allocation based on time or shares. Malicious users could siphon the entire reward pool if the system is not atomic or lacks protection.
- Handling Integer Division & Truncation
Check for instances where integer division could cause truncation, resulting in zeroed-out rewards, incorrect ratios, or other failures in contract operations.
- Sensitive Global State Variables
Ensure that global state variables (e.g., totalStakedAmount, totalSupply) cannot be illegally modified by attackers via direct ERC20 transfers or unprotected functions.
- Strategy Management Functions
Verify that tracking variables (e.g., stakeAmount, totalAssets) are consistently updated during strategy deployment/undeployment to avoid accounting errors or missed fee collections.
- Access Control & Unauthorized Extensions
Ensure that there is proper access control to prevent unauthorized users from setting themselves as operators or extensions, potentially leading to fund theft.

***High-Risk Patterns***
- Identify and report high-risk vulnerabilities based on the following patterns:
- Incorrect Approval Management
- Gas Consumption and Transaction Failures
- Directly unwrapping and comparing packed representations without normalizing for varying mantissa lengths or trailing zeros
- Denial-of-Service (DoS) in Factory/Deployment Functions
- Math/Calculation Logic Errors
- Exploitation of Price Discrepancies and Collateral Theft
- Incorrect Profit and Loss Calculation
- Lack of Access Control
- Reentrancy in External Calls (e.g., safeTransfer)

***Reporting Requirements***
For each vulnerability you identify, provide the following details:
- Exact Function(s) and Variables Involved:
Clearly specify which functions and variables are affected by the vulnerability.
- Exploit Scenario:
Describe how an attacker could exploit the vulnerability. Include a step-by-step exploit scenario if possible.
- Impact:
What happens as a result of the exploit? Who loses funds, what value is drained, or what actions are blocked?
- Confidence Level (0.0 to 1.0):
Rate your confidence in the exploit being feasible. A confidence level of 1.0 indicates a highly likely exploit, while 0.0 indicates no risk.

***Reporting Guidelines***
- High-Risk Vulnerabilities Must Be Reported:
If a vulnerability is critical, report it with a confidence level between 0.9 and 1.0.
- External Calls are High Risk:
Report vulnerabilities related to external calls (such as oracles or other contract interactions) with a confidence score of 0.9 or higher.
- Do Not Report Edge Cases:
Do not report issues that are adequately protected by guards, modifiers, or standard patterns (e.g., onlyOwner modifier).
- Focus on Security:
Avoid reporting issues unrelated to security (e.g., code quality issues, or standard pattern usage).

***OUTPUT FORMAT***

Return ONLY raw valid JSON. Begin with: {{"vulnerabilities": 
{format_instructions}
"""

SYSTEM_USER = """
Your task is to systematically audit the contract code with a focus on user experience and safety. Ensure that users can interact with the contract without unexpected financial losses, and that the contract behaves as expected during normal and edge-case scenarios.

***Audit Methodology***
- Liquidity Verification Before Refunds
Ensure that the contract verifies sufficient liquidity before issuing refunds. This prevents users from receiving incorrect or inflated refunds, protecting them from losses due to insufficient reserves.
- ERC4626 Deposit & Withdrawal Management
Verify that the custom ERC4626 contract handles deposits and returns user assets correctly. Ensure that assets are not mismanaged or lost due to faulty logic during deposit/withdrawal operations.
- Staking Transaction Verification
Ensure proper staking transaction validation to prevent inflation of exchange ratios or withdrawal issues. Inaccurate verification may lead to users losing funds or experiencing errors when staking or unstaking.
- Slippage Control During Withdrawals
Ensure that slippage control is in place for withdrawals to protect users from losses due to price fluctuations between the time of withdrawal initiation and execution. This is critical in volatile markets where price discrepancies can significantly impact the withdrawal amount.
- Handling Non-Contiguous Token IDs
When the contract lists or iterates over NFTs or tokens (e.g., using getTokenId or balanceOf loops), ensure the contract correctly handles non-contiguous or gapped token IDs. Failure to do so may result in missing tokens during iteration or inaccurate user balances due to assumptions about contiguous arrays.
- Liquidity Checks in Withdrawal/Redemption
In withdrawal or redemption functions, ensure robust liquidity checks are implemented to prevent incorrect refunds. This includes avoiding over-refunding or refunding when only partial execution is possible. Insufficient checks could lead to exploitations, such as withdrawing more than available liquidity.
- Accurate Withdrawal/Claim Matching
Verify that users can successfully unstake, withdraw, or claim rewards (including original staking tokens) in an amount that accurately reflects their initial deposit/stake. This includes ensuring that discrepancies due to rounding errors, incorrect accrual periods, or flawed share calculations are avoided.
- ERC20 Approval Mechanism Checks
In all token interactions (such as transfers, deposits, or withdrawals), verify that the ERC20 approval mechanism is properly implemented. Ensure:
Proper checks for allowance amounts.
Avoidance of infinite approvals where unnecessary.
Correct handling of approval resets to prevent front-running attacks.
- DelegateCall or Proxy Contract Risk
If the contract uses delegatecall or is structured as an upgradable proxy (e.g., OpenZeppelin UUPS or Transparent Proxy patterns), ensure that there are no risks of draining or misappropriating tokens/assets during upgrades. This includes guarding against malicious logic injection or storage slot collisions during contract upgrades.
- Liquidity Checks Before Refunds
Ensure that the contract properly checks for sufficient liquidity before issuing refunds or performing any operations that affect user balances. This ensures that users are not affected by liquidity constraints during withdrawals or other operations.
- Withdrawal & Locking Risks
Check for mistakes that could prevent users from withdrawing their assets, such as permanent locks. If a user cannot access their funds due to errors in the contract's logic (e.g., improper lock-up periods or bugs in the redemption process), the contract may lead to major user frustration and financial losses.
- Reward Claims and Lending/Borrowing Operations
During reward claims or lending/borrowing operations, ensure that the contract properly calculates rewards. Avoid issues like:
Insufficient liquidity (e.g., flash loan exploits draining pools temporarily).
Calculation errors (e.g., integer overflows/underflows in interest accrual).
Price manipulation vulnerabilities (e.g., oracle manipulation enabling over-borrowing or inflated reward payouts).
Such errors could lead to a user receiving more rewards or assets than entitled.

***High-Risk Patterns***
- Insufficient Liquidity Verification Before Refunds
- Faulty Custom ERC4626 Handling of Deposits/Withdrawals
- Invalid Staking Transaction Verification
- Lack of Slippage Control During Withdrawals
- Missing or Faulty Liquidity Checks in Withdrawal/Redemption Functions
- Non-Contiguous Token ID Handling Failures
- Issues in Unstaking, Withdrawal, or Reward Claims
- ERC20 Approval Mechanism Weaknesses
- DelegateCall/Proxy Contract Upgrade Risks
- Permanent Lock or Unaccessible Asset Issues
- Overpayment During Reward Claims or Borrowing Operations

***Reporting Requirements***
For each vulnerability you identify, provide the following details:
- Exact Function(s) and Variables Involved:
Clearly specify which functions and variables are affected by the vulnerability.
- Exploit Scenario:
Describe how an attacker could exploit the vulnerability. Include a step-by-step exploit scenario if possible.
- Impact:
What happens as a result of the exploit? Who loses funds, what value is drained, or what actions are blocked?
- Confidence Level (0.0 to 1.0):
Rate your confidence in the exploit being feasible. A confidence level of 1.0 indicates a highly likely exploit, while 0.0 indicates no risk.

***Reporting Guidelines***
- High-Risk Vulnerabilities Must Be Reported:
If a vulnerability is critical, report it with a confidence level between 0.9 and 1.0.
- External Calls are High Risk:
Report vulnerabilities related to external calls (such as oracles or other contract interactions) with a confidence score of 0.9 or higher.
- Do Not Report Edge Cases:
Do not report issues that are adequately protected by guards, modifiers, or standard patterns (e.g., onlyOwner modifier).
- Focus on Security:
Avoid reporting issues unrelated to security (e.g., gas optimizations, code quality issues, or standard pattern usage).

***OUTPUT FORMAT***

Return ONLY raw valid JSON. Begin with: {{"vulnerabilities":

{format_instructions}
"""

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

    def __init__(self, **data):
        super().__init__(**data)
        if not self.id:
            id_source = f"{self.file}:{self.title}"
            self.id = hashlib.md5(id_source.encode()).hexdigest()[:16]

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
        
        retry_wait_time = 5

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
                    console.print(f"Retrying in {retry_wait_time} seconds... (attempt {attempt + 1}/3)")
                    time.sleep(retry_wait_time)
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
                    console.print(f"Retrying in {retry_wait_time} seconds... (attempt {attempt + 1}/3)")
                    time.sleep(retry_wait_time)
                    # retry_wait_time += 10
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

    def analyze_file(self, source_dir: Path, relative_path: str, related_files_list: list[str], model: str = None, system_prompt: str = None, prompt_name: str = None)  -> tuple[Vulnerabilities, int, int]:
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
        exclude_dirs = {
            'node_modules', 'script', 'scripts', 
            'mocks', 'mock', 'interfaces', '.git', 'artifacts', 'cache', 'out', 'dist', 'build'
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
            print("Search model:", model)
            response = self.inference(messages=messages, model=model)
            response_content = response['content'].strip()
            msg_json = self.clean_json_response(response_content)
            related_files = msg_json['related_files']
        except Exception as e:
            console.print(f"[red]Error finding related files: {e}[/red]")
            return []
        
        return related_files
    
    def analyze_project(
        self, 
        source_dir: Path,
        project_name: str,
        file_patterns: list[str] | None = None
    ) -> AnalysisResult:
        console.print("\n[bold cyan]Analyzing project[/bold cyan]")
            
        model = 'Qwen/Qwen3-Next-80B-A3B-Instruct'
        
        max_threads = 6
        
        # Find files to analyze
        files = self.find_files_to_analyze(source_dir, file_patterns)
        
        related_files = {}
        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = {}
            for f in files[:20]: # look at top 20 files only
                future = executor.submit(self.find_related_files, f, files, model, sleep_timeout = 100 / len(files[:10]))
                futures[future] = f
            for future in as_completed(futures):
                try:
                    related_files[futures[future]] = future.result()
                except Exception as e:
                    console.print(f"[red]Error finding related files: {e}[/red]")
        
        # import random
        # wait_time = random.randint(15, 25)
        # time.sleep(wait_time) # just to be sure
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

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            console.print(f"Analyzing {len(files)} files...")

            for file_path, related_files_list in related_files.items():
                relative_path = str(file_path.relative_to(source_dir))

                console.print(f"Analyzing {relative_path}...")

                try:

                    prompts = [ 
                        (model, SYSTEM_ATTACKER, 'system'),
                        (model, SYSTEM_DEVELOPER, 'system'),
                        (model, SYSTEM_USER, 'system'),
                    ]
                    
                    for model, system_prompt, prompt_name in prompts:
                        future = executor.submit(self.analyze_file, source_dir, relative_path, related_files_list, model=model, system_prompt=system_prompt, prompt_name=prompt_name)
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

        # Deduplicate vulnerabilities
        unique_vulnerabilities = {
            v.id: v for v in all_vulnerabilities
        }
        vulns = list(unique_vulnerabilities.values())
        # vulns = sorted(filter(lambda x: x.confidence >= 0.9, vulns), key=lambda x: x.confidence, reverse=True)
        vulns = sorted(filter(lambda x: x.confidence >= 0.5, vulns), key=lambda x: x.confidence, reverse=True)

        result = AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            total_vulnerabilities=len(unique_vulnerabilities),
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
    report = agent_main('projects/ttt', inference_api=inference_api)
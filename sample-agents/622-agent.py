import hashlib
import json
import multiprocessing
import os
import signal
import requests
import sys
import threading
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


console = Console()

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
        
        
        # Process tracking: {process_id: {'started': bool, 'finished': bool, 'start_time': float, 'end_time': float | None, 'approach': str, 'file': str, 'process_pid': int}}
        self.process_tracking = {}
        self.process_tracking_lock = threading.Lock()

        console.print(f"Inference: {self.inference_api}")

    def inference(self, messages: dict[str, Any], model: str = None) -> dict[str, Any]:
        payload = {
            "model": "Qwen/Qwen3-30B-A3B-Instruct-2507",
            "messages": messages,
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
    
    
    def attack_analysis_approach(self, relative_path: str, content: str, model: str, timeout_seconds: float | None = None, start_time: float | None = None) -> tuple[Vulnerabilities, int, int]:
        """Perform audit using attack flow analysis approach.
        
        Focuses on understanding fund flows, automatic function triggers, withdrawal/deposit
        interactions, and how external calls can trigger unintended behavior.
        
        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens)
        """
        
        file_path = Path(relative_path)

        console.print(f"[dim]Analyzing file (attack analysis approach): {relative_path} (size: {len(content)} bytes)[/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        format_instructions = parser.get_format_instructions()

        system_prompt = dedent(f"""
            You are an EXPERT smart contract security auditor specializing in DeFi protocols.
            Your expertise lies in identifying vulnerabilities through attack flow analysis - understanding
            how funds move through the system, how automatic functions are triggered, and how normal
            protocol operations can be exploited.

            === ATTACK FLOW ANALYSIS METHODOLOGY ===
            
            Analyze contracts by tracing complete attack flows and operational sequences. Focus on
            understanding the full lifecycle of operations, especially:
            
            1. **Fund Flow Analysis**: Trace how tokens/native currency move through the system
            2. **Automatic Function Triggers**: Identify when default currency handlers or other automatic
               entry points are invoked
            3. **Withdrawal/Deposit Interactions**: Understand complete withdrawal and deposit flows
            4. **State Transitions**: Track how state changes during multi-step operations
            5. **External Call Interactions**: Identify how external contracts can trigger unintended behavior
            
            === CRITICAL ANALYSIS POINTS ===
            
            **1. Automatic Function Triggers**
            
            When contracts have default entry points for receiving native currency transfers, analyze:
            - What happens when native tokens are sent to the contract?
            - Are there checks on the caller identity or transaction origin before executing operations?
            - Can funds meant for withdrawals be subjected to unintended operations?
            
            **1b. Signature-Based Operations**
            
            When operations use signatures for authorization, analyze:
            - What data is included in the signed message?
            - Is the transaction submitter identity included in the signature?
            - Can someone other than the intended submitter execute the signed operation?
            - Does the signature bind to execution context (value transferred, other parameters)?
            - Can the same signature be submitted by different parties with different contexts?
            
            **2. Complete Withdrawal Flow Analysis**
            
            Trace the complete withdrawal process:
            - User requests withdrawal → funds locked → operator processes → funds returned
            - Where do funds go at each step?
            - Are funds held in the contract for user collection, or processed differently?
            - What happens if funds are sent to the contract during withdrawal processing?
            - Can withdrawal funds be mixed with new deposits?
            
            **2b. Silent Failure Analysis**
            
            For operations with error handling that allows continuation:
            - Identify operations where failures don't cause reverts
            - What happens if an external call or subcall fails?
            - Is state committed before verifying the operation succeeded?
            - Can an operation partially complete (some steps succeed, others fail)?
            - Are success conditions properly verified before state commitments?
            
            **3. Deposit and Stake Flow Analysis**
            
            Trace deposit/stake operations:
            - How are funds received and processed?
            - Are there automatic staking mechanisms?
            - Can funds from different sources (users vs. system) be distinguished?
            - What happens if funds arrive unexpectedly?
            
            **4. Multi-Step Operation State Tracking**
            
            For operations that span multiple transactions:
            - Track state at each step
            - Identify what happens if operations are interrupted
            - Check if intermediate states can be exploited
            - Verify that funds are properly held during pending operations
            
            **5. External System Interactions**
            
            When contracts interact with external systems:
            - How are funds sent to external systems?
            - How are funds returned from external systems?
            - What triggers automatic functions when funds are returned?
            - Can returned funds be distinguished from new deposits?
            
            For external calls and subcalls:
            - What happens if the call fails or runs out of resources?
            - Does the function revert on call failure, or continue execution?
            - Is state modified before verifying the call succeeded?
            - Can an attacker control conditions that cause the call to fail?
            
            **6. Buffer and Reserve Management**
            
            For systems with buffers or reserves:
            - How are buffers filled and emptied?
            - Can withdrawal funds be incorrectly added to buffers?
            - Are buffers properly isolated from withdrawal funds?
            
            === SYSTEMATIC ATTACK FLOW CHECKLIST ===
            
            For each contract, systematically analyze:
            
            **Step 1: Identify Automatic Functions and Signature Operations**
            - Does the contract have default entry points for receiving native currency?
            - What operations do these default handlers perform?
            - Do they verify the caller identity or transaction origin before executing?
            - Can they be triggered by system operations (withdrawals, rewards, external returns)?
            
            For signature-based operations:
            - What operations can be triggered by providing a signature?
            - Is there verification that the transaction submitter is authorized?
            - What data is included in the signed digest?
            - Can execution context differ between signer's intent and actual execution?
            
            **Step 2: Trace Withdrawal Flows and Operation Completion**
            - Map the complete withdrawal process from request to completion
            - Identify where funds are held during processing
            - Check if funds can be diverted or processed through unintended paths during the flow
            - Verify that withdrawal funds are isolated from new deposits
            
            For operations with external calls:
            - Identify operations that don't revert on call failure
            - Check when state commitments (nonces, signatures, etc.) are made
            - Verify operation success before committing state
            - Consider: Can the call fail while high-level function succeeds?
            
            **Step 3: Trace Deposit/Stake Flows**
            - Map how deposits are received and processed
            - Identify automatic staking mechanisms
            - Check if funds from different sources are properly distinguished
            - Verify that system-returned funds are handled appropriately based on their origin
            
            **Step 4: Analyze State Transitions**
            - Track state changes during multi-step operations
            - Identify vulnerable intermediate states
            - Check if operations can be interrupted or exploited mid-flow
            
            **Step 5: External Interaction Analysis**
            - Map how funds are sent to external systems
            - Map how funds are returned from external systems
            - Identify automatic triggers when funds are returned
            - Verify that returned funds are handled correctly
            
            **Step 6: Buffer and Accounting Analysis**
            - Understand buffer management logic
            - Check if withdrawal funds can incorrectly affect buffers
            - Verify accounting consistency during fund flows
            
            === VULNERABILITY PATTERNS TO IDENTIFY ===
            
            **Pattern 1: Automatic Processing of Withdrawal Funds**
            - Default currency handlers automatically invoke deposit or investment operations
            - Withdrawal funds returned from external systems trigger automatic investment mechanisms
            - Users cannot collect withdrawals because funds are immediately processed through unintended paths
            - Impact: Users cannot withdraw, exchange ratio inflation
            
            **Pattern 2: Mixed Fund Sources**
            - Contract cannot distinguish between user deposits and system-returned funds
            - Withdrawal funds are treated as new deposits
            - Accounting becomes incorrect (total deposits increase without actual user deposits)
            
            **Pattern 3: Missing Caller Verification in Operations**
            - Default currency handlers don't verify caller identity or transaction origin
            - System addresses can trigger user-facing operations
            - Funds meant for withdrawals trigger deposit logic
            - Signature-based operations lack submitter identity verification
            - Anyone with a valid signature can submit the transaction
            
            **Pattern 4: Incomplete Withdrawal Flow**
            - Withdrawal requests are processed but funds are not held for collection
            - Funds are immediately processed through unintended paths
            - Withdrawal confirmation operations fail due to insufficient balance
            
            **Pattern 5: State Desynchronization During Flows**
            - State variables updated at different points in multi-step operations
            - Intermediate states allow exploitation
            - Funds can be extracted during vulnerable intermediate states
            
            **Pattern 6: State Commitment Before Operation Verification**
            - Operations modify state (consume nonces, signatures, allowances) before verifying completion
            - External calls or subcalls can fail after state commitment
            - Function has error handling that allows continuation without revert
            - Attacker can trigger call failures through controlled conditions
            - Impact: State consumed but intended operation never executes
            
            **Pattern 7: Authorization Bypass in Funds Destination Determination**
            - Functions allow multiple entities to call, but destination determination doesn't account for caller identity
            - Access control allows multiple entities, but destination logic doesn't restrict who receives funds
            - Impact: One entity can bypass restrictions and claim funds meant for another
            
            **Pattern 8: Missing State Reset in Reduction-Triggered Flows**
            - Operations reduce state values, then trigger dependent operations that read the state
            - State is not set to final intended value before dependent function reads it
            - Dependent function reads stale state value, allowing incorrect calculations
            - Impact: Values that should be lost can be recovered or incorrectly calculated
            
            **Pattern 9: Return Value Unit Mismatch**
            - Functions implementing interfaces or overriding base functions return values in wrong units
            - Callers expect one unit but receive another
            - Return values are used in calculations assuming different units, causing accounting errors
            - Impact: Incorrect calculations lead to fund loss, asset locking, or accounting inconsistencies
            
            **Pattern 7: Signature Scheme Incompleteness**
            - Signed data doesn't include all relevant execution context
            - Transaction submitter identity not included in signed message
            - Execution parameters not bound to signature
            - Same signature can be submitted by different parties or with different contexts
            - Impact: Unauthorized execution, transaction ordering attacks, context manipulation
            
            **Pattern 8: Authorization Bypass in Funds Destination Determination**
            - Functions that allow multiple entities to call (original entity and authorized entity)
              allow multiple entities to call
            - Destination determination doesn't properly enforce authorization restrictions when original entity calls
            - Access control allows multiple entities, but destination logic doesn't prevent original entity
              from claiming funds that should go to authorized entity
            - Impact: Original entity can bypass authorization restrictions and claim funds meant for authorized entity
            
            **Pattern 9: Missing State Reset in Reduction-Triggered Flows**
            - Operations reduce state values (balances, amounts, etc.) potentially to zero
            - Then trigger dependent operations (withdrawals, unstaking, transfers, etc.)
            - State is not explicitly set to final intended value (often zero) before dependent function reads it
            - Dependent function reads stale state value, allowing recovery or incorrect calculation
              of values that should have been lost or modified
            - Impact: Parties can recover or incorrectly calculate values that should have been permanently lost or modified
            
            **Pattern 10: State Commitment Before Operation Verification**
            - Operations modify state (consume nonces, signatures, allowances) before verifying completion
            - External calls or subcalls can fail after state commitment
            - Function has error handling that allows continuation without revert
            - Attacker can trigger call failures through controlled conditions
            - Impact: State consumed but intended operation never executes
            
            === VERIFICATION REQUIREMENTS ===
            
            For each vulnerability you identify, you must provide:
            
            1. **Complete Attack Flow** - Step-by-step description of the entire flow:
               - Initial state
               - Each transaction/operation
               - State at each step
               - Final outcome
            
            2. **Mathematical Proof** - Show exact calculations with specific numbers:
               - Initial balances
               - Amounts at each step
               - Final balances
               - Demonstrate the financial impact with arithmetic
            
            3. **Exact Location** - Specify:
               - Function names and line numbers
               - Specific variables involved
               - Automatic functions that trigger the issue
            
            4. **Exploitation Scenario** - Describe:
               - Normal protocol operation that triggers the bug
               - Or concrete attack steps
               - Who loses funds and how much
            
            5. **Financial Impact** - Clearly state:
               - Who loses funds
               - How much is lost
               - Where funds go (or if permanently locked)
               - Effect on exchange rates or accounting
            
            === WHAT NOT TO REPORT ===
            
            Do not report theoretical issues without concrete flow analysis. Do not report
            edge cases that are properly handled. Focus only on vulnerabilities with clear,
            demonstrable attack flows that lead to financial loss.
            
            === CONFIDENCE ASSESSMENT ===
            
            **Very High Confidence (0.95-1.0)**: Clear attack flows with concrete proof:
            - Automatic handlers that unconditionally trigger operations
            - Complete withdrawal flows that fail due to automatic processing through unintended paths
            - Mathematical proof showing exact fund movements
            
            **High Confidence (0.85-0.94)**: Demonstrated attack flows:
            - Automatic handlers with missing caller verification
            - Withdrawal flows that process funds through unintended paths
            - State desynchronization during multi-step operations
            
            **Medium-High Confidence (0.75-0.84)**: Likely issues with reasonable flows:
            - Complex interactions that may cause problems
            - Edge cases in fund flow handling
            
            For HIGH or CRITICAL severity findings, you must have confidence >= 0.80.

            {format_instructions}

            IMPORTANT: Begin your response with `{{"vulnerabilities":`
        """)

        user_prompt = dedent(f"""
            Analyze this {file_path.suffix} file for HIGH-SEVERITY security vulnerabilities using attack flow analysis:

            File: {relative_path}
            ```{file_path.suffix[1:] if file_path.suffix else 'txt'}
            {content}
            ```

            **STEP 1: Identify Automatic Functions**
            - Find all default entry points for receiving native currency transfers
            - What operations do these handlers perform?
            - Do they verify caller identity or transaction origin before executing?
            - Can they be triggered by system operations (withdrawals, external system returns)?
            
            **STEP 2: Trace Complete Withdrawal Flows**
            - Map: User requests withdrawal → funds locked → operator processes → funds returned → user collects
            - Where are funds held at each step?
            - Can funds be diverted or processed through unintended paths during the flow?
            - What happens if funds are sent to the contract during withdrawal processing?
            
            **STEP 3: Trace Deposit/Investment Flows**
            - Map: User sends funds → contract receives → funds processed
            - Are there automatic investment or deposit mechanisms?
            - Can funds from different sources (users vs. system) be distinguished?
            
            **STEP 4: Analyze External Interactions**
            - How are funds sent to external systems (validators, bridges, other contracts)?
            - How are funds returned from external systems?
            - What triggers automatic handlers when funds are returned?
            - Can returned funds be distinguished from new deposits?
            
            **STEP 5: Check for Vulnerability Patterns**
            - Pattern 1: Automatic processing of withdrawal funds through unintended paths
            - Pattern 2: Mixed fund sources (can't distinguish user deposits from system returns)
            - Pattern 3: Missing caller verification in automatic handlers or signature operations
            - Pattern 4: Incomplete withdrawal flows (funds not held for collection)
            - Pattern 5: State desynchronization during multi-step operations
            - Pattern 6: State commitment before operation verification (silent failures consume state)
            - Pattern 7: Signature scheme incompleteness (missing submitter identity or execution context)
            - Pattern 8: Authorization bypass in funds destination determination (original entity can claim funds meant for authorized entity)
            - Pattern 9: State update ordering in function chains (dependent functions reading stale state)
            - Pattern 10: Return value unit mismatch (functions return wrong units causing accounting errors)
            
            For Pattern 8 (Authorization Bypass):
            - Look for functions that allow multiple entities to call
            - Verify destination determination accounts for caller identity
            
            For Pattern 9 (Missing State Reset):
            - Look for operations that reduce state values and trigger dependent operations
            - Verify state is set to final intended value BEFORE dependent function reads it
            
            For Pattern 10 (Return Value Unit Mismatch):
            - Look for functions implementing interfaces or overriding base functions
            - Verify return values use expected units when used by callers in calculations
            - Check if functions return one unit when another is expected
            
            For each vulnerability found:
            - Provide complete attack flow (step-by-step)
            - Show mathematical proof with specific numbers
            - Identify exact function names and locations
            - Describe exploitation scenario
            - Calculate financial impact
            
            Only report findings with confidence >= 0.7 for HIGH/CRITICAL severity.
        """)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages, model=model)
            response_content = response['content'].strip()

            msg_json = self.clean_json_response(response_content)
            
            vulnerabilities = Vulnerabilities(**msg_json)
            
            # Filter vulnerabilities by confidence and severity
            filtered_vulns = []
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = model
                
                # Strict filtering: HIGH/CRITICAL must have confidence >= 0.80
                if v.severity in [Severity.HIGH, Severity.CRITICAL]:
                    if v.confidence >= 0.80:
                        filtered_vulns.append(v)
                    else:
                        console.print(f"[dim]Filtered out {v.severity} with low confidence {v.confidence:.2f}: {v.title}[/dim]")
                else:
                    # MEDIUM/LOW can have lower confidence
                    if v.confidence >= 0.65:
                        filtered_vulns.append(v)

            vulnerabilities.vulnerabilities = filtered_vulns

            input_tokens = response.get('input_tokens', 0)
            output_tokens = response.get('output_tokens', 0)

            if vulnerabilities.vulnerabilities:
                console.print(f"[dim]Found {len(vulnerabilities.vulnerabilities)} vulnerabilities in {relative_path} (attack analysis approach)[/dim]")
                for vuln in vulnerabilities.vulnerabilities:
                    console.print(f"[dim]  - [{vuln.severity.value.upper()}] {vuln.title} (confidence: {vuln.confidence:.2f})[/dim]")
                    console.print(f"[dim]    Location: {vuln.location}[/dim]")
                    console.print(f"[dim]    Type: {vuln.vulnerability_type}[/dim]")
            else:
                console.print(f"[dim]No vulnerabilities found in {relative_path} (attack analysis approach)[/dim]")

            console.print(f"[dim]Token usage - Input: {input_tokens}, Output: {output_tokens}[/dim]")

            return vulnerabilities, input_tokens, output_tokens
            
        except TimeoutError as e:
            console.print(f"[yellow]Timeout in attack analysis approach for {file_path.name}: {e}[/yellow]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except requests.exceptions.ReadTimeout as e:
            console.print(f"[yellow]Read timeout in attack analysis approach for {file_path.name}: {e}[/yellow]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except Exception as e:
            console.print(f"[red]Error analyzing {file_path.name} (attack analysis approach): {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0

    def boundary_consistency_approach(self, relative_path: str, content: str, model: str, timeout_seconds: float | None = None, start_time: float | None = None) -> tuple[Vulnerabilities, int, int]:
        """
        Perform audit using boundary consistency verification approach.
        """
        file_path = Path(relative_path)

        console.print(f"[dim]Analyzing file (boundary consistency approach): {relative_path} (size: {len(content)} bytes)[/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        format_instructions = parser.get_format_instructions()

        system_prompt = dedent(f"""
            You are an EXPERT smart contract security auditor specializing in DeFi protocols.
            Your expertise lies in identifying vulnerabilities related to boundary consistency:
            access control boundaries, representation boundaries, and data structure boundaries.

            === BOUNDARY CONSISTENCY VERIFICATION ===
            
            Analyze contracts systematically focusing on consistency and integrity at system boundaries:

            **Boundary 1: Access Control Boundaries**
            
            Functions that update state variables used in economic calculations (fees, rewards, interest,
            accounting) must have appropriate access control. If such functions lack access control, users can
            manipulate the timing or values of these updates to avoid fees or gain unfair advantages.
            
            **Systematic verification process**:
            
            1. Identify functions that update state variables used in economic calculations:
               - Balance tracking and snapshots
               - Position and accounting state variables
               - Any state that is read by fee or reward calculation logic

            2. Check access control: Are these update functions properly restricted?

            3. Identify the economic impact: What operations read these state variables? How are they
               used in calculations? What happens if values can be manipulated at critical times?

            4. When identifying such issues, explain:
               - The state manipulation mechanism
               - The timing requirements
               - The resulting economic impact
            
            **Boundary 2: Representation Boundaries**
            
            Functions that implement interfaces or are called by other functions must return values in the
            correct units. Units encompass both semantic meaning and numeric scaling. When systems use
            internal representations that differ from external representations, conversions must occur at
            function boundaries.
            
            **Systematic unit verification process**: For each function that implements an interface or is called
            by other functions, perform this verification:
            
            1. Identify what representation the function uses internally:
               - Check what it reads from state
               - Check what calculations it performs
               - Check what external calls it makes
               - Determine: raw values, normalized values, or converted values?
            
            2. Identify what representation the function returns:
               - Check if it returns raw values, normalized values, or values after conversion
               - Check if conversions occur before returning
            
            3. Identify what representation callers expect:
               - Check how callers use the return value
               - Do they pass it to share calculations? What representation do those expect?
               - Do they pass it to external protocols? What representation do those expect?
               - Do they pass it to oracles or swaps? What representation do those expect?
            
            4. Verify conversions occur when crossing boundaries:
               - If a function returns values in one representation but callers expect another, the function
                 must convert before returning
               - If a function receives values in one representation but needs another for internal operations,
                 it must convert upon receipt
            
            5. Pay particular attention to:
               - Functions that return amounts used in share/asset calculations (must match the representation
                 used in those calculations)
               - Functions that receive normalized amounts but call external protocols (must convert to
                 protocol's expected representation)
               - Functions that receive amounts from one source and pass to another expecting different
                 representation (must convert at the boundary)
            
            When identifying unit mismatches, trace the full call chain:
            - Identify the function that returns a value and what unit it returns
            - Identify which functions consume that value and what unit they expect
            - Identify the specific calculations that become incorrect
            - Explain the cascading effects: which operation fails first, what other operations depend on it,
              and how the failure propagates through the system
            - For each affected function, state what representation it receives, what it expects, and what
              operations fail as a result
            
            **Boundary 3: Data Access and Collection Integrity**

            For functions that access collections or indexed data, verify iteration mechanisms properly
            access all intended elements. Data structures may have assumptions about continuity,
            ordering, or completeness that can be violated.

            **Systematic data access analysis**:

            1. Identify access patterns:
               - How does the function determine which elements to process?
               - What assumptions are made about the collection structure?

            2. Understand data structure:
               - Where is the actual data stored?
               - How is it indexed or accessed?

            3. Verify coverage and assumptions:
               - Does the access mechanism reach all intended data?
               - What happens when collection structure changes during or between operations?
            
            4. Check synchronization:
               - Do loop bounds stay synchronized with data modifications?
               - What operations modify the iteration bound?
               - What operations modify the data storage?
               - Can these become desynchronized?
            
            For loops that iterate based on a counter or size variable:
            - Where does this iteration bound come from?
            - Is it maintained independently from the data storage?
            - What operations modify this iteration bound?
            - What operations modify the data storage?
            - Can these become desynchronized?
            
            For loops that access data using indices or identifiers:
            - Are identifiers assumed to be contiguous?
            - Can data persist after the bound is decreased?
            - Does the loop cover all valid identifiers in the data structure?
            
            Edge cases for iteration:
            - What happens with empty collections or when all items are removed?
            - What happens when the iteration bound is decreased but data persists?
            - Can iteration miss valid data due to desynchronization between bounds and storage?
            - Do loops handle boundary conditions correctly (zero items, maximum items, gaps in sequences)?
            - Model scenarios where items are added and removed: Does iteration still access all valid data?

            === VERIFICATION REQUIREMENTS ===
            
            For each vulnerability you identify, you must provide:
            
            1. **Mathematical proof with specific numbers** - Show the exact calculations that
               demonstrate the bug using realistic values. Prove the financial impact with arithmetic.
            
            2. **Exact location** - Specify the function name and relevant lines, along with
               the specific variables involved.
            
            3. **Exploitation scenario** - Describe concrete steps an attacker would take, or
               explain how normal protocol usage would trigger the loss. For access control issues,
               explain the timing attack or manipulation strategy. For unit mismatches, trace the
               full call chain showing function relationships and failures. For iteration issues,
               describe the desynchronization scenario.
            
            4. **Financial impact** - Clearly state who loses funds, how much, and where the
               funds go (or if they're permanently lost). For economic manipulation issues, explain
               what advantage is gained and by whom.
            
            5. **Complete vulnerability description** - Your description should include:
               - The root cause (missing modifier, wrong units, desynchronized bounds, etc.)
               - The mechanism (how it can be exploited or why it fails)
               - The impact (economic loss, fee avoidance, broken invariants, system failure)
               - The affected functions and their relationships

            === CONFIDENCE ASSESSMENT ===
            
            Assess your confidence based on the clarity and demonstrability of the vulnerability:
            
            **Very High Confidence (0.95-1.0)**: Clear, demonstrable errors with concrete proof:
            - Missing access control on functions updating economic state
            - Obvious unit mismatches with clear call chain evidence
            - Desynchronized loop bounds with demonstrable data loss
            
            **High Confidence (0.85-0.94)**: Demonstrated vulnerabilities with clear exploitation scenarios:
            - Access control issues with clear timing manipulation paths
            - Unit mismatches with traceable call chains
            - Iteration issues with specific desynchronization scenarios
            
            **Medium-High Confidence (0.75-0.84)**: Likely issues with reasonable exploit paths:
            - Potential access control gaps requiring specific conditions
            - Potential unit mismatches requiring further verification
            - Potential iteration issues requiring specific state sequences
            
            For HIGH or CRITICAL severity findings, you must have confidence >= 0.80. Ensure you
            can provide concrete mathematical proof, specific exploitation scenarios, or clear
            demonstrations of the vulnerability.

            Focus on vulnerabilities that lead to direct loss of funds, permanent locking of assets,
            protocol insolvency, theft of user funds, and so on that prevents
            core protocol functionality.

            {format_instructions}

            IMPORTANT: Begin your response with `{{"vulnerabilities":`
        """)

        user_prompt = dedent(f"""
            Analyze this {file_path.suffix} file for HIGH-SEVERITY security vulnerabilities focusing on
            boundary consistency verification:

            File: {relative_path}
            ```{file_path.suffix[1:] if file_path.suffix else 'txt'}
            {content}
            ```

            **Boundary 1: Access Control Boundaries**
            
            Check functions that update state used in economic calculations:
            - Balance snapshots, deployed amounts, position tracking variables
            - Any state read by fee calculation logic
            - Verify these update functions have appropriate access control
            - If publicly callable, explain how users can manipulate them before admin operations
            - Describe what action users take, what timing enables it, what state changes occur,
              and what economic outcome results (how fee calculations are affected and who benefits)
            
            **Boundary 2: Representation Boundaries**
            
            For each function implementing interfaces or called by others:
            - Identify what representation the function uses internally (from state, calculations, external calls)
            - Identify what representation the function returns (raw, normalized, converted)
            - Identify what representation callers expect (check how return values are used - share calculations,
              external protocols, oracles, swaps - and what those expect)
            - Verify conversions occur when crossing boundaries
            - Check: functions returning amounts for share/asset calculations, functions receiving normalized
              amounts but calling external protocols, functions bridging between different representations
            
            When reporting: Trace the call chain showing what units are returned, what units are expected,
            which specific calculations fail, and describe the propagation of failures through dependent operations.
            For each affected function, state what representation it receives, expects, and what operations fail.
            
            **Boundary 3: Data Access and Collection Integrity**

            For functions that access collections or indexed data:
            - Identify how functions determine which elements to access
            - Understand data structure: where is data stored? How is it indexed/accessed?
            - Verify the access mechanism reaches all intended data elements
            - Check assumptions about collection properties (size, continuity, ordering)
            - Model scenarios: add items, remove items, then access. Does access still reach all valid data?
            - Consider what happens when collection structure changes during or between operations
            - Edge cases: empty collections, structural changes, gaps in sequences
            
            For each vulnerability you identify:
            - Provide concrete numbers showing the exact calculations
            - Demonstrate the mathematical proof step-by-step
            - Explain the exploitation or loss scenario with structural completeness:
              * What actions can be taken
              * What conditions or timing enables them
              * What operations or calculations break
              * What outcomes result (who gains/loses what)
            - Clearly show the financial impact with arithmetic
            - Describe the complete mechanism linking cause to effect
            
            Only report findings with confidence >= 0.7 for HIGH/CRITICAL severity.
        """)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages, model=model)
            response_content = response['content'].strip()

            msg_json = self.clean_json_response(response_content)
            
            vulnerabilities = Vulnerabilities(**msg_json)
            
            # Filter vulnerabilities by confidence and severity
            filtered_vulns = []
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = model
                
                # Strict filtering: HIGH/CRITICAL must have confidence >= 0.80
                if v.severity in [Severity.HIGH, Severity.CRITICAL]:
                    if v.confidence >= 0.80:
                        filtered_vulns.append(v)
                    else:
                        console.print(f"[dim]Filtered out {v.severity} with low confidence {v.confidence:.2f}: {v.title}[/dim]")
                else:
                    # MEDIUM/LOW can have lower confidence
                    if v.confidence >= 0.65:
                        filtered_vulns.append(v)

            vulnerabilities.vulnerabilities = filtered_vulns

            input_tokens = response.get('input_tokens', 0)
            output_tokens = response.get('output_tokens', 0)

            if vulnerabilities.vulnerabilities:
                console.print(f"[dim]Found {len(vulnerabilities.vulnerabilities)} vulnerabilities in {relative_path} (boundary consistency approach)[/dim]")
                for vuln in vulnerabilities.vulnerabilities:
                    console.print(f"[dim]  - [{vuln.severity.value.upper()}] {vuln.title} (confidence: {vuln.confidence:.2f})[/dim]")
                    console.print(f"[dim]    Location: {vuln.location}[/dim]")
                    console.print(f"[dim]    Type: {vuln.vulnerability_type}[/dim]")
            else:
                console.print(f"[dim]No vulnerabilities found in {relative_path} (boundary consistency approach)[/dim]")

            console.print(f"[dim]Token usage - Input: {input_tokens}, Output: {output_tokens}[/dim]")

            return vulnerabilities, input_tokens, output_tokens
            
        except TimeoutError as e:
            console.print(f"[yellow]Timeout in boundary consistency approach for {file_path.name}: {e}[/yellow]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except requests.exceptions.ReadTimeout as e:
            console.print(f"[yellow]Read timeout in boundary consistency approach for {file_path.name}: {e}[/yellow]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except Exception as e:
            console.print(f"[red]Error analyzing {file_path.name} (boundary consistency approach): {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0

    def audit_dimensions_approach(self, relative_path: str, content: str, model: str, timeout_seconds: float | None = None, start_time: float | None = None) -> tuple[Vulnerabilities, int, int]:
        """Perform audit using dimensions-based approach.
        
        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens)
        """
        
        file_path = Path(relative_path)

        console.print(f"[dim]Analyzing file (dimensions approach): {relative_path} (size: {len(content)} bytes)[/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        format_instructions = parser.get_format_instructions()

        system_prompt = dedent(f"""
            You are an EXPERT smart contract security auditor specializing in DeFi protocols.
            Your expertise lies in identifying subtle mathematical and logical errors that lead to 
            loss of funds, protocol insolvency, or theft of user assets.

            **Systematic Verification Checklist**
            
            For each function, systematically verify across all dimensions:
            
            Access Control and Authorization:
            1. Are critical operations appropriately restricted?
            
            Input Validation and Parameter Checking:
            2. Are all parameters validated for correctness, bounds, and expected ranges?
            3. Do execution functions validate parameters against computed values when applicable?
            4. Are correct variables and parameters used in calculations?
            
            State Management and Consistency:
            5. Do related state variables update together and remain synchronized?
            6. Are conditional state updates applied consistently?
            7. When state is read for computation, can the read value represent a different logical
               context than the computation requires? When values are recomputed, does the formula account
               for all relevant historical state changes?
            8. Are critical state commitments (that prevent replay) made before operations that could fail?
            
            Mathematical Operations and Precision:
            8. Can division operations round to zero? How are results used?
            
            Control Flow and Logic:
            9. Are independent conditions handled separately, not as mutually exclusive?
            10. Do return values match expected types and units?
            11. **Unit consistency in return values**: When functions implement interfaces or are called by other
                functions, verify return values use the correct units. Functions may return values in different
                units than what callers expect.
                If a function is expected to return one unit but returns another, calculations using that
                return value will be incorrect, leading to accounting errors and potential fund loss.
            
            **Access control and funds destination determination**: When functions allow multiple entities to call,
            verify destination determination accounts for caller identity. Access control may allow multiple entities,
            but destination logic must properly restrict who receives funds based on who calls.
            
            External Interactions and Dependencies:
            11. Are appropriate checks performed before creating or interacting with external resources?
            12. Are cross-contract interactions correctly implemented?
            
            Edge Cases and Boundary Conditions:
            13. What happens with zero values, maximum values, empty collections, initial/final states,
                partial processing, concurrent executions, state transitions, time boundaries, overflow/underflow,
                or when multiple conditions are true simultaneously?
            14. For operations with external calls: What happens if the call fails due to insufficient
                resources? Are state commitments made before or after verifying successful completion?

            === YOUR SYSTEMATIC AUDITING APPROACH ===
            
            As you analyze each contract, systematically examine every function through multiple
            security dimensions. The most dangerous bugs are often hidden in the details of how
            functions manage state, validate inputs, perform calculations, and interact with external
            systems.
            
            **Audit Dimension 1: Access Control and Authorization**
            
            Verify that functions performing critical operations have appropriate access restrictions.
            Functions that modify protocol state, change balances, deploy contracts, execute trades,
            or alter protocol parameters should have access control modifiers unless they are
            intentionally public for specific use cases. Public functions performing critical operations
            without restrictions allow unauthorized manipulation of protocol state, breaking invariants
            and so on.
            
            Pay special attention to functions that update state variables used in economic calculations
            (fees, rewards, interest, accounting). If such functions lack access control, users can
            manipulate the timing or values of these updates to avoid fees or gain unfair advantages.
            
            **Audit Dimension 2: Input Validation and Parameter Checking**
            
            Functions must validate all input parameters for correctness, bounds, and expected ranges.
            Control parameters, flags, and direction indicators must contain only valid expected values.
            
            When functions receive parameters that should match values computed by other functions,
            verify that the execution function validates these parameters against the computed values.
            Missing validation allows parameter injection attacks that can break protocol invariants.
            
            Verify that functions use the correct variables and parameters. Functions accepting multiple
            input types must properly distinguish between different sources of value. Calculations must
            include all relevant components, not just base amounts.
            
            When functions determine parameters for external system interaction by comparing addresses or
            values to constants, verify the parameter is determined by querying the external system's actual
            structure rather than assuming fixed relationships. External systems may organize entities according
            to deterministic rules that differ from assumed relationships.
            
            **Audit Dimension 3: State Management and Consistency**
            
            When multiple state variables track aspects of the same underlying state, they must remain
            synchronized. Identify all state variables updated in each function and determine which
            are related. If one variable updates conditionally based on a calculation result, but
            another related variable always updates, they will desynchronize when the condition is
            false, leading to permanent loss of value.
            
            Verify that state updates are consistent across related variables and that conditional
            updates maintain synchronization. When state is copied or computed from other state,
            verify the source state represents the same logical context as the destination. When
            an address receives items from multiple different sources and later redistributes them,
            verify that state tracking distinguishes which item came from which source, rather than
            using a single state value for all items that would mix their histories.
            
            When functions call other internal functions that depend on state, verify that required
            state changes happen before the dependent function executes. If a function chain performs
            multiple operations on the same state, ensure each step sees the correct state value for
            its logic. Missing state updates between chained operations can cause incorrect behavior.
            
            **Critical state synchronization in function chains**: When operations modify state values
            and then call dependent functions, verify state updates complete BEFORE the dependent function
            reads it. If dependent function reads state before updates finish, it may use stale values,
            allowing incorrect calculations.
            
            For operations with replay protection mechanisms, verify the commitment point. If state is
            committed to prevent replay before actual operations complete, a failure in the operation
            leaves the committed state consumed without the intended effect being achieved. This is
            especially critical for operations involving external calls or subcalls where execution
            might fail due to external factors.
            
            **Expanded state commitment analysis**: Systematically identify ALL state that gets consumed,
            modified, or committed during an operation. For each such state change, verify when it occurs
            relative to operation completion. State that prevents reuse (nonces, signatures, counters, flags)
            should be committed only after verifying that all intended operations succeeded. For functions
            with multiple subcalls, verify that no state is committed before all subcalls complete successfully.
            If state is committed before verification, partial execution scenarios can consume the state
            without achieving the intended outcome.
            
            **Audit Dimension 4: Mathematical Operations and Precision**
            
            Division operations can round down to zero when the numerator is much smaller than the
            denominator, especially with different decimal precisions or large denominators. Trace
            every division operation and verify how its result is used. When computed values are
            recalculated after state changes, verify formulas account for all relevant prior state mutations.
            
            When functions calculate adjustments based on multi-component values,
            verify calculations use complete totals rather than partial components.
            
            **Audit Dimension 5: Control Flow and Logic**
            
            In financial systems, multiple independent adjustments can occur simultaneously. If code
            treats them as mutually exclusive using if-else chains, one adjustment will be silently
            ignored. Verify that independent conditions are handled separately with independent if
            statements, not as mutually exclusive branches.
            
            Verify that return values match expected types and units, and that control flow correctly
            handles all possible execution paths.
            
            When control flow or parameter determination uses address/value comparisons to determine
            directional/positional/ordering parameters with external systems, verify those parameters are
            determined by querying the external system's actual structure rather than fixed constants.
            
            **Unit consistency in return values**: When functions implement interfaces or override base
            functions, verify return values use the correct units. Functions may return values in different
            units than what callers expect.
            If a function is expected to return one unit but returns another, calculations using that
            return value will be incorrect, leading to accounting errors and potential fund loss.
            
            Units encompass both semantic meaning and numeric scaling. When systems use internal representations
            that differ from external representations, verify conversions occur at function boundaries.
            
            For functions that determine where funds are sent (beneficiaries, recipients, destinations), trace
            how the destination is selected. If destination determination uses default values with conditional
            overrides, verify the override conditions cover all necessary cases. Logic that assigns a default
            destination and then conditionally changes it may fail to change it in all appropriate scenarios,
            allowing funds to go to the wrong entity.
            
            **Critical funds destination determination pattern**: When functions allow multiple entities to call,
            verify that destination determination properly accounts for caller identity. If access control allows
            multiple entities but destination logic doesn't restrict who receives funds based on who calls,
            one entity may bypass restrictions and claim funds meant for another.
            
            **Audit Dimension 6: External Interactions and Dependencies**

            When contracts create or interact with external resources, consider race conditions where
            other parties may act first. Functions should verify expected conditions before operations,
            especially when addresses or identifiers may be predictable. Check error handling when
            expected creation or interaction conditions don't hold.

            Verify that cross-contract interactions use correct function signatures, that addresses
            and conversions are handled correctly, and that appropriate checks are performed before
            resource creation or interaction.
            
            **Audit Dimension 7: Edge Cases and Boundary Conditions**
            
            Systematically consider edge cases and boundary conditions that could expose vulnerabilities:
            zero values, maximum values, empty collections, initial states, final states, incomplete
            operations, partial processing, concurrent executions, state transitions, time-based
            boundaries, overflow and underflow conditions, and any scenario where multiple independent
            conditions could be true simultaneously. These scenarios often reveal accounting bugs,
            state inconsistencies, and logic errors that only manifest under specific conditions.
            
            **Systematic partial execution analysis**: For functions that perform multiple operations or subcalls,
            systematically analyze what happens when execution is incomplete:
            - What happens if some operations succeed while others fail?
            - What happens if a function performs multiple subcalls and only some complete?
            - Are there scenarios where the high-level operation can succeed while low-level subcalls fail?
            - If partial execution is possible, what state gets committed or consumed in this scenario?
            - Does the function revert entirely on partial execution, or can it complete partially?
            - If partial completion is allowed, are users protected from unfavorable outcomes?
            
            **Iteration coverage and edge cases**: For functions that iterate through collections or indexed data,
            verify loops handle boundary conditions correctly and access all valid data.
            
            === VERIFICATION REQUIREMENTS ===
            
            For each vulnerability you identify, you must provide:
            
            1. **Mathematical proof with specific numbers** - Show the exact calculations that
               demonstrate the bug using realistic values. Prove the financial impact with arithmetic.
            
            2. **Exact location** - Specify the function name and relevant lines, along with
               the specific variables involved.
            
            3. **Exploitation scenario** - Describe concrete steps an attacker would take, or
               explain how normal protocol usage would trigger the loss. For access control issues,
               explain the timing attack or manipulation strategy. For unit mismatches, trace the
               full call chain and show where calculations break.
            
            4. **Financial impact** - Clearly state who loses funds, how much, and where the
               funds go (or if they're permanently lost). For economic manipulation issues, explain
               what advantage is gained and by whom.
            
            5. **Complete vulnerability description** - Your description should include:
               - The root cause (missing modifier, wrong units, etc.)
               - The mechanism (how it can be exploited or why it fails)
               - The impact (economic loss, fee avoidance, broken invariants, system failure)
               - The affected functions and their relationships

            === WHAT NOT TO REPORT ===
            
            Do not report theoretical issues without concrete mathematical proof. Do not report
            edge cases that are properly handled by existing guards or modifiers. Do not report
            gas optimizations, code quality issues, or standard patterns that are implemented
            correctly. Focus only on vulnerabilities that have a clear, demonstrable path to
            financial loss.

            === CONFIDENCE ASSESSMENT ===
            
            Assess your confidence based on the clarity and demonstrability of the vulnerability:
            
            **Very High Confidence (0.95-1.0)**: Clear, demonstrable errors with concrete proof:
            - Mathematical errors with specific calculations showing the bug
            - Missing access control with no modifiers on critical functions
            - Obvious logic errors that break protocol invariants
            - Missing validation where parameters can be clearly exploited
            
            **High Confidence (0.85-0.94)**: Demonstrated vulnerabilities with clear exploitation scenarios:
            - State synchronization issues with specific numerical examples
            - Parameter validation gaps where injection is clearly possible
            - Deterministic resource creation without existence checks
            - Control flow errors with demonstrated incorrect behavior
            
            **Medium-High Confidence (0.75-0.84)**: Likely issues with reasonable exploit paths:
            - Division rounding issues that may cause problems under specific conditions
            - Edge cases that could lead to vulnerabilities with specific inputs
            - Complex interactions where exploitation requires specific circumstances
            
            **Lower Confidence (<0.75)**: Potential issues requiring specific external conditions or
            further investigation. These should typically not be reported as HIGH or CRITICAL severity.

            For HIGH or CRITICAL severity findings, you must have confidence >= 0.80. Ensure you
            can provide concrete mathematical proof, specific exploitation scenarios, or clear
            demonstrations of the vulnerability.

            Focus on vulnerabilities that lead to direct loss of funds, permanent locking of assets,
            protocol insolvency, theft of user funds, and so on that prevents
            core protocol functionality.

            {format_instructions}

            IMPORTANT: Begin your response with `{{"vulnerabilities":`
        """)

        user_prompt = dedent(f"""
            Analyze this {file_path.suffix} file for HIGH-SEVERITY security vulnerabilities:

            File: {relative_path}
            ```{file_path.suffix[1:] if file_path.suffix else 'txt'}
            {content}
            ```

            Apply the systematic auditing approach above. For each function, systematically examine
            all seven audit dimensions using the verification checklist. Pay particular attention to:
            
            Access Control and Authorization:
            - Are critical operations appropriately restricted?
            - For functions that update state used in economic calculations (balances, fees, interest,
              accounting snapshots), verify they have appropriate access control.
            
            Input Validation and Parameter Checking:
            - Are all parameters validated for correctness, bounds, and expected ranges?
            - Do execution functions validate parameters against computed values when applicable?
            - Are correct variables and parameters used?
            - When functions determine directional/positional/ordering parameters using constant comparisons
              with external systems, is the parameter determined by querying the external system's structure?
            - When actual execution amount differs from requested amount, verify transfer and refund logic are consistent.
              Check that transfers and refunds reference the correct execution values to prevent incorrect fund flows.
              This is a high-severity issue when it causes direct fund loss to the protocol.
            
            State Management and Consistency:
            - Do related state variables update together and remain synchronized?
            - Are conditional state updates applied consistently?
            - When state is copied or computed from other state, verify the source state represents
              the same logical context as the destination.
            - When an address receives items from multiple sources and redistributes them, does state
              tracking distinguish which item came from which source?
            - When operations reduce state values and trigger dependent operations, verify state is set to
              final intended value BEFORE dependent function reads it. If dependent function reads state
              before reset, it may use stale state value, allowing incorrect calculations.
            - **Iteration and Loop Synchronization**: For functions that iterate through data structures,
              verify loops handle boundary conditions correctly and access all valid data.
            
            Mathematical Operations and Precision:
            - Can division operations round to zero? How are results used?
            - **Recomputation correctness**: When computed values are recalculated after state changes,
              verify formulas account for all categories of state mutations and accumulated progress.
            - **Multi-component calculations**: When calculating adjustments based on values with multiple
              components, verify all components are included in comparisons.
            
            Control Flow and Logic:
            - Are independent conditions handled separately, not as mutually exclusive?
            - Do return values match expected types and units?
            - When control flow uses constant comparisons to determine directional/positional/ordering parameters
              with external systems, are those parameters determined by querying the external system's structure?
            - **Unit consistency in return values**: When functions implement interfaces or override base
              functions, verify return values use the correct units. Functions may return values in different
              units than what callers expect. If a function is expected to return one unit but returns another,
              calculations using that return value will be incorrect, leading to accounting errors.
            - Units encompass semantic meaning and numeric scaling. When systems use internal representations
              differing from external ones, verify conversions at boundaries.
            - When functions allow multiple entities to call, verify destination determination accounts for
              caller identity. Access control may allow multiple entities, but destination logic must properly
              restrict who receives funds based on who calls.
            
            External Interactions and Dependencies:
            - Are appropriate checks performed before creating or interacting with external resources?
            - Are cross-contract interactions correctly implemented?
            
            Edge Cases and Boundary Conditions:
            - What happens with zero values, maximum values, empty collections, initial/final states,
              partial processing, concurrent executions, state transitions, time boundaries, overflow/underflow,
              or when multiple conditions are true simultaneously?
            - **Systematic partial execution analysis**: For functions with multiple operations or subcalls:
              - What happens if some operations succeed while others fail?
              - What happens if only a subset of subcalls complete successfully?
              - Are there scenarios where high-level operations succeed while low-level subcalls fail?
              - If partial execution is possible, what state gets committed or consumed?
              - Does the function revert entirely on partial execution, or can it complete partially?
              - If partial completion is allowed, are users protected from unfavorable outcomes?
            - **Iteration coverage edge cases**: For functions that iterate through collections, verify loops
              handle boundary conditions correctly (zero items, maximum items, gaps in sequences).
            
            For each vulnerability you identify:
            - Provide concrete numbers showing the exact calculations
            - Demonstrate the mathematical proof step-by-step
            - Explain the exploitation or loss scenario with structural completeness:
              * What actions can be taken
              * What conditions or timing enables them
              * What operations or calculations break
              * What outcomes result (who gains/loses what)
            - Clearly show the financial impact with arithmetic
            - Describe the complete mechanism linking cause to effect
            
            Only report findings with confidence >= 0.7 for HIGH/CRITICAL severity.
        """)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages, model=model)
            response_content = response['content'].strip()

            msg_json = self.clean_json_response(response_content)
            
            vulnerabilities = Vulnerabilities(**msg_json)
            
            # Filter vulnerabilities by confidence and severity
            filtered_vulns = []
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = model
                
                # Strict filtering: HIGH/CRITICAL must have confidence >= 0.80
                if v.severity in [Severity.HIGH, Severity.CRITICAL]:
                    if v.confidence >= 0.80:
                        filtered_vulns.append(v)
                    else:
                        console.print(f"[dim]Filtered out {v.severity} with low confidence {v.confidence:.2f}: {v.title}[/dim]")
                else:
                    # MEDIUM/LOW can have lower confidence
                    if v.confidence >= 0.65:
                        filtered_vulns.append(v)

            vulnerabilities.vulnerabilities = filtered_vulns

            input_tokens = response.get('input_tokens', 0)
            output_tokens = response.get('output_tokens', 0)

            if vulnerabilities.vulnerabilities:
                console.print(f"[dim]Found {len(vulnerabilities.vulnerabilities)} vulnerabilities in {relative_path} (dimensions approach)[/dim]")
                for vuln in vulnerabilities.vulnerabilities:
                    console.print(f"[dim]  - [{vuln.severity.value.upper()}] {vuln.title} (confidence: {vuln.confidence:.2f})[/dim]")
                    console.print(f"[dim]    Location: {vuln.location}[/dim]")
                    console.print(f"[dim]    Type: {vuln.vulnerability_type}[/dim]")
            else:
                console.print(f"[dim]No vulnerabilities found in {relative_path} (dimensions approach)[/dim]")

            console.print(f"[dim]Token usage - Input: {input_tokens}, Output: {output_tokens}[/dim]")

            return vulnerabilities, input_tokens, output_tokens
            
        except TimeoutError as e:
            console.print(f"[yellow]Timeout in dimensions approach for {file_path.name}: {e}[/yellow]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except requests.exceptions.ReadTimeout as e:
            console.print(f"[yellow]Read timeout in dimensions approach for {file_path.name}: {e}[/yellow]")
            # Timeout during API call - return empty results
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except Exception as e:
            console.print(f"[red]Error analyzing {file_path.name} (dimensions approach): {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0

    def vulnerability_pattern_approach(self, relative_path: str, content: str, model: str, timeout_seconds: float | None = None, start_time: float | None = None) -> tuple[Vulnerabilities, int, int]:
        """Perform audit using vulnerability pattern approach.
        
        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens)
        """
        file_path = Path(relative_path)

        console.print(f"[dim]Analyzing file (pattern approach): {relative_path} (size: {len(content)} bytes)[/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        format_instructions = parser.get_format_instructions()

        system_prompt = dedent(f"""
            You are an EXPERT smart contract security auditor specializing in DeFi protocols.
            Your expertise lies in identifying subtle mathematical and logical errors that lead to 
            loss of funds, protocol insolvency, or theft of user assets.

            === SYSTEMATIC VERIFICATION CHECKLIST ===
            
            For each function, verify in this order:
            
            **Step 1: High-Priority Pattern Checks**
            1. Do operations that modify user asset values provide mechanisms for users to express acceptable execution bounds?
            2. Does validation occur after state changes instead of before?
            3. When execution differs from initial requests, do validation, accounting, and state updates align with what actually occurred?
               When actual execution amount differs from requested amount, verify transfer and refund logic are consistent.
               Check that transfers and refunds reference the correct execution values to prevent incorrect fund flows.
               This is a high-severity issue when it causes direct fund loss to the protocol.
            4. Does the interface/contract lack access control indicators for critical functions?
            5. For funds destination determination: Are default assignments conditionally overridden in all necessary cases?
            6. In function chains: Does state get updated before dependent functions execute?
            7. For replay protection: Is state committed before or after operations that could fail?
            
            **Step 2: Access Control**
            6. Are critical operations appropriately restricted?
            7. For interfaces: Do interface declarations indicate access control expectations?
            
            **Step 3: Input Validation**
            8. Are all parameters validated for correctness, bounds, and expected ranges?
            9. Do execution functions validate parameters against computed values?
            10. Are correct variables and parameters used in calculations?
            
            **Step 4: State Management**
            11. Do related state variables update together and remain synchronized?
            12. Are conditional state updates applied consistently?
            13. When state is read for computation, does it represent the correct logical context?
            14. In function chains, are state modifications applied before dependent operations?
            
            **Step 5: Mathematical Operations**
            14. Can division operations round to zero? How are results used?
            15. When execution differs from requests, do calculations reference the correct values (what actually occurred vs. what was requested)?
                When actual execution amount differs from requested amount, verify transfer and refund logic follows a consistent approach.
                If transfers use the actual amount, verify no refund occurs. Having both transfer of actual amount and refund logic
                simultaneously indicates an inconsistency that causes fund loss when excess funds are sent to users. This is a
                high-severity issue when it causes direct fund loss to the protocol.
            
            **Step 6: Return Value Unit Consistency**
            16. When functions implement interfaces or override base functions, do return values use expected units?
            17. When functions are called by other functions that use return values in calculations, do the units match expectations?
            18. Are there unit mismatches where functions return one unit when another is expected?
            
            **Step 6: Control Flow**
            19. Are independent conditions handled separately?
            20. Do return values match expected types and units?
            21. For funds destination selection: Do conditional overrides cover all scenarios?
            22. **Unit consistency**: When functions implement interfaces or override base functions, verify
                return values use expected units. Unit mismatches cause incorrect calculations.
            
            **Step 7: External Interactions**
            23. Are appropriate checks performed before creating or interacting with external resources?
            24. Are cross-contract interactions correctly implemented with matching function signatures?
            25. Do function signatures match between contracts when one acts on behalf of another?
            
            **Step 8: Edge Cases**
            26. What happens with zero values, maximum values, empty collections, initial/final states?
            27. What happens with partial processing, concurrent executions, state transitions?
            28. What happens with overflow/underflow or multiple simultaneous conditions?
            29. For external calls: What if the call fails due to insufficient resources?

            === AUDITING METHODOLOGY ===
            
            Analyze each function systematically through a structured process:
            1. Identify the function's purpose and critical operations
            2. Check for high-priority vulnerability patterns (listed below)
            3. Verify systematic security dimensions (listed below)
            4. Document findings with exact function names, parameter names, and evidence

            === HIGH-PRIORITY VULNERABILITY PATTERNS ===
            
            These patterns frequently lead to high-severity vulnerabilities. Check for them FIRST:
            
            **Pattern 1: User Control Over Execution Outcomes**
            - Operations that modify user asset positions or values should provide mechanisms for users to express acceptable execution bounds
            - When functions execute trades, withdrawals, or position changes, consider whether users can specify minimum acceptable outputs
            - Without such controls, users may be exposed to unfavorable execution due to market conditions or adversarial actions
            - Examine function signatures and logic: do users have input parameters to constrain execution outcomes?
            - **Critical consideration**: What happens if execution is incomplete or partial? Can some operations succeed while others fail?
            - For functions that execute multiple operations or subcalls: What happens if only a subset completes successfully?
            - Check: Do users have mechanisms to ensure their intended operations complete fully, or can they be left in a partially-executed state?
            - Check: If execution can be partial, are there safeguards to prevent users from being exposed to outcomes that differ from their expectations?
            
            **Pattern 2: Validation Timing and Order of Operations**
            - Validation must occur BEFORE state changes (token transfers, balance updates, swap execution)
            - If validation occurs AFTER state changes, invalid operations can complete
            - Check: Does the function validate parameters before or after executing the operation?
            - Example: Swap function that validates output amount after the swap has already executed
            
            **Pattern 3: Execution Boundaries and Validation Consistency**
            - Operations that may execute differently than initially requested must maintain consistency between expected and actual execution
            - When functions adjust execution based on constraints (liquidity, balances, etc.), verify that validation, accounting, and state updates align with what actually occurred
            - Check whether validation boundaries are enforced at the appropriate points relative to state changes
            - Examine functions where execution parameters may differ from initial requests - ensure all related logic (transfers, refunds, validations) references the correct values
            - When actual execution amount differs from requested amount, verify transfer and refund logic are consistent. Check that transfers and refunds reference the correct execution values to prevent incorrect fund flows that could lead to fund loss.
            
            **Pattern 4: Access Control in Interfaces**
            - Interfaces declaring administrative or critical functions without access control modifiers
            - Functions like pool creation, fee collection, parameter changes should indicate restrictions
            - Check: Does the interface show access control expectations for critical functions?
            - Example: Interface with admin functions but no modifiers or documentation about restrictions
            
            **Pattern 5: Conditional Recipient Selection**
            - Functions that send value to recipients based on conditional logic
            - Verify all code paths correctly identify the intended recipient
            - Check that authorization checks and recipient determination are consistent
            - Ensure conditional recipient selection covers all valid scenarios
            
            **Pattern 6: State Synchronization in Function Chains**
            - When functions call other functions that depend on shared state
            - Verify state modifications complete before dependent functions execute
            - Check ordering of state updates relative to function calls
            - Ensure dependent functions see the correct state for their logic
            - Missing intermediate state updates cause dependent functions to use stale values
            
            **Pattern 7: State Commitment Timing with External Operations**
            - Operations with replay protection commit state to prevent reuse
            - If commitment happens before operations that can fail, the commitment is wasted on failure
            - Check: For operations with external calls, when is the replay protection state committed?
            - Pattern: State committed → External call fails → State consumed but operation didn't complete
            - **Expanded scope**: Check ALL state that gets consumed, committed, or modified before operations complete
            - For any state that prevents reuse (nonces, signatures, flags, counters): When is this state modified relative to operation completion?
            - Check: Are there any state changes that happen before verifying that all intended operations succeeded?
            - For functions with multiple subcalls or operations: Does any state get committed before all subcalls complete successfully?
            - Pattern: State modified → Subcall fails → State consumed but intended operation incomplete
            
            **Pattern 8: External System Assumptions**
            - When functions interact with external systems or contracts
            - Verify assumptions about external state, structure, or behavior
            - Check if code makes fixed assumptions that could change or vary across contexts
            - Consider whether dynamic queries would be more robust than static assumptions
            - Look for hardcoded values or comparisons that assume external system properties
            
            === SYSTEMATIC AUDIT DIMENSIONS ===
            
            After checking high-priority patterns, systematically verify these dimensions:
            
            **Dimension 1: Access Control and Authorization**
            - Critical operations (state changes, balance modifications, trades, parameter changes) must have restrictions
            - Public functions performing critical operations without restrictions are vulnerabilities
            - Functions updating state used in economic calculations (fees, rewards, interest, accounting) need
              access control to prevent timing manipulation
            - For interfaces: Check if interface design reflects security expectations
            - Always identify exact function names and interface names in findings
            
            **Dimension 2: Input Validation and Parameter Checking**
            - All parameters must be validated for correctness, bounds, and expected ranges
            - Execution functions must validate parameters against computed values when applicable
            - Functions must use correct variables and parameters in calculations
            - Always identify exact parameter names in findings
            - When functions determine directional/positional/ordering parameters using constant comparisons
              with external systems, verify the parameter is determined by querying the external system's
              actual structure rather than assuming fixed relationships
            
            **Dimension 2b: Return Value Unit Consistency**
            - Functions implementing interfaces or overriding base functions must return values in expected units
            - When functions are called by other functions that use return values in calculations, verify
              the units match expectations
            - Unit mismatches
              cause incorrect calculations and accounting errors
            - Always verify return value units match the interface contract or caller expectations
            
            **Dimension 3: State Management and Consistency**
            - Related state variables must remain synchronized
            - Conditional updates must maintain synchronization across related variables
            - State copied from other state must represent the same logical context
            - When items come from multiple sources, state tracking must distinguish sources
            - When function chains involve state reductions followed by dependent operations, verify state is
              set to final intended value BEFORE dependent function reads it. If dependent function reads state
              before reset, it may use stale state value, allowing incorrect calculations.
            
            **Dimension 4: Mathematical Operations and Precision**
            - Division operations can round down to zero (check how results are used)
            - Computed values recalculated after state changes must account for all prior mutations
            - When calculating adjustments based on multi-component values, verify all components are
              included in comparisons rather than using only partial components
            - Accounting consistency: ensure calculations reference the correct variables (covered in Pattern 3 above)
            
            **Dimension 5: Control Flow and Logic**
            - Independent conditions must be handled separately (not as mutually exclusive)
            - Return values must match expected types and units
            - All execution paths must be handled correctly
            - When functions allow multiple entities to call, verify destination determination accounts for
              caller identity. Access control may allow multiple entities, but destination logic must properly
              restrict who receives funds based on who calls.
            
            **Dimension 5b: Return Value Unit Consistency**
            - Functions implementing interfaces or overriding base functions must return values in expected units
            - When functions are called by other functions that use return values in calculations, verify
              the units match expectations
            - Units encompass semantic meaning and numeric scaling
            - When systems use internal representations differing from external ones, verify conversions
              at function boundaries
            - Unit mismatches cause incorrect calculations and accounting errors
            - Always verify return value units match the interface contract or caller expectations
            
            **Dimension 6: External Interactions and Dependencies**
            - Existence checks must be performed before interacting with predicted resource identifiers
            - Cross-contract interactions must use correct function signatures
            - Function signatures must match between contracts when one acts on behalf of another (covered in Pattern 5 above)
            - Addresses and conversions must be handled correctly
            
            **Dimension 7: Edge Cases and Boundary Conditions**
            - Check: zero values, maximum values, empty collections, initial/final states
            - Check: incomplete operations, partial processing, concurrent executions
            - Check: state transitions, time boundaries, overflow/underflow
            - Check: scenarios where multiple independent conditions are true simultaneously
            - **Systematic partial execution analysis**: For functions with multiple operations or subcalls:
              - What happens if some operations succeed while others fail?
              - What happens if only a subset of subcalls complete successfully?
              - Are there scenarios where high-level operations succeed while low-level subcalls fail?
              - If partial execution is possible, what state gets committed or consumed?
              - Does the function revert entirely on partial execution, or can it complete partially?
              - If partial completion is allowed, are users protected from unfavorable outcomes?
            
            === VERIFICATION REQUIREMENTS ===
            
            For each vulnerability you identify, you must provide:
            
            1. **Exact function and parameter names** - Always identify the specific function name.
               When discussing parameters, use their exact names.
               For interface-level issues, identify the interface name and list the affected functions.
            
            2. **Mathematical proof with specific numbers** - Show the exact calculations that
               demonstrate the bug using realistic values. Prove the financial impact with arithmetic.
            
            3. **Exact location** - Specify the function name and relevant lines, along with
               the specific variables involved. Include interface names when applicable.
            
            4. **Exploitation scenario** - Describe concrete steps an attacker would take, or
               explain how normal protocol usage would trigger the loss.
            
            5. **Financial impact** - Clearly state who loses funds, how much, and where the
               funds go (or if they're permanently lost).

            === WHAT NOT TO REPORT ===
            
            Do not report theoretical issues without concrete mathematical proof. Do not report
            edge cases that are properly handled by existing guards or modifiers. Do not report
            gas optimizations, code quality issues, or standard patterns that are implemented
            correctly. Focus only on vulnerabilities that have a clear, demonstrable path to
            financial loss.

            === CONFIDENCE ASSESSMENT ===
            
            Assess your confidence based on the clarity and demonstrability of the vulnerability:
            
            **Very High Confidence (0.95-1.0)**: Clear, demonstrable errors with concrete proof:
            - Mathematical errors with specific calculations showing the bug
            - Missing access control with no modifiers on critical functions
            - Obvious logic errors that break protocol invariants
            - Missing validation where parameters can be clearly exploited
            
            **High Confidence (0.85-0.94)**: Demonstrated vulnerabilities with clear exploitation scenarios:
            - State synchronization issues with specific numerical examples
            - Parameter validation gaps where injection is clearly possible
            - Deterministic resource creation without existence checks
            - Control flow errors with demonstrated incorrect behavior
            - Access control issues in interfaces declaring critical functions without restrictions
            - Validation occurring after state changes allowing invalid operations to complete
            
            **Medium-High Confidence (0.75-0.84)**: Likely issues with reasonable exploit paths:
            - Division rounding issues that may cause problems under specific conditions
            - Edge cases that could lead to vulnerabilities with specific inputs
            - Complex interactions where exploitation requires specific circumstances
            
            **Lower Confidence (<0.75)**: Potential issues requiring specific external conditions or
            further investigation. These should typically not be reported as HIGH or CRITICAL severity.

            For HIGH or CRITICAL severity findings, you must have confidence >= 0.80. Ensure you
            can provide concrete mathematical proof, specific exploitation scenarios, or clear
            demonstrations of the vulnerability.

            Focus on vulnerabilities that lead to direct loss of funds, permanent locking of assets,
            protocol insolvency, theft of user funds, and so on that prevents
            core protocol functionality.

            {format_instructions}

            IMPORTANT: Begin your response with `{{"vulnerabilities":`
        """)

        user_prompt = dedent(f"""
            Analyze this {file_path.suffix} file for HIGH-SEVERITY security vulnerabilities:

            File: {relative_path}
            ```{file_path.suffix[1:] if file_path.suffix else 'txt'}
            {content}
            ```

            Follow the systematic auditing approach above. For each function:

            **STEP 1: Check High-Priority Vulnerability Patterns First**
            
            Check these patterns in order (they frequently lead to high-severity findings):
            
            1. **Missing User Protection**: Does the function reduce user positions, withdraw assets, or decrease
               user-held value WITHOUT allowing users to specify minimum acceptable outputs? (Pattern 1)
               - Look for: position decrease, withdrawal, liquidity removal functions
               - Check: Are there parameters to protect user?
               - If missing: This is a vulnerability - users cannot protect against manipulation
               - **Critical consideration**: What happens if execution is incomplete or partial?
               - For functions that execute multiple operations or subcalls: Can some operations succeed while others fail?
               - Check: Do users have mechanisms to ensure their intended operations complete fully?
               - Check: If execution can be partial, are there safeguards to prevent unfavorable outcomes?
            
            2. **Validation Timing**: Does validation occur AFTER state changes instead of BEFORE? (Pattern 2)
               - Look for: validation checks that happen after token transfers, balance updates, or swap execution
               - Check: Does the function execute the operation first, then validate?
               - If yes: This is a vulnerability - invalid operations can complete
            
            3. **Execution Boundaries and Validation Consistency**: When operations execute differently than
               initially requested, do validation, accounting, and state updates align with what actually occurred? (Pattern 3)
               - Look for: functions that adjust execution based on constraints (liquidity, balances, etc.)
               - Check: Do validation boundaries, accounting calculations, and state updates reference the correct values (actual vs. requested)?
               - Check: Are validation checks enforced at appropriate points relative to state changes?
               - When actual execution amount differs from requested amount, verify transfer and refund logic are consistent.
                 Check that transfers and refunds reference the correct execution values to prevent incorrect fund flows
                 that could lead to fund loss. This is a high-severity issue when it causes direct fund loss to the protocol.
            
            4. **Access Control in Interfaces**: Does the interface declare critical functions without
               access control indicators? (Pattern 4)
               - Look for: interfaces with admin functions, pool creation, fee collection, parameter changes
               - Check: Are there modifiers or documentation indicating restrictions?
               - If missing: This is a vulnerability - interface design should reflect security expectations
            
            5. **Recipient Selection Logic**: For functions that send value based on conditional logic, is the
               recipient correctly determined in all cases? (Pattern 5)
               - Look for: functions with conditional recipient selection
               - Check: Do all code paths correctly identify the intended recipient?
               - Verify that authorization checks and recipient determination are consistent
            
            6. **State Synchronization in Function Chains**: When functions call other internal functions,
               is state updated before the dependent call? (Pattern 6)
               - Look for: functions that call other internal functions
               - Check: Does the calling function modify state that the called function depends on?
               - Verify: State modifications happen before the dependent function executes
               - When operations reduce state values and trigger dependent operations, verify state is set to
                 final intended value BEFORE dependent function reads it. If dependent function reads state
                 before reset, it may use stale state value.
            
            7. **Return Value Unit Consistency**: When functions implement interfaces or override base functions,
               do return values use expected units? (Pattern 9)
               - Look for: functions implementing interfaces or overriding base functions
               - Check: Do return values use the correct units when used by callers in calculations?
               - Verify: If callers expect one unit but receive another, calculations will be incorrect
               - Consider both semantic meaning and numeric scaling of values
               - When systems use internal representations differing from external ones, verify conversions at boundaries
               - When reporting: Identify returning function and unit, consuming function and expected unit,
                 failed calculations, and propagation to dependent operations
               - Unit mismatches cause accounting errors, fund loss, or asset locking
            
            8. **State Commitment Timing**: For operations with replay protection, when is state committed? (Pattern 7)
               - Look for: operations that consume nonces, signatures, or other replay protection mechanisms
               - Check: Is the commitment made before or after operations that could fail?
               - Verify: If external calls can fail, commitment should happen after success verification
               - **Expanded scope**: Check ALL state that gets consumed, committed, or modified before operations complete
               - For any state that prevents reuse: When is this state modified relative to operation completion?
               - For functions with multiple subcalls: Does any state get committed before all subcalls complete successfully?
               - Check: Are there state changes that happen before verifying that all intended operations succeeded?
            
            9. **External System Assumptions**: When functions interact with external systems, are assumptions
               about their structure or behavior verified? (Pattern 8)
               - Look for: functions that make fixed assumptions about external contract properties
               - Check: Does code assume external system characteristics that could vary?
               - Verify: Whether dynamic queries would be more robust than static assumptions
               - Impact: Incorrect assumptions leading to wrong parameter determination or logic errors
            
            **STEP 2: Verify Systematic Audit Dimensions**
            
            After checking patterns, verify the systematic dimensions:
            
            - Access Control: Are critical operations restricted? (Check interfaces too)
              Do functions that update state used in economic calculations have access control?
            - Input Validation: Are parameters validated? When does validation occur?
            - State Management: Do related variables stay synchronized?
            - Mathematical Operations: Can divisions round to zero? Do calculations reference correct values?
              When calculating adjustments from multi-component values, are all components included?
            - Control Flow: Are independent conditions handled separately?
            - External Interactions: Are function signatures matched? Existence checks performed?
            - Edge Cases: What happens with zero, max values, partial processing, etc.?
            - **Systematic partial execution analysis**: For functions with multiple operations or subcalls:
              - What happens if some operations succeed while others fail?
              - What happens if only a subset of subcalls complete successfully?
              - Are there scenarios where high-level operations succeed while low-level subcalls fail?
              - If partial execution is possible, what state gets committed or consumed?
              - Does the function revert entirely on partial execution, or can it complete partially?
              - If partial completion is allowed, are users protected from unfavorable outcomes?
            
            **STEP 3: Document Findings**
            
            For each vulnerability, you MUST provide:
            - **Exact function name(s)** and interface names (if applicable)
            - **Exact parameter names** when discussing validation or execution consistency issues
            - **When validation occurs** (before/after state changes) for timing issues
            - **Mathematical proof** with specific numbers showing the bug
            - **Exploitation scenario** with structural completeness:
              * What actions can be taken
              * What conditions or timing enables them  
              * What state changes or calculations break
              * What outcomes result
            - **Financial impact** with arithmetic showing who loses funds and how much
            - **Mechanism linking cause to effect** throughout the system
            
            **Confidence Assessment**:
            - For HIGH/CRITICAL severity: confidence >= 0.80 required
            - For clear pattern matches (Patterns 1-5): confidence 0.85-0.95 is appropriate even without
              detailed mathematical proofs, as these are well-established vulnerability indicators
            - Only report findings with confidence >= 0.7
            
            Focus on vulnerabilities that lead to direct loss of funds, permanent locking of assets,
            protocol insolvency, or theft of user funds.
        """)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages, model=model)
            response_content = response['content'].strip()

            msg_json = self.clean_json_response(response_content)
            
            vulnerabilities = Vulnerabilities(**msg_json)
            
            # Filter vulnerabilities by confidence and severity
            filtered_vulns = []
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = model
                
                # Strict filtering: HIGH/CRITICAL must have confidence >= 0.80
                if v.severity in [Severity.HIGH, Severity.CRITICAL]:
                    if v.confidence >= 0.80:
                        filtered_vulns.append(v)
                    else:
                        console.print(f"[dim]Filtered out {v.severity} with low confidence {v.confidence:.2f}: {v.title}[/dim]")
                else:
                    # MEDIUM/LOW can have lower confidence
                    if v.confidence >= 0.65:
                        filtered_vulns.append(v)

            vulnerabilities.vulnerabilities = filtered_vulns

            input_tokens = response.get('input_tokens', 0)
            output_tokens = response.get('output_tokens', 0)

            if vulnerabilities.vulnerabilities:
                console.print(f"[dim]Found {len(vulnerabilities.vulnerabilities)} vulnerabilities in {relative_path} (pattern approach)[/dim]")
                for vuln in vulnerabilities.vulnerabilities:
                    console.print(f"[dim]  - [{vuln.severity.value.upper()}] {vuln.title} (confidence: {vuln.confidence:.2f})[/dim]")
                    console.print(f"[dim]    Location: {vuln.location}[/dim]")
                    console.print(f"[dim]    Type: {vuln.vulnerability_type}[/dim]")
            else:
                console.print(f"[dim]No vulnerabilities found in {relative_path} (pattern approach)[/dim]")

            console.print(f"[dim]Token usage - Input: {input_tokens}, Output: {output_tokens}[/dim]")

            return vulnerabilities, input_tokens, output_tokens
            
        except TimeoutError as e:
            console.print(f"[yellow]Timeout in pattern approach for {file_path.name}: {e}[/yellow]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except requests.exceptions.ReadTimeout as e:
            console.print(f"[yellow]Read timeout in pattern approach for {file_path.name}: {e}[/yellow]")
            # Timeout during API call - return empty results
            return Vulnerabilities(vulnerabilities=[]), 0, 0
        except Exception as e:
            console.print(f"[red]Error analyzing {file_path.name} (pattern approach): {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0

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
        
        model = 'unknown_model'
    
        max_threads = 8
    
        # Find files to analyze
        default_patterns = [
            "**/*.sol",
            "**/*.rs",
            "**/*.vy",
            "**/*.move",
        ]

        patterns = file_patterns or default_patterns
    
        files_to_analyze = []
        for pattern in patterns:
            files_to_analyze.extend(source_dir.glob(pattern))

        files_to_analyze = sorted(set(files_to_analyze))

        excluded_dirs = {
            'node_modules', 'test', 'tests', 'script', 'scripts', 
            'mocks', 'mock', 'interfaces', 'lib', 'libraries',
            '.git', 'artifacts', 'cache', 'out', 'dist', 'build'
        }
    
        files_to_analyze = [
            f for f in files_to_analyze 
            if not any(excluded in f.parts for excluded in excluded_dirs)
        ]

        console.print(f"Found {len(files_to_analyze)} files to analyze in {source_dir}")

        # Store file contents to avoid re-reading in each iteration
        file_contents = {}
        files_to_process = []
    
        for f in files_to_analyze:
            relative_path = f.relative_to(source_dir)
        
            # Skip very large files
            file_size = f.stat().st_size
            if file_size > 500_000:  # 500KB limit
                console.print(f"[yellow]Skipping large file: {relative_path} ({file_size} bytes)[/yellow]")
                continue
        
            try:
                with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()
            
                # Skip empty files
                if not content.strip():
                    continue
            
                file_contents[str(relative_path)] = content
                files_to_process.append((f, str(relative_path)))
            except Exception as e:
                console.print(f"[red]Error reading file {relative_path}: {e}[/red]")
                continue

        console.print(f"[dim]Found {len(files_to_process)} files to analyze[/dim]")

        # Configuration
        NUM_ITERATIONS = 10
        TIMEOUT_SECONDS = 18 * 60
        start_time = time.time()
        MAX_CONCURRENT_PROCESSES = max_threads * 2  # Limit concurrent processes
        MAX_TOTAL_PROCESSES = 1000  # Safety limit on total processes created
    
        dimensions_model = "unknown_model"
        pattern_model = "unknown_model"
        attack_model = "unknown_model"
    
        # Create temporary directory for result files - MUCH simpler than queues!
        import tempfile
        import shutil
        result_dir = tempfile.mkdtemp(prefix='agent_results_')
        console.print(f"[dim]Result directory: {result_dir}[/dim]")
    
        # Use multiprocessing.Process for hard termination capability
        processes = []  # List of (process_id, process) tuples
        process_id_to_process = {}  # Map process_id to process for quick lookup
        process_id_counter = 0
        timeout_reached = False  # Flag to break out of nested loops
        
        console.print(f"Analyzing {len(files_to_process)} files... (max {MAX_CONCURRENT_PROCESSES} concurrent processes)")

        for i in range(NUM_ITERATIONS):
            if timeout_reached:
                break
        
            for file_path, relative_path_str in files_to_process:
                if timeout_reached:
                    break
                
                content = file_contents[relative_path_str]
                try:
                    # Create processes for each approach
                    process_configs = [
                        ('audit_dimensions', dimensions_model),
                        ('vulnerability_pattern', pattern_model),
                        ('attack_analysis', attack_model),
                        ('boundary_consistency', dimensions_model)
                    ]
                
                    for approach_name, model in process_configs:
                        if timeout_reached:
                            break
                        
                        # Check total process limit
                        if process_id_counter >= MAX_TOTAL_PROCESSES:
                            console.print(f"[yellow]Reached maximum process limit ({MAX_TOTAL_PROCESSES}), skipping remaining tasks[/yellow]")
                            break
                    
                        # Wait if we've reached the concurrency limit
                        while True:
                            # Check if timeout reached during process creation
                            if time.time() - start_time > TIMEOUT_SECONDS:
                                console.print(f"[yellow]Timeout reached during process creation ({time.time() - start_time:.1f}s), stopping all process creation immediately...[/yellow]")
                                timeout_reached = True
                                break
                        
                            # Count alive processes
                            alive_count = sum(1 for _, p in processes if p.is_alive())
                            if alive_count < MAX_CONCURRENT_PROCESSES:
                                break
                        
                            time.sleep(0.1)
                    
                        # If timeout reached during concurrency wait, skip this process creation
                        if timeout_reached:
                            break
                    
                        process_id_counter += 1
                        proc = multiprocessing.Process(
                            target=_worker_approach,
                            args=(approach_name, relative_path_str, content, model,
                                    self.inference_api, self.project_id, self.job_id, result_dir, process_id_counter),
                            daemon=True
                        )
                        proc.start()
                    
                        # Track process
                        with self.process_tracking_lock:
                            self.process_tracking[process_id_counter] = {
                                'process': proc,
                                'process_pid': proc.pid if proc.pid else None,
                                'started': True,
                                'finished': False,
                                'start_time': time.time(),
                                'end_time': None,
                                'approach': approach_name,
                                'file': relative_path_str
                            }
                        processes.append((process_id_counter, proc))
                        process_id_to_process[process_id_counter] = proc
                
                    if process_id_counter >= MAX_TOTAL_PROCESSES:
                        break
                except Exception as e:
                    console.print(f"[red]Error processing {file_path.name}: {e}[/red]")
                    continue
    
        # Wait for processes to complete or timeout
        total_processes_created = process_id_counter
        console.print(f"[cyan]Created {total_processes_created} worker processes[/cyan]")
    
        # Simple wait loop - no complex queue management!
        if not timeout_reached:
            console.print(f"[cyan]Waiting for processes to complete (timeout: {TIMEOUT_SECONDS}s)...[/cyan]")
            last_progress_time = time.time()
            
            try:
                while True:
                    # Check timeout
                    if time.time() - start_time > TIMEOUT_SECONDS:
                        console.print(f"[yellow]Timeout reached ({TIMEOUT_SECONDS}s), terminating all processes...[/yellow]")
                        timeout_reached = True
                        break
                    
                    # Count alive processes
                    alive_count = sum(1 for _, p in processes if p.is_alive())
                    
                    # Check if all done
                    if alive_count == 0:
                        console.print(f"[green]All processes completed![/green]")
                        break
                    
                    # Progress update every 5 seconds
                    if time.time() - last_progress_time > 5.0:
                        console.print(f"[dim]Progress: {alive_count} processes still running...[/dim]")
                        last_progress_time = time.time()
                    
                    time.sleep(0.5)
            except KeyboardInterrupt:
                console.print("[yellow]Interrupted, terminating all processes...[/yellow]")
                timeout_reached = True
    
        # Terminate any remaining processes
        alive_count = sum(1 for _, p in processes if p.is_alive())
        if alive_count > 0:
            console.print(f"[yellow]Terminating {alive_count} remaining processes...[/yellow]")
            for proc_id, proc in processes:
                if proc.is_alive():
                    try:
                        proc.kill()
                    except:
                        pass
            time.sleep(0.5)
    
        # Now aggregate ALL results from files - SIMPLE and RELIABLE!
        console.print(f"[cyan]Aggregating results from {result_dir}...[/cyan]")
        all_vulnerabilities = []
        total_input_tokens = 0
        total_output_tokens = 0
        
        import json
        from pathlib import Path
        result_files = list(Path(result_dir).glob("result_*.json"))
        console.print(f"[cyan]Found {len(result_files)} result files[/cyan]")
        
        for result_file in result_files:
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)
                
                if data['success']:
                    total_input_tokens += data.get('input_tokens', 0)
                    total_output_tokens += data.get('output_tokens', 0)
                    
                    for vuln_dict in data.get('vulnerabilities', []):
                        # Reconstruct Vulnerability object
                        vuln = Vulnerability(
                            title=vuln_dict['title'],
                            description=vuln_dict['description'],
                            severity=Severity(vuln_dict['severity']),
                            confidence=vuln_dict['confidence'],
                            location=vuln_dict['location'],
                            vulnerability_type=vuln_dict['vulnerability_type'],
                            file=vuln_dict['file']
                        )
                        all_vulnerabilities.append(vuln)
                        
                    if data.get('vulnerabilities'):
                        console.print(f"[green]✓ Loaded {len(data['vulnerabilities'])} vulnerabilities from process {data['process_id']}[/green]")
            except Exception as e:
                console.print(f"[red]Error loading {result_file.name}: {e}[/red]")
        
        console.print(f"[cyan]Total vulnerabilities collected: {len(all_vulnerabilities)}[/cyan]")
        console.print(f"[cyan]Total tokens - Input: {total_input_tokens}, Output: {total_output_tokens}[/cyan]")
        
        # Clean up result directory
        try:
            shutil.rmtree(result_dir)
        except:
            pass
    
        # Deduplicate vulnerabilities
        unique_vulnerabilities = {
            v.id: v for v in all_vulnerabilities
        }
        vulns = list(unique_vulnerabilities.values())
    
        result = AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=len(files_to_process),
            files_skipped=0,
            total_vulnerabilities=len(unique_vulnerabilities),
            vulnerabilities=vulns,
            token_usage={
                'input_tokens': total_input_tokens,
                'output_tokens': total_output_tokens,
                'total_tokens': total_input_tokens + total_output_tokens
            }
        )

        self.print_summary(result)
    
        # Report incomplete processes
        with self.process_tracking_lock:
            incomplete_processes = [
                proc_info for proc_id, proc_info in self.process_tracking.items()
                if proc_info['started'] and not proc_info['finished']
            ]
    
        if incomplete_processes:
            console.print("\n[bold yellow]WARNING: Processes that were started but not finished:[/bold yellow]")
            current_time = time.time()
            for proc_info in incomplete_processes:
                elapsed = current_time - proc_info['start_time']
                console.print(f"  - {proc_info['approach']} for {proc_info['file']} (running for {elapsed:.2f} seconds)")
        else:
            console.print("\n[green]All processes completed successfully[/green]")
    
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



# Worker function for multiprocessing - must be at module level
def _worker_approach(approach_name, relative_path, content, model, inference_api, project_id, job_id, result_dir, process_id):
    """Generic worker function that runs an approach method in a separate process.
    Writes results to a file instead of using a queue for reliability.
    """
    import sys
    import os
    import json
    from pathlib import Path
    
    # Write to stderr for debugging (visible in parent process)
    try:
        sys.stderr.write(f"Worker {process_id} ({approach_name}) starting for {relative_path}\n")
        sys.stderr.flush()
    except:
        pass
    
    start_time = time.time()
    result_file = Path(result_dir) / f"result_{process_id}.json"
    
    try:
        # Create a runner instance for this process
        runner = BaselineRunner(config={'model': ''}, inference_api=inference_api)
        runner.project_id = project_id
        runner.job_id = job_id
        
        # Call the appropriate approach method
        if approach_name == 'audit_dimensions':
            result = runner.audit_dimensions_approach(relative_path, content, model, 120, time.time())
        elif approach_name == 'vulnerability_pattern':
            result = runner.vulnerability_pattern_approach(relative_path, content, model, 120, time.time())
        elif approach_name == 'attack_analysis':
            result = runner.attack_analysis_approach(relative_path, content, model, 120, time.time())
        elif approach_name == 'boundary_consistency':
            result = runner.boundary_consistency_approach(relative_path, content, model, 120, time.time())
        else:
            raise ValueError(f"Unknown approach: {approach_name}")
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        # Extract vulnerabilities and token counts
        vulnerabilities, input_tokens, output_tokens = result
        
        # Serialize vulnerabilities to dict format
        vuln_list = []
        if vulnerabilities and vulnerabilities.vulnerabilities:
            for v in vulnerabilities.vulnerabilities:
                vuln_list.append({
                    'title': v.title,
                    'description': v.description,
                    'severity': v.severity.value,
                    'confidence': v.confidence,
                    'location': v.location,
                    'vulnerability_type': v.vulnerability_type,
                    'file': v.file
                })
        
        # Write result to file
        result_data = {
            'process_id': process_id,
            'success': True,
            'vulnerabilities': vuln_list,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'elapsed_time': elapsed_time,
            'error': None
        }
        
        with open(result_file, 'w') as f:
            json.dump(result_data, f)
        
        try:
            sys.stderr.write(f"Worker {process_id} completed successfully in {elapsed_time:.2f}s - wrote {len(vuln_list)} vulnerabilities to {result_file.name}\n")
            sys.stderr.flush()
        except:
            pass
            
    except Exception as e:
        end_time = time.time()
        elapsed_time = end_time - start_time
        import traceback
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        
        try:
            sys.stderr.write(f"Worker {process_id} ERROR: {error_msg}\n")
            sys.stderr.flush()
        except:
            pass
        
        # Write error result to file
        try:
            result_data = {
                'process_id': process_id,
                'success': False,
                'vulnerabilities': [],
                'input_tokens': 0,
                'output_tokens': 0,
                'elapsed_time': elapsed_time,
                'error': error_msg
            }
            with open(result_file, 'w') as f:
                json.dump(result_data, f)
        except Exception as file_error:
            try:
                sys.stderr.write(f"Worker {process_id} file write error: {file_error}\n")
                sys.stderr.flush()
            except:
                pass


def agent_main(project_dir: str = None, inference_api: str = None, output_dir: str = None, run_id: str = None):
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
        project_id = run_id if run_id else Path(project_dir).name
        if output_dir:
            output_file = f"{output_dir}/{project_id}.json"
        else:
            output_file = f"logs/{project_id}.json"
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
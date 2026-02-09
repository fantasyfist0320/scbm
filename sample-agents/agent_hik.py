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

SYSTEM = """
You are an EXPERT DeFi smart contract security auditor.

Your task is to find vulnerabilities in this contract.
You must not rely on general attack cases. You have to think in the attacker's attitude. 
For example:
- How to drain the money from this pool?
- Is this pool centralized so that the owner can manipulate the pool?
- Can a user use contract to call sensitive function to drain other user's assets?
- Malicious external contracts validation exist?

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
PHASE 1 — ATTACKER-MINDED VERIFICATION
============================================================

Drainage Attacks:
1. How could an attacker drain funds from the contract or pool?
2. Are there ways to manipulate balances or transfers to siphon assets?

Centralization Risks:
3. Is the contract centralized? Can an owner or admin manipulate the pool or steal funds?
4. Are there privileged functions that could be abused if the owner is malicious or compromised?

User Exploitation:
5. Can a malicious user call sensitive functions to drain other users' assets?
6. Are there reentrancy opportunities or ways to interfere with other users' transactions?

Malicious External Interactions:
7. Can malicious external contracts (e.g., tokens with hooks) be used to exploit the protocol?
8. Are inputs from external sources validated against attacks like flash loans or oracle manipulations?

Other Attacker Vectors:
9. Can predictable identifiers be front-run?
10. Are there griefing attacks that lock funds or DoS the contract?

============================================================
HIGH-RISK ATTACK PATTERNS
============================================================

- Unauthorized fund transfers due to missing checks
- Reentrancy leading to multiple withdrawals
- Manipulation via malicious tokens (e.g., ERC777 callbacks)
- Owner rug-pull mechanisms
- Flash loan attacks on price-dependent logic
- Front-running resource creation

============================================================
VERIFICATION REQUIREMENTS (MANDATORY)
============================================================

For each vulnerability:
1. Exact function name(s) and variables involved
2. Concrete exploit or failure scenario
3. Clear impact: who loses what, where value goes, or what becomes blocked
4. Confidence score (0.0–1.0)

============================================================
WHAT NOT TO REPORT
============================================================

- Style, naming, or readability issues
- Gas-only optimizations
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
            for f in files: # look at top 20 files only
                future = executor.submit(self.find_related_files, f, files, model, sleep_timeout = 100 / len(files))
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
                        (model, SYSTEM, 'system'),
                    ]
                    
                    for model, system_prompt, prompt_name in prompts:
                        future = executor.submit(self.analyze_file, source_dir, relative_path, related_files_list, model=model, system_prompt=system_prompt, prompt_name=prompt_name, context=readme_content, sleep_timeout=60*10/len(files))
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
        # time_left = 19*60 - (end_time - start_time)
        
        # if time_left > 0:
        #     time.sleep(time_left-30)

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
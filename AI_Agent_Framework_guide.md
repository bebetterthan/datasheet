# 🤖 Complete Guide: Building Red Team AI Agent Framework

## 📋 Overview

### Apa yang akan kita buat? 

```
SEBELUM (Fine-tuned Model saja):
═══════════════════════════════════════════════════════════

User: "Scan website ini untuk Magecart"
   │
   ▼
┌─────────────────────────────────────────┐
│           🧠 AI Model                   │
│   "Untuk scan Magecart, kamu perlu:     │
│    1. Check CSP headers                 │
│    2. Analyze JavaScript                │
│    3. ..."                              │
│                                         │
│   ❌ CUMA KASIH TAU, GA BISA EXECUTE    │
└─────────────────────────────────────────┘


SESUDAH (Dengan Agent Framework):
═══════════════════════════════════════════════════════════

User: "Scan website ini untuk Magecart"
   │
   ▼
┌─────────────────────────────────────────┐
│           🤖 AI Agent                   │
│                                         │
│   1. [THINK] "Saya perlu scan headers"  │
│   2. [ACTION] → Execute: check_headers  │
│   3. [OBSERVE] → "CSP missing!"         │
│   4. [THINK] "Perlu analyze JS"         │
│   5. [ACTION] → Execute: scan_js        │
│   6. [OBSERVE] → "Found suspicious..."  │
│   7. [REPORT] → Generate findings       │
│                                         │
│   ✅ BISA THINK + ACTION + REPORT       │
└─────────────────────────────────────────┘
```

### Komponen Agent Framework

```
AGENT FRAMEWORK ARCHITECTURE:
═══════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                     RED TEAM AI AGENT                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    CORE ENGINE                        │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  │  │
│  │  │ Planner │  │Executor │  │Observer │  │ Memory  │  │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    🧠 LLM BRAIN                       │  │
│  │           (Fine-tuned Qwen 2.5 Coder 7B)             │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    🔧 TOOL LAYER                      │  │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐       │  │
│  │  │Recon │ │Scan  │ │Analyze│ │Exploit│ │Report│      │  │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘       │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  🔒 GATE ZERO                         │  │
│  │              (Authorization & Safety)                 │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

Buat struktur folder berikut untuk Agent Framework:

```
redteam-agent/
│
├── agent/
│   ├── __init__. py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── agent. py              # Main agent class
│   │   ├── planner.py            # Task planning
│   │   ├── executor. py           # Tool execution
│   │   ├── observer.py           # Result observation
│   │   └── memory.py             # Conversation & context memory
│   │
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── provider.py           # LLM connection (local/API)
│   │   ├── prompts.py            # System prompts
│   │   └── parser.py             # Response parsing
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── base. py               # Base tool class
│   │   ├── registry.py           # Tool registration
│   │   ├── recon/
│   │   │   ├── __init__.py
│   │   │   ├── http_probe.py     # HTTP probing
│   │   │   ├── subdomain. py      # Subdomain enum
│   │   │   └── tech_detect.py    # Technology detection
│   │   ├── scanner/
│   │   │   ├── __init__.py
│   │   │   ├── header_scan.py    # Security headers
│   │   │   ├── nuclei_scan.py    # Nuclei integration
│   │   │   └── js_scan.py        # JavaScript scanning
│   │   ├── analyzer/
│   │   │   ├── __init__.py
│   │   │   ├── js_analyzer.py    # JS code analysis
│   │   │   ├── skimmer_detect.py # Magecart detection
│   │   │   └── csp_analyzer.py   # CSP analysis
│   │   └── reporter/
│   │       ├── __init__.py
│   │       └── report_gen.py     # Report generation
│   │
│   ├── security/
│   │   ├── __init__.py
│   │   ├── gate_zero.py          # Authorization gate
│   │   ├── scope_validator.py    # Target scope validation
│   │   └── audit_logger.py       # Action logging
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logger.py             # Logging utilities
│       ├── config.py             # Configuration
│       └── helpers.py            # Helper functions
│
├── configs/
│   ├── agent_config.yaml         # Agent configuration
│   ├── tools_config.yaml         # Tools configuration
│   └── prompts/
│       ├── system_prompt.txt     # Main system prompt
│       ├── planner_prompt.txt    # Planner prompt
│       └── analyzer_prompt.txt   # Analyzer prompt
│
├── tests/
│   ├── test_agent.py
│   ├── test_tools.py
│   └── test_security.py
│
├── scripts/
│   ├── run_agent.py              # CLI runner
│   ├── serve_api.py              # API server
│   └── interactive. py            # Interactive mode
│
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🔨 PHASE 1: Core Agent Engine

### Task 1. 1: Base Agent Class

Lokasi: `agent/core/agent.py`

Buat class utama untuk Agent dengan fitur:

**Attributes:**
- `llm` - Connection ke fine-tuned model
- `tools` - Registry of available tools
- `memory` - Conversation and context memory
- `gate` - Gate Zero security layer
- `config` - Agent configuration

**Methods:**
- `run(task)` - Main entry point, execute a task
- `plan(task)` - Create execution plan
- `execute_step(step)` - Execute single step
- `observe(result)` - Analyze tool output
- `should_continue()` - Decide if task complete
- `generate_report()` - Create final report

**Workflow Logic:**
```
1.  Receive task from user
2. Pass through Gate Zero (authorization check)
3.  LOOP:
   a.  THINK - LLM decides next action
   b.  ACTION - Execute selected tool
   c.  OBSERVE - LLM analyzes result
   d. Check if goal achieved
   e. If not, continue loop
4. Generate final report
5. Log all actions
```

**Configuration yang bisa di-set:**
- `max_iterations` - Prevent infinite loops (default: 20)
- `timeout` - Max time per task (default: 600 seconds)
- `verbose` - Print detailed steps (default: True)
- `auto_report` - Auto generate report (default: True)

---

### Task 1.2: Planner Module

Lokasi: `agent/core/planner.py`

Module untuk membuat execution plan.  

**Input:**
- User task/query
- Available tools list
- Current context/memory

**Output:**
- Structured plan dengan steps
- Each step: tool_name, action, parameters, expected_output

**Planner harus bisa:**
1. Understand task requirements
2.  Break down into subtasks
3. Select appropriate tools for each subtask
4. Order steps logically
5.  Handle dependencies between steps

**Plan Format:**
```yaml
task: "Scan example. com for Magecart vulnerabilities"
steps:
  - id: 1
    tool: "http_probe"
    action: "check_alive"
    params:
      url: "https://example. com"
    depends_on: null
    
  - id: 2
    tool: "header_scanner"
    action: "check_security_headers"
    params:
      url: "https://example.com"
    depends_on: 1
    
  - id: 3
    tool: "js_scanner"
    action: "enumerate_scripts"
    params:
      url: "https://example.com"
    depends_on: 1
    
  # ... more steps
```

**Dynamic Replanning:**
- Agent harus bisa adjust plan based on findings
- Contoh: Jika CSP missing, prioritize XSS testing
- Contoh: Jika found suspicious JS, deep analyze immediately

---

### Task 1.3: Executor Module

Lokasi: `agent/core/executor. py`

Module untuk execute tools safely.

**Responsibilities:**
1.  Validate tool exists and is available
2.  Validate parameters
3. Check authorization (via Gate Zero)
4. Execute tool with timeout
5.  Capture output and errors
6. Handle failures gracefully

**Safety Features:**
- Timeout per tool execution
- Error catching and recovery
- Resource limits (prevent runaway processes)
- Sandboxing for dangerous operations

**Execution Result Format:**
```yaml
step_id: 1
tool: "http_probe"
status: "success" | "failed" | "timeout" | "skipped"
start_time: "2024-01-15T10:30:00Z"
end_time: "2024-01-15T10:30:05Z"
duration_seconds: 5.2
output:
  raw: "..."
  parsed: { ...  }
error: null | "error message"
```

---

### Task 1.4: Observer Module

Lokasi: `agent/core/observer.py`

Module untuk analyze tool output menggunakan LLM.

**Responsibilities:**
1. Parse raw tool output
2.  Send to LLM for interpretation
3. Extract key findings
4.  Determine severity/risk level
5.  Suggest next actions
6. Update memory with findings

**Observation Output Format:**
```yaml
step_id: 1
tool: "header_scanner"
findings:
  - type: "missing_csp"
    severity: "high"
    description: "Content-Security-Policy header is missing"
    evidence: "No CSP header in response"
    impact: "Allows injection of arbitrary scripts"
    
  - type: "missing_sri"
    severity: "medium"
    description: "Scripts loaded without Subresource Integrity"
    evidence: "3 external scripts without integrity attribute"
    
recommendations:
  - "Deep scan for XSS vulnerabilities"
  - "Analyze external scripts for tampering"
  
next_suggested_tools:
  - "xss_scanner"
  - "js_analyzer"
```

---

### Task 1.5: Memory Module

Lokasi: `agent/core/memory.py`

Module untuk maintain context dan state.

**Memory Types:**

1. **Short-term Memory (per task)**
   - Current task description
   - Execution plan
   - Steps completed
   - Findings so far
   - Current context

2. **Long-term Memory (persistent)**
   - Previous scan results (optional)
   - Known vulnerabilities found
   - Target information cache

**Memory Operations:**
- `add(key, value)` - Store information
- `get(key)` - Retrieve information
- `get_context()` - Get full context for LLM
- `summarize()` - Summarize for token efficiency
- `clear()` - Clear short-term memory
- `export()` - Export for persistence

**Context Window Management:**
- Track token count
- Summarize old context when approaching limit
- Keep most relevant information

---

## 🔨 PHASE 2: LLM Integration Layer

### Task 2.1: LLM Provider

Lokasi: `agent/llm/provider.py`

Abstraction layer untuk connect ke LLM. 

**Support multiple backends:**
1. Local model (via vLLM or transformers)
2.  OpenAI-compatible API (untuk vLLM server)
3.  Fallback options

**Provider Interface:**
```
Methods:
- connect() - Establish connection
- generate(prompt, **kwargs) - Generate response
- chat(messages, **kwargs) - Chat completion
- is_healthy() - Health check
- get_info() - Model information
```

**Configuration options:**
- `model_path` - Path untuk local model
- `api_url` - URL untuk API server
- `api_key` - API key (if needed)
- `max_tokens` - Max generation tokens
- `temperature` - Sampling temperature
- `timeout` - Request timeout

---

### Task 2.2: Prompt Engineering

Lokasi: `agent/llm/prompts.py` dan `configs/prompts/`

System prompts yang CRITICAL untuk agent behavior.

**Prompts yang perlu dibuat:**

1.  **Main System Prompt** (`system_prompt.txt`)
   - Agent identity dan role
   - Capabilities dan limitations
   - Tool usage instructions
   - Output format requirements
   - Safety guidelines

2. **Planner Prompt** (`planner_prompt. txt`)
   - How to analyze tasks
   - How to select tools
   - Plan format specification
   - Prioritization guidelines

3. **Analyzer Prompt** (`analyzer_prompt.txt`)
   - How to interpret tool output
   - Finding classification
   - Severity assessment
   - Recommendation generation

4. **Tool-specific Prompts**
   - One for each tool category
   - Specific output expectations

**Prompt Template Variables:**
```
{task} - Current user task
{available_tools} - List of available tools
{current_context} - Current memory/context
{previous_findings} - Findings so far
{tool_output} - Raw tool output to analyze
```

---

### Task 2.3: Response Parser

Lokasi: `agent/llm/parser.py`

Parse LLM responses into structured data.

**Parser harus handle:**
1. Extract tool calls from response
2. Extract findings/analysis
3. Handle malformed responses
4.  Validate required fields present

**Expected LLM Output Formats:**

For Planning:
```
<plan>
  <step id="1" tool="http_probe" action="check">
    <params>{"url": "https://example.com"}</params>
  </step>
  <step id="2" tool="header_scanner" depends="1">
    ... 
  </step>
</plan>
```

For Tool Call:
```
<tool_call>
  <name>js_analyzer</name>
  <action>analyze_script</action>
  <params>{"script_url": "https://..."}</params>
  <reason>Need to check this script for skimmer patterns</reason>
</tool_call>
```

For Analysis:
```
<analysis>
  <finding severity="high" type="missing_csp">
    <description>... </description>
    <evidence>...</evidence>
    <remediation>...</remediation>
  </finding>
</analysis>
```

**Fallback parsing:**
- If structured format fails, try regex extraction
- If still fails, ask LLM to reformat

---

## 🔨 PHASE 3: Tool System

### Task 3.1: Base Tool Class

Lokasi: `agent/tools/base.py`

Abstract base class untuk semua tools.

**Base Tool Interface:**
```
Attributes:
- name: str - Unique tool identifier
- description: str - What tool does (for LLM)
- category: str - Tool category (recon/scanner/analyzer/etc)
- parameters: dict - Required and optional params
- requires_auth: bool - Needs Gate Zero check

Methods:
- validate_params(params) - Validate input parameters
- execute(params) - Run the tool
- parse_output(raw) - Parse raw output
- get_schema() - Get tool schema for LLM
```

**Tool Schema Format (untuk LLM):**
```yaml
name: "header_scanner"
description: "Scans HTTP security headers of a target URL"
category: "scanner"
parameters:
  required:
    - name: "url"
      type: "string"
      description: "Target URL to scan"
  optional:
    - name: "follow_redirects"
      type: "boolean"
      default: true
      description: "Follow HTTP redirects"
returns:
  - name: "headers"
    type: "object"
    description: "All response headers"
  - name: "missing_security_headers"
    type: "array"
    description: "List of missing security headers"
example:
  input: {"url": "https://example.com"}
  output: {"headers": {... }, "missing_security_headers": ["CSP", "X-Frame-Options"]}
```

---

### Task 3.2: Tool Registry

Lokasi: `agent/tools/registry.py`

Central registry untuk manage semua tools.

**Registry Features:**
- `register(tool)` - Register a new tool
- `get(name)` - Get tool by name
- `list_all()` - List all available tools
- `list_by_category(category)` - Filter by category
- `get_schemas()` - Get all schemas for LLM prompt
- `search(query)` - Search tools by description

**Auto-discovery:**
- Automatically discover and register tools from tools/ subfolders
- Load tool configurations from tools_config.yaml

---

### Task 3.3: Implement Core Tools

Implement tools berikut (satu file per tool):

**RECON TOOLS:**

1. `tools/recon/http_probe.py`
   - Check if URL is alive
   - Get status code, response time
   - Detect redirects
   - Extract basic info

2. `tools/recon/tech_detect.py`
   - Detect technologies used (CMS, framework, etc)
   - Use response headers, HTML patterns
   - Identify JavaScript libraries

3. `tools/recon/js_enumerate.py`
   - Find all JavaScript files on page
   - Extract inline scripts
   - Identify third-party scripts
   - Check for source maps

**SCANNER TOOLS:**

4. `tools/scanner/header_scan. py`
   - Check security headers (CSP, HSTS, X-Frame, etc)
   - Analyze CSP policy if present
   - Check SRI on scripts
   - Rate security posture

5. `tools/scanner/nuclei_scan.py`
   - Wrapper for Nuclei scanner
   - Run with specific templates
   - Parse output into findings
   - Magecart-specific templates

6. `tools/scanner/ssl_scan.py`
   - Check SSL/TLS configuration
   - Certificate validation
   - Protocol versions

**ANALYZER TOOLS:**

7. `tools/analyzer/js_analyzer.py`
   - Download and analyze JavaScript
   - Deobfuscation (basic)
   - Pattern matching for suspicious code
   - Extract URLs and endpoints

8. `tools/analyzer/skimmer_detect. py`
   - Specialized Magecart detection
   - 100+ skimmer patterns
   - Behavioral analysis
   - Exfiltration domain detection

9. `tools/analyzer/csp_analyzer.py`
   - Deep CSP policy analysis
   - Find bypass possibilities
   - Check for unsafe directives
   - Suggest improvements

**REPORTER TOOLS:**

10. `tools/reporter/report_gen. py`
    - Generate structured reports
    - Multiple formats (JSON, Markdown, HTML)
    - Include all findings
    - Severity summary

---

### Task 3.4: Tool Configuration

Lokasi: `configs/tools_config. yaml`

Configuration untuk semua tools:

```yaml
tools:
  http_probe:
    enabled: true
    timeout: 30
    user_agent: "RedTeamAgent/1.0"
    max_redirects: 5
    
  nuclei:
    enabled: true
    binary_path: "/usr/bin/nuclei"
    templates_path: "./nuclei-templates"
    severity_filter: ["critical", "high", "medium"]
    rate_limit: 100
    
  js_analyzer:
    enabled: true
    max_file_size: 5242880  # 5MB
    deobfuscate: true
    pattern_file: "./configs/skimmer_patterns. yaml"
    
  # ... more tools
```

---

## 🔨 PHASE 4: Security Layer (Gate Zero)

### Task 4.1: Gate Zero Implementation

Lokasi: `agent/security/gate_zero.py`

Core security gate yang HARUS dilewati sebelum any action.

**Gate Zero Checks:**

1. **Authorization Check**
   - Is there valid engagement/authorization?
   - Is target in scope?
   - Is action type allowed?

2.  **Scope Validation**
   - Target domain/IP validation
   - Subdomains allowed? 
   - Path restrictions?

3. **Action Safety Check**
   - Is action destructive?
   - Rate limiting check
   - Blacklist check

4.  **Audit Logging**
   - Log every check
   - Log every action
   - Timestamp and context

**Gate Zero Interface:**
```
Methods:
- check_authorization(engagement_id) - Verify engagement
- validate_target(target) - Check target in scope
- validate_action(action_type) - Check action allowed
- full_check(target, action) - Run all checks
- log_action(action, result) - Audit log
```

**Engagement Format:**
```yaml
engagement_id: "ENG-2024-001"
client: "Example Corp"
scope:
  domains:
    - "*. example.com"
    - "example.org"
  exclude:
    - "prod. example.com"
    - "api.example.com"
allowed_actions:
  - "recon"
  - "scan"
  - "analyze"
  # - "exploit"  # NOT allowed unless specified
start_date: "2024-01-15"
end_date: "2024-02-15"
rules_of_engagement:
  - "No denial of service"
  - "No data exfiltration"
  - "Report critical findings immediately"
```

---

### Task 4.2: Scope Validator

Lokasi: `agent/security/scope_validator.py`

Validate targets against engagement scope.

**Validation Logic:**
1. Parse target URL/domain
2. Check against allowed domains (with wildcard support)
3. Check against exclusions
4.  Validate IP ranges if applicable
5. Return clear allow/deny with reason

---

### Task 4.3: Audit Logger

Lokasi: `agent/security/audit_logger.py`

Comprehensive logging untuk semua actions. 

**Log Entry Format:**
```yaml
timestamp: "2024-01-15T10:30:00. 000Z"
engagement_id: "ENG-2024-001"
session_id: "sess_abc123"
action:
  type: "tool_execution"
  tool: "nuclei_scan"
  target: "https://example.com"
  parameters: {... }
authorization:
  checked: true
  result: "allowed"
  scope_match: "*. example.com"
result:
  status: "success"
  duration_ms: 5200
  findings_count: 3
user:
  id: "user_123"
  ip: "1.2.3. 4"
```

**Log Storage:**
- File-based (rotating logs)
- Optional: Database storage
- Optional: Remote logging (SIEM integration)

---

## 🔨 PHASE 5: Configuration System

### Task 5.1: Main Agent Config

Lokasi: `configs/agent_config. yaml`

```yaml
agent:
  name: "RedTeam Agent"
  version: "1.0.0"
  
  # Core settings
  max_iterations: 20
  task_timeout: 600
  verbose: true
  
  # LLM settings
  llm:
    provider: "local"  # or "api"
    model_path: "./models/finetuned/redteam-v1"
    api_url: "http://localhost:8000/v1"
    max_tokens: 4096
    temperature: 0.7
    
  # Memory settings
  memory:
    max_context_tokens: 8000
    summarize_threshold: 6000
    persist_memory: false
    
  # Security settings
  security:
    require_authorization: true
    engagement_file: "./configs/engagement. yaml"
    audit_log_path: "./logs/audit/"
    
  # Output settings
  output:
    auto_report: true
    report_format: "markdown"
    output_dir: "./outputs/"
```

---

### Task 5.2: Configuration Loader

Lokasi: `agent/utils/config. py`

Load dan validate configurations.

**Features:**
- Load from YAML files
- Environment variable override
- Validation of required fields
- Default values
- Config merging (base + override)

---

## 🔨 PHASE 6: User Interfaces

### Task 6.1: CLI Runner

Lokasi: `scripts/run_agent.py`

Command-line interface untuk run agent.

**Commands:**

```bash
# Run single task
python run_agent.py run "Scan example.com for Magecart"

# Run with engagement file
python run_agent.py run "Scan target" --engagement ./engagement.yaml

# Interactive mode
python run_agent.py interactive

# List available tools
python run_agent.py tools list

# Check tool details
python run_agent.py tools info js_analyzer

# Validate engagement
python run_agent.py validate --engagement ./engagement.yaml

# Run with specific config
python run_agent.py run "task" --config ./my_config.yaml
```

**CLI Features:**
- Rich terminal output (colors, progress bars)
- Real-time step display
- Interrupt handling (Ctrl+C saves state)
- Output to file option

---

### Task 6.2: Interactive Mode

Lokasi: `scripts/interactive.py`

Interactive chat-like interface. 

**Features:**
- Multi-turn conversation
- Command shortcuts
- History navigation
- Context display
- Tool output preview

**Example Session:**
```
╔══════════════════════════════════════════════════════════════╗
║           🤖 RED TEAM AI AGENT - Interactive Mode            ║
╠══════════════════════════════════════════════════════════════╣
║  Type 'help' for commands, 'exit' to quit                   ║
╚══════════════════════════════════════════════════════════════╝

[engagement: ENG-2024-001] [scope: *.example. com]

You > Scan the checkout page for Magecart vulnerabilities

Agent > I'll analyze the checkout page for Magecart risks. 

[PLANNING] Creating execution plan... 
  Step 1: Probe target URL
  Step 2: Check security headers
  Step 3: Enumerate JavaScript files
  Step 4: Analyze scripts for skimmer patterns
  Step 5: Check third-party resources

[EXECUTING] Step 1: http_probe
  ✓ Target is alive (200 OK, 234ms)

[EXECUTING] Step 2: header_scanner
  ⚠ Missing CSP header
  ⚠ Missing X-Frame-Options
  ✓ HSTS present

[EXECUTING] Step 3: js_enumerate
  Found 12 JavaScript files
  - 3 inline scripts
  - 5 first-party scripts
  - 4 third-party scripts

[EXECUTING] Step 4: skimmer_detect
  ⚠ Suspicious pattern in checkout. min.js
  ⚠ Obfuscated code detected

...  [detailed results] ...

[REPORT] Analysis complete.  Found 3 high-severity issues. 

Do you want me to:
1. Generate full report
2. Deep-dive into suspicious script
3. Check additional pages

You > 2

Agent > Analyzing checkout. min.js in detail... 
```

---

### Task 6.3: API Server

Lokasi: `scripts/serve_api.py`

REST API untuk programmatic access.

**Endpoints:**

```
POST /api/v1/task
  - Submit new task for execution
  - Body: { "task": ".. .", "engagement_id": "..." }
  - Returns: { "task_id": ".. .", "status": "queued" }

GET /api/v1/task/{task_id}
  - Get task status and results
  - Returns: { "status": ".. .", "progress": .. ., "findings": [... ] }

GET /api/v1/task/{task_id}/stream
  - SSE stream for real-time updates
  
POST /api/v1/analyze
  - Quick analysis without full task
  - Body: { "type": "js", "content": "..." }
  - Returns: { "findings": [...] }

GET /api/v1/tools
  - List available tools
  
GET /api/v1/health
  - Health check

POST /api/v1/engagement
  - Create/update engagement
```

**API Features:**
- Authentication (API keys)
- Rate limiting
- Request validation
- Async task execution
- WebSocket support (optional)

---

## 🔨 PHASE 7: Testing

### Task 7. 1: Unit Tests

Lokasi: `tests/`

Test files untuk setiap component:

```
tests/
├── test_core/
│   ├── test_agent. py
│   ├── test_planner.py
│   ├── test_executor.py
│   └── test_memory.py
├── test_tools/
│   ├── test_base_tool.py
│   ├── test_header_scanner.py
│   └── test_js_analyzer.py
├── test_security/
│   ├── test_gate_zero.py
│   └── test_scope_validator.py
├── test_llm/
│   ├── test_provider. py
│   └── test_parser.py
└── test_integration/
    ├── test_full_scan.py
    └── test_real_targets.py
```

---

### Task 7.2: Integration Tests

Test full agent workflow:

1. **Happy Path Test**
   - Valid engagement
   - Target in scope
   - Full scan completes
   - Report generated

2. **Security Tests**
   - Reject without authorization
   - Reject out-of-scope targets
   - Rate limiting works

3. **Error Handling Tests**
   - Tool failure recovery
   - LLM timeout handling
   - Invalid input handling

4. **Performance Tests**
   - Response time benchmarks
   - Memory usage
   - Concurrent requests

---

## 📋 Implementation Order

```
RECOMMENDED BUILD ORDER:
═══════════════════════════════════════════════════════════

WEEK 1: Foundation
├── Day 1-2: Project structure + base classes
├── Day 3-4: LLM provider + prompts
├── Day 5-6: Memory module
└── Day 7: Basic agent loop (without tools)

WEEK 2: Tools
├── Day 1-2: Tool base class + registry
├── Day 3-4: Recon tools (http_probe, tech_detect)
├── Day 5-6: Scanner tools (header_scan, js_enumerate)
└── Day 7: Integration testing

WEEK 3: Analysis & Security
├── Day 1-2: Analyzer tools (js_analyzer, skimmer_detect)
├── Day 3-4: Gate Zero + audit logging
├── Day 5-6: Report generation
└── Day 7: Full workflow testing

WEEK 4: Interfaces & Polish
├── Day 1-2: CLI runner
├── Day 3-4: Interactive mode
├── Day 5-6: API server
└── Day 7: Documentation + final testing
```

---

## ⚠️ Critical Notes untuk Copilot

1. **Security First**
   - SELALU implement Gate Zero checks
   - NEVER skip authorization
   - Log EVERYTHING

2. **Error Handling**
   - Every tool call MUST have try/except
   - Graceful degradation
   - Clear error messages

3.  **Token Efficiency**
   - Keep prompts concise
   - Summarize long contexts
   - Don't repeat information

4. **Modularity**
   - Each tool independent
   - Easy to add new tools
   - Configuration-driven

5.  **Testing**
   - Test each component
   - Mock external services
   - Test edge cases

---

## 🚀 Getting Started

Mulai dengan command ini ke Copilot:

```
Berdasarkan GUIDE_AGENT_FRAMEWORK.md:

1. Buat project structure (semua folder dan __init__.py files)
2.  Implement Task 1. 1: Base Agent Class
3. Include comprehensive docstrings
4.  Add type hints
5. Include basic error handling

Mulai sekarang. 
```

Lalu lanjut ke task berikutnya secara sequential. 
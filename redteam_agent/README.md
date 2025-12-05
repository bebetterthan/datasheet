# Red Team Agent Framework

AI-powered security assessment agent built with a fine-tuned Qwen 2.5 Coder 7B model.

## Features

- **THINK + ACTION + REPORT**: Complete autonomous agent loop
- **Security Gate (Gate Zero)**: All actions validated against whitelist/blacklist
- **Modular Tools**: Nmap, Nuclei, Gobuster, and more
- **Structured Reports**: JSON, Markdown, HTML output formats
- **Memory Management**: Context-aware execution with summarization

## Installation

```bash
cd redteam_agent
pip install -e .
```

## Quick Start

```python
from agent import RedTeamAgent
from agent.utils.config import Config

# Load configuration
config = Config("config.yaml")

# Initialize agent
agent = RedTeamAgent(config)

# Execute task
result = agent.execute_task(
    task="Perform reconnaissance on target 192.168.1.100",
    scope=["192.168.1.0/24"]
)

# Get report
print(result["report"])
```

## Architecture

```
agent/
├── core/           # Core agent engine
│   ├── agent.py    # Main RedTeamAgent class
│   ├── planner.py  # Task planning
│   ├── executor.py # Tool execution
│   ├── observer.py # Output analysis
│   ├── memory.py   # Context management
│   └── reporter.py # Report generation
├── llm/            # LLM interface
│   ├── provider.py # Model loading/inference
│   └── prompts.py  # System prompts
├── security/       # Security layer
│   └── gate.py     # Gate Zero authorization
├── tools/          # Security tools
│   ├── recon/      # Reconnaissance tools
│   ├── scanner/    # Vulnerability scanners
│   ├── analyzer/   # Analysis tools
│   └── reporter/   # Report tools
└── utils/          # Utilities
    ├── config.py   # Configuration
    └── logger.py   # Logging
```

## Configuration

Create `config.yaml`:

```yaml
llm:
  model_path: ~/redteam-ai-agent/outputs/run_20251130_084846/final_model
  base_model: Qwen/Qwen2.5-Coder-7B-Instruct

security:
  enabled: true
  whitelist:
    - 192.168.1.0/24
    - target.example.com
  blacklist:
    - 127.0.0.1

agent:
  max_steps: 50
  require_approval: false
```

## Safety Notice

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- Only test systems you have explicit permission to test
- Configure the whitelist carefully
- Review all actions before execution in production
- Follow responsible disclosure practices

## License

MIT License

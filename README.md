# 🛡️ Security Dataset Scraper

**Comprehensive tool for collecting security/pentesting datasets for LLM fine-tuning**

Build high-quality training datasets for Red Team AI agents by scraping and processing security knowledge from multiple authoritative sources.

## ✨ Features

### Core Features

- **Multi-Source Scraping**: HackTricks, CTFTime, Exploit-DB, NVD/CVE, Nuclei Templates, PayloadsAllTheThings, OWASP
- **Intelligent Processing**: Deduplication, quality filtering, automatic categorization
- **Flexible Output**: Alpaca, ShareGPT, OpenAI, Axolotl, LLaMA-Factory, Unsloth formats
- **Q&A Generation**: Automatic question-answer pair generation from content
- **Resume Capability**: SQLite-based progress tracking for interrupted scrapes
- **Rate Limiting**: Adaptive rate limiting with proxy rotation support
- **Docker Support**: Easy deployment with Docker and docker-compose

### Advanced Features (NEW)

- **🔄 Data Augmentation**: Automatic paraphrasing, context variation, difficulty scaling
- **✅ Data Validation**: Comprehensive quality checks with detailed reports
- **📊 Analytics**: Token counting, category distribution, quality scoring
- **💾 Disk Caching**: TTL-based caching with compression
- **🔁 Circuit Breaker**: Robust retry logic with exponential backoff
- **📦 Batch Processing**: Parallel processing with checkpointing
- **📈 Streaming Export**: Memory-efficient export for large datasets

## 📊 Target Output

- **10,000+ Q&A pairs** covering security topics
- **13+ security categories**: Web Security, Exploitation, Privilege Escalation, Credential Access, and more
- **Multiple formats** ready for fine-tuning with Axolotl, LLaMA-Factory, Unsloth

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/your-repo/security-dataset-scraper.git
cd security-dataset-scraper

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -e ".[dev]"

# Install Playwright browsers (for JS-rendered pages)
playwright install chromium
```

### Quick Start with Make

```bash
# Setup everything
make quickstart

# Run full pipeline
make scrape-all
make process
make export-axolotl
```

### Basic Usage

```bash
# List available sources
python main.py list

# Scrape from specific sources
python main.py scrape --source hacktricks --source owasp --limit 100

# Scrape all sources
python main.py scrape --all --limit 500

# Process scraped data
python main.py process -i data/raw -o data/processed

# Generate training dataset
python main.py generate -i data/processed -o data/dataset -f alpaca

# Quality check
python main.py quality -i data/dataset/train.json --strict

# Augment dataset
python main.py augment -i data/dataset/train.json -m 2.0

# Export to different formats
python main.py export -i data/dataset -f axolotl
python main.py export -i data/dataset -f llama_factory

# Analyze dataset
python main.py analyze -i data/dataset/train.json -o report.md

# Run full pipeline
python main.py run --all --limit 100

# View statistics
python main.py stats -i data/dataset --detailed
```

### Docker Usage

```bash
# Build and run
docker compose up --build

# Run specific command
docker compose run scraper scrape --source hacktricks --limit 50

# Run full pipeline
docker compose run scraper run --all --limit 100

# With Jupyter for analysis
docker compose --profile analysis up
```

## 📁 Project Structure

```
datasheet_scraper/
├── main.py                    # CLI entry point
├── requirements.txt           # Python dependencies
├── pyproject.toml             # Project configuration
├── setup.py                   # Package setup
├── Makefile                   # Automation commands
├── Dockerfile                 # Docker configuration
├── docker-compose.yml         # Docker Compose configuration
├── config/
│   ├── config.yaml           # Main configuration
│   └── sources.yaml          # Source-specific configuration
├── src/
│   ├── scrapers/             # Source-specific scrapers
│   │   ├── base_scraper.py   # Base scraper class
│   │   ├── hacktricks_scraper.py
│   │   ├── ctf_writeup_scraper.py
│   │   ├── exploit_db_scraper.py
│   │   ├── cve_scraper.py
│   │   ├── nuclei_templates_scraper.py
│   │   ├── payloads_scraper.py
│   │   └── owasp_scraper.py
│   ├── processors/           # Data processing modules
│   │   ├── content_cleaner.py
│   │   ├── format_converter.py
│   │   ├── deduplicator.py
│   │   ├── quality_checker.py
│   │   ├── category_classifier.py
│   │   ├── dataset_exporter.py   # NEW: Multi-format export
│   │   ├── batch_processor.py    # NEW: Parallel batch processing
│   │   ├── data_validator.py     # NEW: Quality validation
│   │   └── data_augmenter.py     # NEW: Data augmentation
│   ├── generators/           # Q&A generation
│   │   └── qa_generator.py
│   └── utils/                # Utilities
│       ├── config.py
│       ├── logger.py
│       ├── rate_limiter.py
│       ├── proxy_manager.py
│       ├── cache.py          # NEW: Disk caching
│       ├── retry.py          # NEW: Circuit breaker
│       └── analytics.py      # NEW: Dataset analytics
├── data/                     # Output data
│   ├── raw/                  # Raw scraped data
│   ├── processed/            # Processed data
│   ├── dataset/              # Final dataset
│   ├── exports/              # Exported formats
│   └── checkpoints/          # Processing checkpoints
├── notebooks/                # Jupyter notebooks
│   └── usage_examples.ipynb  # Usage examples
├── scripts/                  # Utility scripts
│   └── init_db.sql          # PostgreSQL init
└── tests/                    # Unit tests
```

## 📦 Data Sources

| Source                   | Description                            | Content Type               |
| ------------------------ | -------------------------------------- | -------------------------- |
| **HackTricks**           | Comprehensive pentesting documentation | Methodology, techniques    |
| **CTFTime**              | CTF competition writeups               | Challenges, solutions      |
| **Exploit-DB**           | Public exploits database               | Exploit code, advisories   |
| **NVD/CVE**              | Vulnerability database                 | CVE details, CVSS scores   |
| **Nuclei Templates**     | Security detection templates           | YAML templates             |
| **PayloadsAllTheThings** | Security payloads collection           | Payloads, techniques       |
| **OWASP**                | Security best practices                | CheatSheets, Testing Guide |

## 🎯 Security Categories

The dataset covers these security domains:

- **Reconnaissance**: Information gathering, network scanning
- **Web Security**: SQL injection, XSS, CSRF, SSRF, etc.
- **Exploitation**: Buffer overflow, RCE, code injection
- **Privilege Escalation**: Linux/Windows privesc techniques
- **Credential Access**: Password attacks, token theft
- **Lateral Movement**: Active Directory, pivoting
- **Defense Evasion**: AV bypass, obfuscation
- **Persistence**: Backdoors, rootkits
- **Cryptography**: Encryption, hashing, PKI

## 📄 Output Format

### Alpaca Format (Default)

```json
{
  "instruction": "How do I perform SQL injection on a login form?",
  "input": "",
  "output": "SQL injection on login forms can be performed by...",
  "category": "web_security/sql_injection",
  "source": "https://book.hacktricks.xyz/...",
  "difficulty": "intermediate",
  "tags": ["sqli", "web", "authentication"]
}
```

### ShareGPT Format

```json
{
  "conversations": [
    { "from": "human", "value": "How do I perform SQL injection?" },
    { "from": "gpt", "value": "SQL injection can be performed by..." }
  ]
}
```

## ⚙️ Configuration

Edit `config/config.yaml` to customize:

```yaml
scraping:
  timeout: 30
  max_retries: 3
  concurrent_requests: 10

rate_limiting:
  requests_per_second: 2.0
  adaptive: true

processing:
  min_quality_score: 0.5
  deduplicate: true

output:
  format: "alpaca"
  split_dataset: true
  train_ratio: 0.8
```

## 🔧 CLI Commands

| Command    | Description                     |
| ---------- | ------------------------------- |
| `scrape`   | Scrape content from sources     |
| `process`  | Process and clean scraped data  |
| `generate` | Generate training dataset       |
| `run`      | Run full pipeline               |
| `stats`    | Show dataset statistics         |
| `validate` | Validate dataset format         |
| `quality`  | Run comprehensive quality check |
| `augment`  | Augment dataset with variations |
| `export`   | Export to fine-tuning formats   |
| `analyze`  | Generate analytics report       |
| `clean`    | Clean cache and temp files      |
| `list`     | List available sources          |

### Common Options

- `--verbose, -v`: Enable verbose output
- `--config, -c`: Specify config file
- `--limit, -l`: Limit items per source
- `--resume`: Resume from checkpoint
- `--dry-run`: Preview without scraping

## 🎛️ Export Formats

| Format          | Description                     | Use With                  |
| --------------- | ------------------------------- | ------------------------- |
| `alpaca`        | Standard instruction format     | Most fine-tuning tools    |
| `sharegpt`      | Conversation format             | ShareGPT-compatible tools |
| `openai`        | OpenAI chat format              | OpenAI API fine-tuning    |
| `axolotl`       | Axolotl YAML config + dataset   | Axolotl trainer           |
| `llama_factory` | LLaMA-Factory compatible        | LLaMA-Factory             |
| `unsloth`       | Unsloth format with HF datasets | Unsloth trainer           |

## 🛠️ Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
make test-cov

# Code formatting
make format

# Linting
make lint

# All checks
make check-all
```

## ⚠️ Legal & Ethical Use

This tool is intended for **educational and research purposes only**. Users must:

- Respect robots.txt and rate limits
- Comply with each source's Terms of Service
- Use collected data responsibly
- Not use for malicious purposes

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

---

**Built for Red Team AI Research** 🔴

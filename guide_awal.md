# Complete Guide: Deploy & Fine-tune Red Team AI Agent

## 🎯 Project Overview

Saya sudah terkoneksi ke GCP server dengan spesifikasi:
- **GPU:** NVIDIA L4 (24GB VRAM)
- **CPU:** 16 vCPU (8 cores)
- **RAM:** 64 GB
- **OS:** Deep Learning on Linux
- **Storage:** 150-200 GB SSD

Saya ingin:
1. Setup environment untuk fine-tuning
2. Download base model (Qwen 2.5 Coder 7B)
3.  Prepare dataset untuk Red Team AI Agent
4. Fine-tune model dengan LoRA
5.  Test model hasil fine-tuning
6. Deploy sebagai API server

Tolong guide saya step-by-step dengan penjelasan untuk setiap command. 

---

## 📋 PHASE 1: Environment Verification & Setup

### Step 1. 1: Verify GPU & System

Pertama, saya perlu memastikan GPU dan system sudah siap. 

Tolong buatkan script untuk:
1. Check NVIDIA driver terinstall dengan benar
2.  Check CUDA version
3. Check available GPU memory
4. Check system RAM
5. Check disk space
6.  Verify Python version

Expected output format:
```
=== SYSTEM CHECK ===
GPU: NVIDIA L4 (24GB) ✅
CUDA: 12. x ✅
Driver: 535.xx ✅
RAM: 64GB available ✅
Disk: xxxGB free ✅
Python: 3. 10+ ✅
```

### Step 1.2: Create Project Structure

Buatkan struktur folder project yang organized:

```
~/redteam-ai-agent/
├── configs/
│   └── training_config.yaml
├── data/
│   ├── raw/
│   ├── processed/
│   └── final/
├── models/
│   ├── base/
│   └── finetuned/
├── scripts/
│   ├── setup. sh
│   ├── train.py
│   ├── evaluate.py
│   ├── inference.py
│   └── serve.py
├── notebooks/
│   └── experiments. ipynb
├── logs/
├── outputs/
└── requirements.txt
```

### Step 1. 3: Install Dependencies

Buatkan `requirements.txt` dengan semua dependencies yang diperlukan:

**Core ML:**
- torch (dengan CUDA support)
- transformers
- datasets
- accelerate
- peft (untuk LoRA)
- bitsandbytes (untuk quantization)
- trl (untuk SFTTrainer)

**Optimization:**
- unsloth (untuk faster training)
- flash-attn (kalau compatible)
- xformers

**Serving:**
- vllm (untuk inference server)
- fastapi
- uvicorn

**Utilities:**
- rich (untuk beautiful terminal output)
- wandb (optional, untuk experiment tracking)
- jupyter
- ipywidgets

Juga buatkan `setup. sh` script yang:
1. Create virtual environment
2.  Install semua dependencies
3.  Verify installation
4. Download base model

---

## 📋 PHASE 2: Download & Prepare Base Model

### Step 2.1: Download Qwen 2. 5 Coder 7B

Buatkan script `scripts/download_model.py` yang:

1. Download model dari HuggingFace: `Qwen/Qwen2. 5-Coder-7B-Instruct`
2. Atau versi 4-bit quantized: `unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit`
3. Save ke `models/base/`
4. Verify model integrity
5. Show progress bar saat download
6. Handle resume kalau download terputus

Juga include option untuk:
- Download dengan HuggingFace token (untuk gated models)
- Choose antara full precision atau quantized

### Step 2.2: Test Base Model

Buatkan script `scripts/test_base_model.py` yang:

1.  Load model dalam 4-bit quantization
2. Run simple inference test
3.  Measure:
   - Load time
   - VRAM usage
   - Inference speed (tokens/second)
4. Test dengan beberapa prompt security-related:
   - "Jelaskan apa itu SQL Injection"
   - "Bagaimana cara detect XSS vulnerability?"
   - "Apa itu Magecart attack?"

Output expected:
```
=== BASE MODEL TEST ===
Model: Qwen2.5-Coder-7B-Instruct
Load time: X.X seconds
VRAM usage: XX. X GB / 24 GB
Inference speed: XX tokens/sec

Test 1: SQL Injection explanation
[Response...]
✅ Passed

Test 2: XSS detection
[Response...]
✅ Passed
```

---

## 📋 PHASE 3: Dataset Preparation

### Step 3.1: Dataset Format

Saya akan menggunakan format Alpaca untuk dataset:

```json
{
  "instruction": "Task atau pertanyaan untuk model",
  "input": "Context tambahan (optional, bisa kosong)",
  "output": "Response yang diharapkan dari model",
  "category": "Kategori data (untuk tracking)",
  "tags": ["relevant", "tags"]
}
```

Buatkan script `scripts/prepare_dataset. py` yang:

1. Load raw JSON files dari `data/raw/`
2.  Validate format setiap entry
3. Clean data:
   - Remove duplicates
   - Fix encoding issues
   - Normalize whitespace
4. Convert ke format yang siap training
5. Split menjadi train/validation (90/10)
6. Save ke `data/final/`
7. Generate statistics:
   - Total samples
   - Average length (instruction, output)
   - Category distribution
   - Token count distribution

### Step 3.2: Sample Dataset untuk Testing

Karena saya belum punya full dataset, buatkan sample dataset dengan 50-100 entries untuk testing pipeline.

Kategori yang harus di-cover:
1. **Reconnaissance** (10 samples)
   - Subdomain enumeration
   - Port scanning
   - Technology fingerprinting

2.  **Vulnerability Identification** (15 samples)
   - XSS detection
   - SQL Injection detection
   - Misconfiguration identification

3. **Magecart Specific** (15 samples)
   - Skimmer detection
   - JavaScript analysis
   - Payment security

4. **Exploitation Techniques** (10 samples)
   - PoC development
   - Payload crafting
   - Bypass techniques

5. **Defense & Remediation** (10 samples)
   - Fix recommendations
   - Security hardening
   - Best practices

Format setiap sample harus:
- Technically accurate
- Detailed dan actionable
- Include code examples where relevant
- Always include defensive perspective

Save sebagai `data/raw/sample_dataset. json`

### Step 3.3: Dataset Validation

Buatkan script `scripts/validate_dataset.py` yang:

1. Check JSON validity
2. Verify required fields exist
3. Check for:
   - Empty fields
   - Too short responses (< 50 chars)
   - Too long responses (> 4000 chars)
   - Duplicates
4. Validate code blocks (proper formatting)
5. Generate quality report

---

## 📋 PHASE 4: Fine-tuning dengan LoRA

### Step 4.1: Training Configuration

Buatkan `configs/training_config.yaml`:

```yaml
# Model settings
model:
  name: "unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit"
  max_seq_length: 2048
  load_in_4bit: true

# LoRA settings
lora:
  r: 16
  lora_alpha: 32
  target_modules:
    - "q_proj"
    - "k_proj"
    - "v_proj"
    - "o_proj"
    - "gate_proj"
    - "up_proj"
    - "down_proj"
  lora_dropout: 0.05
  bias: "none"

# Training settings
training:
  num_epochs: 2
  batch_size: 4
  gradient_accumulation_steps: 4
  learning_rate: 2e-4
  lr_scheduler: "cosine"
  warmup_ratio: 0.05
  weight_decay: 0.01
  
# Optimization
optimization:
  fp16: true
  gradient_checkpointing: true
  optim: "adamw_8bit"
  
# Saving
saving:
  output_dir: "./outputs"
  save_steps: 500
  save_total_limit: 3
  
# Logging
logging:
  logging_steps: 50
  report_to: "none"  # atau "wandb" kalau mau tracking
```

### Step 4.2: Training Script

Buatkan `scripts/train.py` yang comprehensive:

**Features yang harus ada:**
1. Load config dari YAML
2. Load model dengan Unsloth (untuk speed)
3. Apply LoRA adapters
4. Load dan format dataset
5. Setup SFTTrainer
6. Training dengan:
   - Progress bar
   - Loss logging
   - Checkpoint saving
   - VRAM monitoring
7.  Save final model
8. Generate training summary

**CLI arguments:**
```bash
python scripts/train.py \
    --config configs/training_config.yaml \
    --dataset data/final/train.json \
    --output_dir outputs/run_001 \
    --resume_from_checkpoint latest  # optional
```

**Output yang diharapkan:**
```
=== RED TEAM AI AGENT TRAINING ===
Model: Qwen2.5-Coder-7B-Instruct
Dataset: 10,000 samples
Epochs: 2
Effective batch size: 16

[============================] 100% | Epoch 2/2
Loss: 0.XXX | LR: X.XXe-X | VRAM: XX. X GB

✅ Training complete! 
Total time: X hours XX minutes
Model saved to: outputs/run_001/final_model
```

### Step 4.3: Training Monitor

Buatkan `scripts/monitor. py` yang bisa dijalankan di terminal terpisah:

1. Real-time GPU monitoring (nvidia-smi)
2. Training progress (dari log files)
3. Loss curve (ASCII art di terminal)
4.  Estimated time remaining
5. Alert kalau ada issue (OOM, loss spike, dll)

---

## 📋 PHASE 5: Evaluation & Testing

### Step 5.1: Model Evaluation

Buatkan `scripts/evaluate.py` yang:

1. Load fine-tuned model
2. Run evaluation pada test set
3. Calculate metrics:
   - Perplexity
   - Response quality (length, completeness)
   - Accuracy per category
4. Compare dengan base model
5. Generate evaluation report

### Step 5.2: Interactive Testing

Buatkan `scripts/chat.py` untuk interactive testing:

```bash
python scripts/chat.py --model outputs/run_001/final_model
```

Features:
1. Interactive chat loop
2. Multi-turn conversation support
3. System prompt customization
4.  Save conversation history
5.  Response timing

### Step 5. 3: Security-Specific Test Suite

Buatkan `scripts/security_test.py` dengan test cases:

```python
test_cases = [
    {
        "name": "Magecart Detection",
        "prompt": "Analyze this JavaScript for Magecart patterns: [code]",
        "expected_elements": ["skimmer", "detection", "exfiltration"]
    },
    {
        "name": "XSS Identification",
        "prompt": "Find XSS vulnerabilities in this code: [code]",
        "expected_elements": ["payload", "sanitization", "remediation"]
    },
    # ... more test cases
]
```

Score model berdasarkan:
- Apakah identify vulnerability correctly
- Apakah provide valid PoC
- Apakah include remediation
- Technical accuracy

---

## 📋 PHASE 6: Deployment sebagai API Server

### Step 6.1: vLLM Server Setup

Buatkan `scripts/serve_vllm.py`:

1. Load fine-tuned model dengan vLLM
2. Start OpenAI-compatible API server
3. Configure:
   - Port: 8000
   - Max concurrent requests
   - Timeout settings
4. Health check endpoint
5.  Graceful shutdown

```bash
python scripts/serve_vllm.py \
    --model outputs/run_001/final_model \
    --port 8000 \
    --max-model-len 4096
```

### Step 6.2: Custom API Server (Alternative)

Buatkan `scripts/serve_fastapi.py` dengan FastAPI:

**Endpoints:**
```
POST /v1/chat/completions    - OpenAI-compatible chat
POST /v1/completions         - Text completion
POST /analyze                - Security analysis endpoint
POST /scan                   - Vulnerability scan
GET  /health                 - Health check
GET  /metrics                - Server metrics
```

**Security Analysis Endpoint:**
```python
@app.post("/analyze")
async def analyze_security(request: AnalysisRequest):
    """
    Specialized endpoint untuk security analysis. 
    
    Request:
    {
        "target_type": "javascript" | "html" | "url" | "code",
        "content": "...",
        "analysis_type": "magecart" | "xss" | "sqli" | "general"
    }
    
    Response:
    {
        "vulnerabilities": [... ],
        "risk_level": "critical" | "high" | "medium" | "low",
        "poc": "...",
        "remediation": "..."
    }
    """
```

### Step 6.3: Systemd Service

Buatkan systemd service file untuk auto-start:

`/etc/systemd/system/redteam-agent.service`

Features:
- Auto-start on boot
- Auto-restart on crash
- Logging ke journald
- Resource limits

### Step 6.4: Client SDK

Buatkan simple Python client `scripts/client.py`:

```python
from redteam_client import RedTeamAgent

agent = RedTeamAgent(base_url="http://localhost:8000")

# Chat
response = agent.chat("Analyze this JavaScript for Magecart patterns...")

# Specialized analysis
result = agent.analyze(
    content="<script>... </script>",
    analysis_type="magecart"
)

print(result. vulnerabilities)
print(result.remediation)
```

---

## 📋 PHASE 7: Testing & Validation

### Step 7.1: End-to-End Test

Buatkan `scripts/e2e_test.py` yang:

1. Start API server (background)
2. Wait for server ready
3. Run test suite via API
4. Validate responses
5. Performance benchmarks:
   - Requests per second
   - Latency (p50, p95, p99)
   - Concurrent request handling
6. Stop server
7. Generate report

### Step 7. 2: Security Gate Test

Buatkan `scripts/gate_test.py` yang verify Gate Zero:

1. Test tanpa authorization → should reject
2. Test dengan invalid scope → should reject
3. Test dengan proper authorization → should work
4.  Verify audit logging
5. Check rate limiting

---

## 📋 Utility Scripts

### Monitoring Dashboard

Buatkan `scripts/dashboard.py`:

ASCII dashboard di terminal showing:
```
╔══════════════════════════════════════════════════════════════╗
║              RED TEAM AI AGENT - DASHBOARD                   ║
╠══════════════════════════════════════════════════════════════╣
║  GPU: NVIDIA L4                    VRAM: 18.2/24. 0 GB (76%)  ║
║  CPU: 12%                          RAM:  24.5/64.0 GB (38%)  ║
║  Disk: 89. 2/200 GB (45%)           Uptime: 2h 34m            ║
╠══════════════════════════════════════════════════════════════╣
║  API Server: ● RUNNING             Port: 8000                ║
║  Requests: 1,234                   Avg Latency: 245ms        ║
║  Errors: 2 (0.16%)                 Active: 3                 ║
╠══════════════════════════════════════════════════════════════╣
║  Recent Requests:                                            ║
║  [12:34:01] POST /analyze - 200 - 234ms                      ║
║  [12:34:03] POST /chat - 200 - 1. 2s                          ║
║  [12:34:05] GET /health - 200 - 12ms                         ║
╚══════════════════════════════════════════════════════════════╝
```

### Cleanup Script

Buatkan `scripts/cleanup.py`:

1. Remove old checkpoints (keep last 3)
2. Clear cache files
3. Compress logs
4. Report disk space freed

---

## 📋 Documentation

### README.md

Buatkan comprehensive README dengan:

1. Project overview
2. Requirements
3. Quick start guide
4.  Configuration options
5. API documentation
6. Training guide
7.  Troubleshooting
8. Contributing guidelines

### API Documentation

Generate OpenAPI/Swagger documentation untuk API endpoints. 

---

## 🚀 Execution Order

Tolong guide saya menjalankan semua ini dengan urutan:

```
PHASE 1: Setup (30 menit)
├── 1. 1 Verify system ✓
├── 1.2 Create project structure
└── 1. 3 Install dependencies

PHASE 2: Model (15 menit)
├── 2. 1 Download model
└── 2.2 Test base model

PHASE 3: Dataset (20 menit)
├── 3. 1 Setup dataset format
├── 3.2 Create sample dataset
└── 3.3 Validate dataset

PHASE 4: Training (2-4 jam)
├── 4.1 Configure training
├── 4.2 Run training
└── 4.3 Monitor progress

PHASE 5: Evaluation (30 menit)
├── 5. 1 Evaluate model
├── 5.2 Interactive testing
└── 5.3 Security test suite

PHASE 6: Deployment (30 menit)
├── 6. 1 Setup vLLM server
├── 6.2 Configure API
├── 6.3 Setup systemd service
└── 6.4 Test client

PHASE 7: Validation (15 menit)
├── 7.1 E2E testing
└── 7.2 Gate testing
```

---

## ⚠️ Important Notes

1. **Checkpoint frequently** - Training bisa interrupted
2. **Monitor VRAM** - Jangan sampai OOM
3. **Use tmux** - Supaya training tetap jalan walau SSH disconnect
4. **Test incrementally** - Jangan langsung full training
5. **Keep logs** - Untuk debugging kalau ada issue

---

## 🆘 Troubleshooting Guide

Tolong sertakan juga common issues dan solutions:

1.  CUDA out of memory
2. Training stuck/frozen
3. Loss not decreasing
4. Model not loading
5. API server errors
6. Slow inference

---

Mulai dari PHASE 1, Step 1. 1: Verify GPU & System. 
Buatkan script verification dan jalankan step by step. 
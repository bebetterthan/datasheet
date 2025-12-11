# 🚀 Quick Start: Testing LLM Provider

## Prerequisites

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## Testing Different Providers

### Option 1: API Provider (Recommended for Testing)

**Using Ollama (Local):**
```bash
# 1. Install Ollama: https://ollama.ai
# 2. Pull a model
ollama pull llama2

# 3. Test the provider
cd redteam_agent
python scripts/test_llm.py --provider api --api-url http://localhost:11434/v1 --model-name llama2
```

**Using vLLM Server:**
```bash
# 1. Start vLLM server (in another terminal)
vllm serve Qwen/Qwen2.5-Coder-7B-Instruct --port 8000

# 2. Test the provider
python scripts/test_llm.py --provider api --api-url http://localhost:8000/v1
```

**Using LM Studio:**
```bash
# 1. Start LM Studio and load a model
# 2. Enable API server (usually on port 1234)
# 3. Test the provider
python scripts/test_llm.py --provider api --api-url http://localhost:1234/v1
```

### Option 2: OpenAI Provider

```bash
# Set API key
export OPENAI_API_KEY="sk-..."

# Test with GPT-4
python scripts/test_llm.py --provider openai --model-name gpt-4

# Test with GPT-3.5 (cheaper)
python scripts/test_llm.py --provider openai --model-name gpt-3.5-turbo
```

### Option 3: Local Provider (Requires GPU)

```bash
# This loads the model directly on your machine
# Requires: 16GB+ GPU RAM for 7B model
python scripts/test_llm.py --provider local
```

## Expected Output

```
╭─────────────────────────────────────────────╮
│ 🤖 Red Team Agent - LLM Provider Test      │
╰─────────────────────────────────────────────╯

Creating api provider...
✅ Provider created: APILLMProvider

📋 Provider Information:
┌──────────────┬─────────────────────────────┐
│ Property     │ Value                       │
├──────────────┼─────────────────────────────┤
│ provider_type│ APILLMProvider              │
│ healthy      │ True                        │
│ api_url      │ http://localhost:8000/v1    │
└──────────────┴─────────────────────────────┘

🏥 Health Check:
✅ Provider is healthy

🧪 Testing Simple Generation:
⠹ Generating response...
╭─ Generation Test ────────────────────────────╮
│ Prompt:                                      │
│ What is a SQL injection vulnerability?      │
│                                              │
│ Response:                                    │
│ SQL injection is a security vulnerability... │
╰──────────────────────────────────────────────╯

...

📊 Test Summary:
┌──────────────────┬────────┐
│ Test             │ Result │
├──────────────────┼────────┤
│ Provider Info    │ ✅ PASS│
│ Health Check     │ ✅ PASS│
│ Simple Generation│ ✅ PASS│
│ Chat Generation  │ ✅ PASS│
│ Security Task    │ ✅ PASS│
└──────────────────┴────────┘

Results: 5/5 tests passed
🎉 All tests passed! Provider is ready to use.
```

## Configuration

Edit `configs/agent_config.yaml` to set default provider:

```yaml
llm:
  provider: "api"  # Change to: local, api, or openai
  api_url: "http://localhost:8000/v1"
  model_name: "your-model-name"
  max_tokens: 4096
  temperature: 0.7
```

## Troubleshooting

### "Could not connect to API"
- Check if the API server is running
- Verify the URL is correct
- Test with: `curl http://localhost:8000/v1/models`

### "API key is required"
- Set environment variable: `export OPENAI_API_KEY="sk-..."`
- Or add to config: `api_key: "your-key"`

### "torch is required"
- Install PyTorch: `pip install torch transformers peft`
- For local provider only

### "Model not found"
- Check model name matches what's available
- For Ollama: `ollama list`
- For vLLM: Check startup logs

## Next Steps

Once tests pass, you can:

1. **Test the full agent:**
   ```bash
   python scripts/run_agent.py run "Test query"
   ```

2. **Interactive mode:**
   ```bash
   python scripts/interactive.py
   ```

3. **API server:**
   ```bash
   python scripts/serve_api.py
   ```

## Provider Comparison

| Provider | Pros | Cons |
|----------|------|------|
| **API (Ollama)** | ✅ Easy setup<br>✅ Free<br>✅ No GPU needed | ⚠️ Slower inference<br>⚠️ Limited model quality |
| **API (vLLM)** | ✅ Fast inference<br>✅ Free | ⚠️ Requires GPU<br>⚠️ Setup complexity |
| **OpenAI** | ✅ Best quality<br>✅ No setup | ❌ Costs money<br>❌ Requires internet |
| **Local** | ✅ Private<br>✅ Fast (with GPU) | ❌ Requires 16GB+ GPU<br>❌ Complex setup |

**Recommended for Development:** Start with Ollama (easiest) or OpenAI (best quality)
**Recommended for Production:** vLLM server or Local (after fine-tuning)

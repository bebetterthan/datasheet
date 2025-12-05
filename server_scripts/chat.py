#!/usr/bin/env python3
"""
Interactive chat with the fine-tuned Red Team AI model
"""

import torch
from pathlib import Path
import sys

def main():
    print("=" * 60)
    print("  🔴 RED TEAM AI AGENT - CHAT")
    print("=" * 60)

    # Find latest model
    outputs_dir = Path("outputs")
    model_path = None
    
    if outputs_dir.exists():
        runs = sorted([d for d in outputs_dir.iterdir() if d.is_dir() and d.name.startswith("run_")])
        if runs:
            latest = runs[-1] / "final_model"
            if latest.exists():
                model_path = str(latest)
                print(f"\n📁 Found fine-tuned model: {runs[-1].name}")
    
    if not model_path:
        print("❌ No fine-tuned model found!")
        return

    print(f"\n🔄 Loading model from: {model_path}")
    print("   This may take a moment...")

    from unsloth import FastLanguageModel

    # Load the fine-tuned model
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_path,
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )

    # Enable fast inference mode
    FastLanguageModel.for_inference(model)

    print("✅ Model loaded successfully!")
    print(f"🎮 GPU Memory: {torch.cuda.memory_allocated() / 1024**3:.1f} GB")
    
    print("\n" + "=" * 60)
    print("  Type your security question (or 'quit' to exit)")
    print("  Examples:")
    print("  - What is SQL injection?")
    print("  - How to detect XSS vulnerabilities?")
    print("  - Explain buffer overflow attacks")
    print("=" * 60)

    # System prompt matching training format
    system_prompt = "You are a cybersecurity expert and red team specialist. Provide detailed, accurate, and educational responses about security topics."

    while True:
        try:
            user_input = input("\n🔴 You: ").strip()

            if user_input.lower() in ['quit', 'exit', 'q']:
                print("\n👋 Goodbye!")
                break

            if not user_input:
                continue

            # Format using Qwen chat template (same as training)
            prompt = f"""<|im_start|>system
{system_prompt}<|im_end|>
<|im_start|>user
{user_input}<|im_end|>
<|im_start|>assistant
"""

            # Tokenize
            inputs = tokenizer(prompt, return_tensors="pt").to("cuda")

            # Generate
            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=1024,
                    temperature=0.7,
                    top_p=0.9,
                    do_sample=True,
                    repetition_penalty=1.1,
                    pad_token_id=tokenizer.eos_token_id,
                )

            # Decode response
            full_response = tokenizer.decode(outputs[0], skip_special_tokens=False)
            
            # Extract assistant response
            if "<|im_start|>assistant" in full_response:
                response = full_response.split("<|im_start|>assistant")[-1]
                response = response.replace("<|im_end|>", "").strip()
            else:
                response = tokenizer.decode(outputs[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True)

            print(f"\n🤖 Agent: {response}")

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()


def test_single(question: str):
    """Test a single question without interactive mode"""
    print("=" * 60)
    print("  🔴 RED TEAM AI AGENT - SINGLE TEST")
    print("=" * 60)
    
    outputs_dir = Path("outputs")
    runs = sorted([d for d in outputs_dir.iterdir() if d.is_dir() and d.name.startswith("run_")])
    model_path = str(runs[-1] / "final_model")
    
    print(f"\n🔄 Loading: {model_path}")
    
    from unsloth import FastLanguageModel
    
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_path,
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )
    FastLanguageModel.for_inference(model)
    
    print("✅ Model loaded!")
    print(f"\n❓ Question: {question}\n")
    
    system_prompt = "You are a cybersecurity expert and red team specialist. Provide detailed, accurate, and educational responses about security topics."
    
    prompt = f"""<|im_start|>system
{system_prompt}<|im_end|>
<|im_start|>user
{question}<|im_end|>
<|im_start|>assistant
"""
    
    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=1024,
            temperature=0.7,
            top_p=0.9,
            do_sample=True,
            repetition_penalty=1.1,
            pad_token_id=tokenizer.eos_token_id,
        )
    
    full_response = tokenizer.decode(outputs[0], skip_special_tokens=False)
    
    if "<|im_start|>assistant" in full_response:
        response = full_response.split("<|im_start|>assistant")[-1]
        response = response.replace("<|im_end|>", "").strip()
    else:
        response = tokenizer.decode(outputs[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True)
    
    print(f"🤖 Response:\n{response}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Single question mode
        question = " ".join(sys.argv[1:])
        test_single(question)
    else:
        # Interactive mode
        main()

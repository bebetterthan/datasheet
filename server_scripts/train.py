#!/usr/bin/env python3
"""
Train Red Team AI Agent using LoRA fine-tuning
"""

import os
import sys
import json
import yaml
import torch
from datetime import datetime
from pathlib import Path

def main():
    print("=" * 50)
    print("  RED TEAM AI AGENT - TRAINING")
    print("=" * 50)
    
    # Check GPU
    if not torch.cuda.is_available():
        print("❌ CUDA not available!")
        sys.exit(1)
    
    print(f"\n✅ GPU: {torch.cuda.get_device_name(0)}")
    print(f"✅ VRAM: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
    
    # Load config
    config_path = Path("configs/training_config.yaml")
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        print(f"✅ Config loaded from {config_path}")
    else:
        print("⚠️ Using default config")
        config = {
            "model": {"name": "Qwen/Qwen2.5-Coder-7B-Instruct", "max_seq_length": 2048},
            "lora": {"r": 16, "lora_alpha": 32},
            "training": {"num_epochs": 3, "per_device_train_batch_size": 2}
        }
    
    # Import ML libraries
    print("\n📦 Loading libraries...")
    from unsloth import FastLanguageModel
    from datasets import load_dataset, Dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from peft import LoraConfig
    
    # Load model
    model_name = config["model"]["name"]
    max_seq_length = config["model"].get("max_seq_length", 2048)
    
    print(f"\n🔄 Loading model: {model_name}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_name,
        max_seq_length=max_seq_length,
        dtype=None,  # Auto detect
        load_in_4bit=config["model"].get("load_in_4bit", True),
    )
    
    # Apply LoRA
    print("\n⚡ Applying LoRA adapters...")
    lora_config = config.get("lora", {})
    model = FastLanguageModel.get_peft_model(
        model,
        r=lora_config.get("r", 16),
        lora_alpha=lora_config.get("lora_alpha", 32),
        lora_dropout=lora_config.get("lora_dropout", 0.05),
        target_modules=lora_config.get("target_modules", [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj"
        ]),
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )
    
    # Load dataset
    data_path = Path("data/final/train.json")
    print(f"\n📊 Loading dataset from {data_path}")
    
    with open(data_path) as f:
        data = json.load(f)
    
    print(f"   Total samples: {len(data)}")
    
    # Format dataset
    def format_prompt(sample):
        """Format to Alpaca style prompt"""
        instruction = sample.get("instruction", "")
        input_text = sample.get("input", "")
        output = sample.get("output", "")
        
        if input_text:
            text = f"""### Instruction:
{instruction}

### Input:
{input_text}

### Response:
{output}"""
        else:
            text = f"""### Instruction:
{instruction}

### Response:
{output}"""
        return {"text": text}
    
    dataset = Dataset.from_list(data)
    dataset = dataset.map(format_prompt)
    
    print(f"   Formatted samples: {len(dataset)}")
    
    # Training arguments
    train_config = config.get("training", {})
    save_config = config.get("saving", {})
    
    output_dir = save_config.get("output_dir", "./outputs")
    run_name = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_path = f"{output_dir}/{run_name}"
    
    training_args = TrainingArguments(
        output_dir=output_path,
        num_train_epochs=train_config.get("num_epochs", 3),
        per_device_train_batch_size=train_config.get("per_device_train_batch_size", 2),
        gradient_accumulation_steps=train_config.get("gradient_accumulation_steps", 8),
        learning_rate=train_config.get("learning_rate", 2e-4),
        lr_scheduler_type=train_config.get("lr_scheduler_type", "cosine"),
        warmup_ratio=train_config.get("warmup_ratio", 0.05),
        weight_decay=train_config.get("weight_decay", 0.01),
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=save_config.get("logging_steps", 10),
        save_steps=save_config.get("save_steps", 100),
        save_total_limit=save_config.get("save_total_limit", 3),
        optim="adamw_8bit",
        seed=42,
        report_to="none",
    )
    
    # Create trainer
    print("\n🏋️ Setting up trainer...")
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=max_seq_length,
        args=training_args,
    )
    
    # Print training info
    total_steps = len(dataset) // (train_config.get("per_device_train_batch_size", 2) * train_config.get("gradient_accumulation_steps", 8)) * train_config.get("num_epochs", 3)
    print(f"\n📈 Training Info:")
    print(f"   Epochs: {train_config.get('num_epochs', 3)}")
    print(f"   Batch size: {train_config.get('per_device_train_batch_size', 2)}")
    print(f"   Gradient accumulation: {train_config.get('gradient_accumulation_steps', 8)}")
    print(f"   Effective batch size: {train_config.get('per_device_train_batch_size', 2) * train_config.get('gradient_accumulation_steps', 8)}")
    print(f"   Total steps: ~{total_steps}")
    print(f"   Output: {output_path}")
    
    # Start training
    print("\n" + "=" * 50)
    print("  STARTING TRAINING...")
    print("=" * 50 + "\n")
    
    trainer_stats = trainer.train()
    
    # Save model
    print("\n💾 Saving model...")
    final_path = f"{output_path}/final_model"
    model.save_pretrained(final_path)
    tokenizer.save_pretrained(final_path)
    
    # Training summary
    print("\n" + "=" * 50)
    print("  TRAINING COMPLETE!")
    print("=" * 50)
    print(f"\n📊 Training Summary:")
    print(f"   Total time: {trainer_stats.metrics['train_runtime']:.1f}s")
    print(f"   Final loss: {trainer_stats.metrics['train_loss']:.4f}")
    print(f"   Model saved to: {final_path}")
    
    # Show GPU memory usage
    print(f"\n🎮 GPU Memory:")
    print(f"   Used: {torch.cuda.max_memory_allocated() / 1024**3:.1f} GB")
    print(f"   Reserved: {torch.cuda.max_memory_reserved() / 1024**3:.1f} GB")

if __name__ == "__main__":
    main()

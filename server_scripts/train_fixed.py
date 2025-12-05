#!/usr/bin/env python3
"""
Red Team AI Agent - Fixed Training Script with Real-time Progress
Fine-tune Qwen 2.5 Coder 7B on security dataset
"""

import os
import sys
import json
import yaml
import torch
import gc
from datetime import datetime
from pathlib import Path

# Disable tokenizer parallelism warning
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["WANDB_DISABLED"] = "true"

def print_banner():
    print("=" * 60)
    print("  RED TEAM AI AGENT - TRAINING (Fixed Version)")
    print("=" * 60)

def check_gpu():
    """Check GPU availability and memory"""
    if not torch.cuda.is_available():
        print("❌ No GPU detected!")
        sys.exit(1)
    
    gpu_name = torch.cuda.get_device_name(0)
    total_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
    print(f"\n✅ GPU: {gpu_name}")
    print(f"✅ VRAM: {total_memory:.1f} GB")
    
    # Clear GPU memory
    torch.cuda.empty_cache()
    gc.collect()
    
    return gpu_name

def load_config(config_path: str = "configs/training_config.yaml"):
    """Load training configuration"""
    if Path(config_path).exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        print(f"✅ Config loaded from {config_path}")
        return config
    else:
        print(f"⚠️ Config not found, using defaults")
        return {}

def main():
    print_banner()
    check_gpu()
    
    # Load config
    config = load_config()
    model_config = config.get("model", {})
    train_config = config.get("training", {})
    lora_config_dict = config.get("lora", {})
    
    # Training parameters - optimized for L4 24GB
    model_name = model_config.get("name", "Qwen/Qwen2.5-Coder-7B-Instruct")
    max_seq_length = model_config.get("max_seq_length", 2048)
    
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"./outputs/run_{timestamp}"
    os.makedirs(output_path, exist_ok=True)
    os.makedirs("./logs", exist_ok=True)
    
    # Progress file for monitoring
    progress_file = f"./logs/training_progress.json"
    
    def save_progress(step, total, loss, epoch, status="training"):
        """Save progress to file for monitoring"""
        progress = {
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "current_step": step,
            "total_steps": total,
            "progress_percent": round((step / total) * 100, 2) if total > 0 else 0,
            "current_loss": loss,
            "epoch": epoch,
            "output_path": output_path,
            "model": model_name,
            "gpu_memory_used_gb": round(torch.cuda.memory_allocated() / 1024**3, 2),
            "gpu_memory_reserved_gb": round(torch.cuda.memory_reserved() / 1024**3, 2),
        }
        with open(progress_file, 'w') as f:
            json.dump(progress, f, indent=2)
    
    # Initial progress
    save_progress(0, 0, 0, 0, "loading_libraries")
    
    print("\n📦 Loading libraries...")
    from unsloth import FastLanguageModel
    from unsloth import is_bfloat16_supported
    from trl import SFTTrainer
    from transformers import TrainingArguments, TrainerCallback
    from datasets import Dataset
    
    # Custom callback for real-time progress
    class ProgressCallback(TrainerCallback):
        def __init__(self, total_steps, progress_file):
            self.total_steps = total_steps
            self.progress_file = progress_file
            self.current_loss = 0
            self.loss_history = []
            
        def on_log(self, args, state, control, logs=None, **kwargs):
            if logs and "loss" in logs:
                self.current_loss = logs["loss"]
                self.loss_history.append(self.current_loss)
                # Print setiap kali ada loss baru (setiap logging_steps)
                epoch = state.epoch if state.epoch else 0
                pct = (state.global_step / self.total_steps) * 100 if self.total_steps > 0 else 0
                mem = torch.cuda.memory_allocated() / 1024**3
                print(f"📊 Step {state.global_step:4d}/{self.total_steps} | {pct:5.1f}% | Loss: {self.current_loss:.4f} | Epoch: {epoch:.2f} | GPU: {mem:.1f}GB", flush=True)
                
        def on_step_end(self, args, state, control, **kwargs):
            epoch = state.epoch if state.epoch else 0
            save_progress(
                state.global_step, 
                self.total_steps, 
                self.current_loss,
                round(epoch, 2),
                "training"
            )
            # Print progress every 10 steps
            if state.global_step % 10 == 0:
                pct = (state.global_step / self.total_steps) * 100
                mem = torch.cuda.memory_allocated() / 1024**3
                print(f"Step {state.global_step}/{self.total_steps} ({pct:.1f}%) | Loss: {self.current_loss:.4f} | GPU: {mem:.1f}GB")
    
    save_progress(0, 0, 0, 0, "loading_model")
    print(f"\n🔄 Loading model: {model_name}")
    
    # Load model with 4-bit quantization - FIXED VERSION
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_name,
        max_seq_length=max_seq_length,
        dtype=None,  # Auto-detect
        load_in_4bit=model_config.get("load_in_4bit", True),
        trust_remote_code=True,
    )
    
    print("\n⚡ Applying LoRA adapters...")
    
    # Apply LoRA - with dropout=0 for better compatibility
    model = FastLanguageModel.get_peft_model(
        model,
        r=lora_config_dict.get("r", 16),
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                       "gate_proj", "up_proj", "down_proj"],
        lora_alpha=lora_config_dict.get("alpha", 32),
        lora_dropout=0,  # FIXED: Set to 0 for Unsloth compatibility
        bias="none",
        use_gradient_checkpointing="unsloth",  # Use Unsloth's optimized checkpointing
        random_state=42,
    )
    
    # Load dataset
    save_progress(0, 0, 0, 0, "loading_dataset")
    print(f"\n📊 Loading dataset from data/final/train.json")
    
    with open("data/final/train.json", "r") as f:
        data = json.load(f)
    print(f"   Total samples: {len(data)}")
    
    # Format for Qwen chat template
    def format_sample(sample):
        instruction = sample.get("instruction", "")
        input_text = sample.get("input", "")
        output = sample.get("output", "")
        
        if input_text:
            user_content = f"{instruction}\n\n{input_text}"
        else:
            user_content = instruction
            
        # Use Qwen chat format
        text = f"""<|im_start|>system
You are a cybersecurity expert and red team specialist. Provide detailed, accurate, and educational responses about security topics.<|im_end|>
<|im_start|>user
{user_content}<|im_end|>
<|im_start|>assistant
{output}<|im_end|>"""
        return {"text": text}
    
    dataset = Dataset.from_list(data)
    dataset = dataset.map(format_sample, remove_columns=dataset.column_names)
    print(f"   Formatted samples: {len(dataset)}")
    
    # Calculate total steps
    batch_size = train_config.get("per_device_train_batch_size", 2)
    grad_accum = train_config.get("gradient_accumulation_steps", 8)
    num_epochs = train_config.get("num_epochs", 3)
    total_steps = (len(dataset) // (batch_size * grad_accum)) * num_epochs
    
    # Training arguments - optimized for stability
    print("\n🏋️ Setting up trainer...")
    training_args = TrainingArguments(
        output_dir=output_path,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        learning_rate=float(train_config.get("learning_rate", 2e-4)),
        weight_decay=train_config.get("weight_decay", 0.01),
        warmup_ratio=train_config.get("warmup_ratio", 0.03),
        lr_scheduler_type=train_config.get("lr_scheduler_type", "cosine"),
        logging_steps=5,
        save_steps=100,
        save_total_limit=3,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        optim="adamw_8bit",
        seed=42,
        report_to="none",
        # Memory optimization
        gradient_checkpointing=True,
        max_grad_norm=0.3,
    )
    
    # Create trainer with progress callback
    progress_callback = ProgressCallback(total_steps, progress_file)
    
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=max_seq_length,
        args=training_args,
        callbacks=[progress_callback],
    )
    
    # Print training info
    print(f"\n📈 Training Info:")
    print(f"   Epochs: {num_epochs}")
    print(f"   Batch size: {batch_size}")
    print(f"   Gradient accumulation: {grad_accum}")
    print(f"   Effective batch size: {batch_size * grad_accum}")
    print(f"   Total steps: ~{total_steps}")
    print(f"   Learning rate: {train_config.get('learning_rate', 2e-4)}")
    print(f"   Output: {output_path}")
    print(f"   Progress file: {progress_file}")
    
    # Start training
    print("\n" + "=" * 60)
    print("  STARTING TRAINING...")
    print("=" * 60 + "\n")
    
    save_progress(0, total_steps, 0, 0, "training")
    
    try:
        trainer_stats = trainer.train()
        
        # Save model
        save_progress(total_steps, total_steps, 0, num_epochs, "saving_model")
        print("\n💾 Saving model...")
        final_path = f"{output_path}/final_model"
        model.save_pretrained(final_path)
        tokenizer.save_pretrained(final_path)
        
        # Also save as LoRA adapter
        lora_path = f"{output_path}/lora_adapter"
        model.save_pretrained(lora_path)
        
        # Training summary
        train_time = trainer_stats.metrics['train_runtime']
        final_loss = trainer_stats.metrics['train_loss']
        
        print("\n" + "=" * 60)
        print("  TRAINING COMPLETE! 🎉")
        print("=" * 60)
        print(f"\n📊 Training Summary:")
        print(f"   Total time: {train_time:.1f}s ({train_time/60:.1f} minutes)")
        print(f"   Final loss: {final_loss:.4f}")
        print(f"   Model saved to: {final_path}")
        print(f"   LoRA adapter: {lora_path}")
        
        # GPU stats
        print(f"\n🎮 GPU Memory (Peak):")
        print(f"   Used: {torch.cuda.max_memory_allocated() / 1024**3:.1f} GB")
        print(f"   Reserved: {torch.cuda.max_memory_reserved() / 1024**3:.1f} GB")
        
        # Save final progress
        save_progress(total_steps, total_steps, final_loss, num_epochs, "completed")
        
        # Save training stats
        stats_file = f"{output_path}/training_stats.json"
        with open(stats_file, 'w') as f:
            json.dump({
                "model": model_name,
                "dataset_size": len(dataset),
                "total_steps": total_steps,
                "train_runtime_seconds": train_time,
                "final_loss": final_loss,
                "gpu_memory_peak_gb": torch.cuda.max_memory_allocated() / 1024**3,
                "config": config
            }, f, indent=2)
        
    except Exception as e:
        save_progress(0, total_steps, 0, 0, f"error: {str(e)}")
        print(f"\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()

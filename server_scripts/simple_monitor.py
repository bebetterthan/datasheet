#!/usr/bin/env python3
"""
Simple Training Monitor - works over SSH without TTY
"""
import json
import time
import sys
import subprocess
from datetime import datetime
from pathlib import Path

def get_gpu_stats():
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu', 
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split(',')
            return {
                'util': int(parts[0].strip()),
                'mem_used': int(parts[1].strip()),
                'mem_total': int(parts[2].strip()),
                'temp': int(parts[3].strip())
            }
    except:
        pass
    return None

def format_time(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

def create_bar(pct, width=30):
    filled = int(width * pct / 100)
    return '[' + '#' * filled + '-' * (width - filled) + ']'

def monitor(progress_file="logs/training_progress.json", interval=5, iterations=None):
    print("=" * 60)
    print("  RED TEAM AI AGENT - TRAINING MONITOR")
    print("=" * 60)
    
    start_time = time.time()
    count = 0
    
    while iterations is None or count < iterations:
        print(f"\n--- Update {datetime.now().strftime('%H:%M:%S')} ---")
        
        # GPU stats
        gpu = get_gpu_stats()
        if gpu:
            mem_pct = (gpu['mem_used'] / gpu['mem_total']) * 100
            print(f"GPU: {gpu['util']}% util | {gpu['mem_used']}/{gpu['mem_total']}MB ({mem_pct:.0f}%) | {gpu['temp']}C")
        
        # Training progress
        progress_path = Path(progress_file)
        if progress_path.exists():
            try:
                with open(progress_path) as f:
                    p = json.load(f)
                
                status = p.get('status', 'unknown')
                step = p.get('current_step', 0)
                total = p.get('total_steps', 1)
                pct = p.get('progress_percent', 0)
                loss = p.get('current_loss', 0)
                epoch = p.get('epoch', 0)
                
                print(f"Status: {status.upper()}")
                print(f"Progress: {create_bar(pct)} {pct:.1f}%")
                print(f"Step: {step}/{total} | Epoch: {epoch:.2f}")
                print(f"Loss: {loss:.4f}")
                print(f"Model Memory: {p.get('gpu_memory_used_gb', 0):.1f}GB")
                
                # ETA
                if step > 0:
                    elapsed = time.time() - start_time
                    rate = step / max(elapsed, 1)
                    remaining = (total - step) / max(rate, 0.001)
                    print(f"ETA: {format_time(remaining)} | Speed: {rate:.2f} steps/s")
                
                if status == 'completed':
                    print("\n🎉 TRAINING COMPLETE!")
                    break
                elif 'error' in status:
                    print(f"\n❌ ERROR: {status}")
                    break
                    
            except Exception as e:
                print(f"Error reading progress: {e}")
        else:
            print("Waiting for training to start...")
        
        count += 1
        if iterations is None or count < iterations:
            time.sleep(interval)
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interval", type=int, default=5, help="Update interval")
    parser.add_argument("-n", "--iterations", type=int, default=None, help="Number of updates (default: infinite)")
    parser.add_argument("-f", "--file", default="logs/training_progress.json")
    args = parser.parse_args()
    
    try:
        monitor(args.file, args.interval, args.iterations)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")

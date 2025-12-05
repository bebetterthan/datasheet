#!/usr/bin/env python3
"""
Real-time Training Monitor for Red Team AI Agent
Shows live progress, GPU stats, and training metrics
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

# ANSI colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

def get_gpu_stats():
    """Get GPU stats using nvidia-smi"""
    try:
        import subprocess
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw', 
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split(',')
            return {
                'name': parts[0].strip(),
                'temp': int(parts[1].strip()),
                'util': int(parts[2].strip()),
                'mem_used': int(parts[3].strip()),
                'mem_total': int(parts[4].strip()),
                'power': float(parts[5].strip()) if parts[5].strip() != '[N/A]' else 0
            }
    except Exception as e:
        pass
    return None

def format_time(seconds):
    """Format seconds to human readable"""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

def create_progress_bar(percent, width=40):
    """Create ASCII progress bar"""
    filled = int(width * percent / 100)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{bar}] {percent:.1f}%"

def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗
║        🔴 RED TEAM AI AGENT - TRAINING MONITOR 🔴              ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
""")

def monitor_training(progress_file="logs/training_progress.json", refresh_rate=2):
    """Monitor training progress in real-time"""
    
    print(f"{Colors.GREEN}Starting training monitor...{Colors.END}")
    print(f"Watching: {progress_file}")
    print(f"Refresh rate: {refresh_rate}s")
    print(f"\nPress Ctrl+C to stop monitoring\n")
    
    start_time = time.time()
    loss_history = []
    
    while True:
        try:
            clear_screen()
            print_banner()
            
            # Read progress file
            progress = None
            if Path(progress_file).exists():
                try:
                    with open(progress_file, 'r') as f:
                        progress = json.load(f)
                except json.JSONDecodeError:
                    pass
            
            # Get GPU stats
            gpu = get_gpu_stats()
            
            # Display GPU info
            print(f"{Colors.YELLOW}═══ GPU STATUS ═══{Colors.END}")
            if gpu:
                gpu_bar = create_progress_bar(gpu['util'], 30)
                mem_pct = (gpu['mem_used'] / gpu['mem_total']) * 100
                mem_bar = create_progress_bar(mem_pct, 30)
                
                print(f"  GPU: {Colors.CYAN}{gpu['name']}{Colors.END}")
                print(f"  Utilization: {gpu_bar}")
                print(f"  Memory: {mem_bar} ({gpu['mem_used']}MB / {gpu['mem_total']}MB)")
                print(f"  Temperature: {Colors.GREEN if gpu['temp'] < 70 else Colors.YELLOW if gpu['temp'] < 85 else Colors.RED}{gpu['temp']}°C{Colors.END}")
                if gpu['power'] > 0:
                    print(f"  Power: {gpu['power']:.1f}W")
            else:
                print(f"  {Colors.RED}Unable to get GPU stats{Colors.END}")
            
            print()
            
            # Display training progress
            print(f"{Colors.YELLOW}═══ TRAINING PROGRESS ═══{Colors.END}")
            
            if progress:
                status = progress.get('status', 'unknown')
                step = progress.get('current_step', 0)
                total = progress.get('total_steps', 0)
                pct = progress.get('progress_percent', 0)
                loss = progress.get('current_loss', 0)
                epoch = progress.get('epoch', 0)
                model = progress.get('model', 'N/A')
                output_path = progress.get('output_path', 'N/A')
                
                # Track loss history
                if loss > 0 and (not loss_history or loss != loss_history[-1]):
                    loss_history.append(loss)
                    if len(loss_history) > 50:
                        loss_history = loss_history[-50:]
                
                # Status indicator
                status_color = {
                    'training': Colors.GREEN,
                    'loading_model': Colors.BLUE,
                    'loading_dataset': Colors.BLUE,
                    'loading_libraries': Colors.BLUE,
                    'saving_model': Colors.CYAN,
                    'completed': Colors.GREEN,
                }.get(status, Colors.YELLOW)
                
                status_icon = {
                    'training': '🏃',
                    'loading_model': '📥',
                    'loading_dataset': '📊',
                    'loading_libraries': '📦',
                    'saving_model': '💾',
                    'completed': '✅',
                }.get(status, '⏳')
                
                print(f"  Status: {status_icon} {status_color}{status.upper()}{Colors.END}")
                print(f"  Model: {Colors.CYAN}{model}{Colors.END}")
                
                if status == 'training' or status == 'completed':
                    # Progress bar
                    prog_bar = create_progress_bar(pct, 40)
                    print(f"\n  {Colors.BOLD}Progress:{Colors.END}")
                    print(f"  {prog_bar}")
                    print(f"  Step: {step}/{total}")
                    print(f"  Epoch: {epoch:.2f}")
                    
                    # Loss
                    print(f"\n  {Colors.BOLD}Training Metrics:{Colors.END}")
                    print(f"  Current Loss: {Colors.CYAN}{loss:.4f}{Colors.END}")
                    
                    # Loss trend
                    if len(loss_history) >= 2:
                        trend = loss_history[-1] - loss_history[0]
                        trend_icon = "📉" if trend < 0 else "📈"
                        trend_color = Colors.GREEN if trend < 0 else Colors.RED
                        print(f"  Loss Trend: {trend_icon} {trend_color}{trend:+.4f}{Colors.END}")
                    
                    # Simple loss graph (ASCII sparkline)
                    if len(loss_history) > 5:
                        min_loss = min(loss_history)
                        max_loss = max(loss_history)
                        range_loss = max_loss - min_loss if max_loss > min_loss else 1
                        
                        sparkline = ""
                        chars = "▁▂▃▄▅▆▇█"
                        for l in loss_history[-30:]:
                            idx = min(7, int((l - min_loss) / range_loss * 7))
                            sparkline += chars[idx]
                        print(f"  Loss History: {Colors.CYAN}{sparkline}{Colors.END}")
                    
                    # ETA calculation
                    if step > 0 and total > 0:
                        elapsed = time.time() - start_time
                        steps_per_sec = step / max(elapsed, 1)
                        remaining_steps = total - step
                        eta_seconds = remaining_steps / max(steps_per_sec, 0.001)
                        
                        print(f"\n  {Colors.BOLD}Time:{Colors.END}")
                        print(f"  Elapsed: {format_time(elapsed)}")
                        print(f"  ETA: {format_time(eta_seconds)}")
                        print(f"  Speed: {steps_per_sec:.2f} steps/sec")
                
                elif 'error' in status:
                    print(f"\n  {Colors.RED}❌ ERROR: {status}{Colors.END}")
                
                elif status == 'completed':
                    print(f"\n  {Colors.GREEN}🎉 Training completed successfully!{Colors.END}")
                    print(f"  Model saved to: {output_path}")
                
                print(f"\n  Output: {output_path}")
                
            else:
                print(f"  {Colors.YELLOW}⏳ Waiting for training to start...{Colors.END}")
                print(f"  Progress file not found yet.")
            
            # Footer
            print(f"\n{Colors.CYAN}{'─' * 60}{Colors.END}")
            print(f"Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Refresh in {refresh_rate}s... (Ctrl+C to exit)")
            
            # Check if training is complete
            if progress and progress.get('status') == 'completed':
                print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 TRAINING COMPLETE! 🎉{Colors.END}")
                break
            
            time.sleep(refresh_rate)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Monitor stopped by user{Colors.END}")
            break
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")
            time.sleep(refresh_rate)

def show_summary():
    """Show training summary from the most recent run"""
    outputs_dir = Path("outputs")
    if not outputs_dir.exists():
        print("No training outputs found.")
        return
    
    # Find most recent run
    runs = sorted(outputs_dir.glob("run_*"), reverse=True)
    if not runs:
        print("No training runs found.")
        return
    
    latest_run = runs[0]
    stats_file = latest_run / "training_stats.json"
    
    if stats_file.exists():
        with open(stats_file) as f:
            stats = json.load(f)
        
        print(f"\n{Colors.CYAN}═══ LATEST TRAINING SUMMARY ═══{Colors.END}")
        print(f"Run: {latest_run.name}")
        print(f"Model: {stats.get('model', 'N/A')}")
        print(f"Dataset size: {stats.get('dataset_size', 'N/A')}")
        print(f"Total steps: {stats.get('total_steps', 'N/A')}")
        print(f"Training time: {format_time(stats.get('train_runtime_seconds', 0))}")
        print(f"Final loss: {stats.get('final_loss', 'N/A'):.4f}")
        print(f"Peak GPU memory: {stats.get('gpu_memory_peak_gb', 0):.1f} GB")
    else:
        print(f"No stats file found for {latest_run.name}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Monitor Red Team AI Training")
    parser.add_argument("-r", "--refresh", type=int, default=2, help="Refresh rate in seconds")
    parser.add_argument("-s", "--summary", action="store_true", help="Show summary of latest run")
    parser.add_argument("-f", "--file", default="logs/training_progress.json", help="Progress file path")
    
    args = parser.parse_args()
    
    if args.summary:
        show_summary()
    else:
        monitor_training(args.file, args.refresh)

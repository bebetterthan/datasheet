#!/usr/bin/env python3
"""Simple script to view scraped data and training summary."""

import json
from pathlib import Path

def main():
    print('=' * 60)
    print('SECURITY DATASET SCRAPER - TEST SUMMARY')
    print('=' * 60)
    
    # Raw data
    raw = Path("data/raw/all_scraped.json")
    if raw.exists():
        with open(raw, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
        print(f'\n1. RAW DATA: {len(raw_data)} items scraped')
        sources = {}
        for item in raw_data:
            url = item.get('url', '')
            if 'payloads' in url.lower():
                src = 'PayloadsAllTheThings'
            elif 'hacktricks' in url.lower():
                src = 'HackTricks'
            elif 'owasp' in url.lower() or 'cheatsheetseries' in url.lower():
                src = 'OWASP'
            elif 'exploit-db' in url.lower():
                src = 'Exploit-DB'
            elif 'gitlab.com/exploit' in url.lower():
                src = 'Exploit-DB'
            else:
                src = 'Other'
            sources[src] = sources.get(src, 0) + 1
        for src, count in sources.items():
            print(f'   - {src}: {count} items')
    
    # Final data
    final_dir = Path('data/final')
    if final_dir.exists():
        print(f'\n2. TRAINING DATA:')
        total = 0
        for f in ['train.json', 'val.json', 'test.json']:
            fp = final_dir / f
            if fp.exists():
                with open(fp, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                print(f'   - {f}: {len(data)} samples')
                total += len(data)
        print(f'   TOTAL: {total} Q&A pairs')
    
    # Sample Q&A
    print('\n3. SAMPLE Q&A PAIRS:')
    train_file = final_dir / 'train.json'
    if train_file.exists():
        with open(train_file, 'r', encoding='utf-8') as f:
            train_data = json.load(f)
        for i, item in enumerate(train_data[:3], 1):
            q = item['instruction'][:70].replace('\n', ' ').replace('\r', ' ')
            a = item['output'][:100].replace('\n', ' ').replace('\r', ' ')
            print(f'\n   Sample {i}:')
            print(f'   Q: {q}...')
            print(f'   A: {a}...')
    
    print('\n' + '=' * 60)
    print('Dataset ready for LLM fine-tuning!')
    print('Files: data/final/train.json, val.json, test.json')
    print('=' * 60)

if __name__ == "__main__":
    main()

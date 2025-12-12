\"\"\"Attack simulator for testing the AI threat detection system.\"\"\"

import requests
import time
import random
import string
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from pathlib import Path
import threading

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, str(Path(__file__).parent))
from generate_jwt import generate_token

PROXY_URL = "https://localhost:8443"
CERT = ("../certs/client.crt", "../certs/client.key")

# Thread-safe counters
lock = threading.Lock()


def get_headers():
    token = generate_token(private_key_path="../certs/jwt_private.pem", subject="attacker")
    return {"Authorization": f"Bearer {token}"}


def clear_blocklist():
    """Clear any existing blocks to start fresh."""
    import subprocess
    subprocess.run(["docker", "exec", "aegis-redis", "redis-cli", "del", "blocklist:ip:192.168.65.1"], 
                   capture_output=True)
    print("  🗑️  Cleared existing blocks\n")


def ddos_attack(duration=30, workers=200):
    """
    Real-world DDoS attack simulation.
    Target: 100+ requests/second, overwhelming the server.
    """
    print("\n" + "🔴"*30)
    print("  💥 DDoS ATTACK - REAL WORLD SCALE 💥")
    print("🔴"*30)
    print(f"  Duration: {duration}s | Workers: {workers}")
    print(f"  Target: 100+ req/s flood")
    print("="*60 + "\n")
    
    stats = {"total": 0, "blocked": 0, "success": 0, "errors": 0}
    start = time.time()
    running = True
    
    def attack():
        nonlocal running
        while running:
            try:
                r = requests.get(f"{PROXY_URL}/api/v1/data", cert=CERT, verify=False, 
                               headers=get_headers(), timeout=0.5)
                with lock:
                    stats["total"] += 1
                    if r.status_code == 403:
                        stats["blocked"] += 1
                    else:
                        stats["success"] += 1
            except:
                with lock:
                    stats["errors"] += 1
                    stats["total"] += 1
    
    # Launch all workers
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(attack) for _ in range(workers)]
        
        # Progress updates
        while time.time() - start < duration:
            time.sleep(1)
            elapsed = time.time() - start
            rate = stats["total"] / elapsed if elapsed > 0 else 0
            block_pct = stats["blocked"] / max(stats["total"], 1) * 100
            print(f"  ⚡ {stats['total']:,} req | ✅ {stats['success']:,} | 🛡️ {stats['blocked']:,} ({block_pct:.0f}%) | ⚡ {rate:.0f}/s")
        
        running = False
    
    elapsed = time.time() - start
    print("\n" + "="*60)
    print(f"  ✅ DDoS COMPLETE")
    print(f"  📊 Total: {stats['total']:,} @ {stats['total']/elapsed:.0f} req/s")
    print(f"  🛡️  Blocked: {stats['blocked']:,} ({stats['blocked']/max(stats['total'],1)*100:.1f}%)")
    print("="*60 + "\n")
    return stats


def scraping_attack(duration=30, workers=100):
    """
    Web scraping attack - hitting many unique paths rapidly.
    Simulates automated crawlers/scrapers.
    """
    print("\n" + "🟡"*30)
    print("  🕷️ SCRAPING ATTACK - REAL WORLD SCALE 🕷️")
    print("🟡"*30)
    print(f"  Duration: {duration}s | Workers: {workers}")
    print(f"  Pattern: Many unique paths, rapid requests")
    print("="*60 + "\n")
    
    stats = {"total": 0, "blocked": 0, "success": 0}
    start = time.time()
    running = True
    
    # Simulated scraped paths
    paths = [f"/product/{i}" for i in range(10000)]
    paths += [f"/category/{c}" for c in ["electronics", "clothing", "books", "toys"]]
    paths += [f"/user/{i}/profile" for i in range(1000)]
    
    def scrape():
        nonlocal running
        while running:
            path = random.choice(paths)
            try:
                r = requests.get(f"{PROXY_URL}{path}", cert=CERT, verify=False,
                               headers=get_headers(), timeout=0.5)
                with lock:
                    stats["total"] += 1
                    if r.status_code == 403:
                        stats["blocked"] += 1
                    else:
                        stats["success"] += 1
            except:
                with lock:
                    stats["total"] += 1
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scrape) for _ in range(workers)]
        
        while time.time() - start < duration:
            time.sleep(1)
            elapsed = time.time() - start
            rate = stats["total"] / elapsed if elapsed > 0 else 0
            print(f"  🕷️ {stats['total']:,} pages | 🛡️ {stats['blocked']:,} blocked | ⚡ {rate:.0f}/s")
        
        running = False
    
    elapsed = time.time() - start
    print("\n" + "="*60)
    print(f"  ✅ SCRAPING COMPLETE")
    print(f"  📊 Total: {stats['total']:,} @ {stats['total']/elapsed:.0f} req/s")
    print(f"  🛡️  Blocked: {stats['blocked']:,} ({stats['blocked']/max(stats['total'],1)*100:.1f}%)")
    print("="*60 + "\n")
    return stats


def exfiltration_attack(duration=30, workers=50):
    """
    Data exfiltration attack - large POST payloads.
    Simulates stealing data via large uploads.
    """
    print("\n" + "🟣"*30)
    print("  📤 DATA EXFILTRATION - REAL WORLD SCALE 📤")
    print("🟣"*30)
    print(f"  Duration: {duration}s | Workers: {workers}")
    print(f"  Pattern: Large POST payloads (100KB each)")
    print("="*60 + "\n")
    
    stats = {"total": 0, "blocked": 0, "bytes_sent": 0}
    start = time.time()
    running = True
    
    # Large payload simulating stolen data
    stolen_data = "X" * 100000  # 100KB
    
    def exfiltrate():
        nonlocal running
        while running:
            try:
                data = {"data": stolen_data, "timestamp": time.time()}
                r = requests.post(f"{PROXY_URL}/api/upload", cert=CERT, verify=False,
                                headers=get_headers(), json=data, timeout=2)
                with lock:
                    stats["total"] += 1
                    stats["bytes_sent"] += len(stolen_data)
                    if r.status_code == 403:
                        stats["blocked"] += 1
            except:
                with lock:
                    stats["total"] += 1
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(exfiltrate) for _ in range(workers)]
        
        while time.time() - start < duration:
            time.sleep(1)
            elapsed = time.time() - start
            mb_sent = stats["bytes_sent"] / 1024 / 1024
            rate = stats["total"] / elapsed if elapsed > 0 else 0
            print(f"  📤 {stats['total']:,} uploads | {mb_sent:.1f} MB | 🛡️ {stats['blocked']:,} blocked")
        
        running = False
    
    elapsed = time.time() - start
    mb_total = stats["bytes_sent"] / 1024 / 1024
    print("\n" + "="*60)
    print(f"  ✅ EXFILTRATION COMPLETE")
    print(f"  📊 Total: {stats['total']:,} uploads ({mb_total:.1f} MB)")
    print(f"  🛡️  Blocked: {stats['blocked']:,} ({stats['blocked']/max(stats['total'],1)*100:.1f}%)")
    print("="*60 + "\n")
    return stats


def run_all_scenarios():
    """Run all attack scenarios sequentially."""
    print("\n" + "🚨"*30)
    print("  ⚔️ FULL ATTACK SIMULATION SUITE ⚔️")
    print("🚨"*30 + "\n")
    
    results = {}
    
    # Clear blocklist before each attack
    clear_blocklist()
    results["ddos"] = ddos_attack(duration=25, workers=150)
    
    time.sleep(2)
    clear_blocklist()
    results["scraping"] = scraping_attack(duration=25, workers=100)
    
    time.sleep(2)
    clear_blocklist()
    results["exfiltration"] = exfiltration_attack(duration=20, workers=50)
    
    # Final summary
    print("\n" + "="*60)
    print("  📊 FINAL ATTACK SUMMARY")
    print("="*60)
    print(f"  {'Scenario':<20} {'Requests':>10} {'Blocked':>10} {'Rate':>10}")
    print("-"*60)
    for name, stats in results.items():
        pct = stats['blocked'] / max(stats['total'], 1) * 100
        print(f"  {name:<20} {stats['total']:>10,} {stats['blocked']:>10,} {pct:>9.1f}%")
    print("="*60 + "\n")
    
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Real World Scale Attack Simulator")
    parser.add_argument("--scenario", choices=["ddos", "scraping", "exfiltration", "all"], 
                       default="all")
    parser.add_argument("--duration", type=int, default=25)
    parser.add_argument("--workers", type=int, default=150)
    args = parser.parse_args()
    
    if args.scenario == "all":
        run_all_scenarios()
    elif args.scenario == "ddos":
        clear_blocklist()
        ddos_attack(duration=args.duration, workers=args.workers)
    elif args.scenario == "scraping":
        clear_blocklist()
        scraping_attack(duration=args.duration, workers=args.workers)
    elif args.scenario == "exfiltration":
        clear_blocklist()
        exfiltration_attack(duration=args.duration, workers=args.workers)

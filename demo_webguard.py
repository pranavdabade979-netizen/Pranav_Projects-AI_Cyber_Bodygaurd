#!/usr/bin/env python3
"""
Web Guard Demonstration Script
Shows how Web Guard detects malicious websites in real-time
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.web_guard import is_malicious_domain, check_url_virustotal
from logger import get_logger

log = get_logger("demo_webguard")

def demo_local_blacklist():
    """Demonstrate instant local blacklist detection"""
    print("\n" + "=" * 70)
    print("TEST 1: LOCAL BLACKLIST DETECTION (INSTANT - No API Call)")
    print("=" * 70)
    
    test_domains = [
        ("malicious-site.com", True),
        ("phishing-example.net", True),
        ("fake-bank-login.ru", True),
        ("google.com", False),
        ("github.com", False),
        ("github.com", False),
    ]
    
    print("\nChecking domains against local blacklist...\n")
    for domain, should_be_malicious in test_domains:
        result = is_malicious_domain(domain)
        status = "🚫 BLOCKED" if result else "✅ ALLOWED"
        check = "✓" if result == should_be_malicious else "✗"
        print(f"  {check} {domain:30} {status}")


def demo_virustotal_api():
    """Demonstrate VirusTotal API detection (requires API key)"""
    print("\n" + "=" * 70)
    print("TEST 2: VIRUSTOTAL API DETECTION (Real-time 70+ Antivirus Engines)")
    print("=" * 70)
    print("\nNote: This requires internet connection and valid API key\n")
    
    # Real URLs for testing
    test_cases = [
        {
            "url": "https://www.google.com",
            "description": "Safe search engine"
        },
        {
            "url": "https://www.github.com", 
            "description": "Safe code repository"
        },
        {
            "url": "https://malicious-site.com",
            "description": "Known malicious domain (from blacklist)"
        }
    ]
    
    for test in test_cases:
        print(f"Checking: {test['url']}")
        print(f"  Description: {test['description']}")
        
        try:
            result = check_url_virustotal(test['url'])
            
            if result['malicious']:
                print(f"  Status: 🚫 MALICIOUS DETECTED")
                print(f"  Details: {result['details']}")
            else:
                print(f"  Status: ✅ SAFE")
                print(f"  {result['details']}")
        except Exception as e:
            print(f"  Error: {str(e)}")
        
        print()


def demo_threat_scenarios():
    """Demonstrate real-world threat scenarios"""
    print("\n" + "=" * 70)
    print("TEST 3: THREAT SCENARIO SIMULATION")
    print("=" * 70)
    
    scenarios = [
        {
            "name": "Phishing Email Attack",
            "url": "phishing-example.net",
            "description": "User clicks link in suspicious email"
        },
        {
            "name": "Trojan Download",
            "url": "fake-bank-login.ru",
            "description": "User attempts to access fake banking site"
        },
        {
            "name": "Trusted Site Access",
            "url": "google.com",
            "description": "User accesses legitimate service"
        },
    ]
    
    print("\nSimulating user access attempts:\n")
    for scenario in scenarios:
        print(f"Scenario: {scenario['name']}")
        print(f"  URL: {scenario['url']}")
        print(f"  Context: {scenario['description']}")
        
        # Check if malicious
        is_malicious = is_malicious_domain(scenario['url'])
        
        if is_malicious:
            print(f"  Result: 🚫 BLOCKED - Malicious domain detected")
            print(f"  Action: Alert user, prevent connection")
        else:
            print(f"  Result: ✅ ALLOWED - Domain approved")
            print(f"  Action: Permit connection")
        
        print()


def main():
    """Run all demonstrations"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "WEB GUARD SECURITY MODULE DEMO" + " " * 24 + "║")
    print("╚" + "=" * 68 + "╝")
    
    log.info("Starting Web Guard demonstration")
    
    # Run demos
    demo_local_blacklist()
    demo_threat_scenarios()
    
    try:
        demo_virustotal_api()
    except Exception as e:
        print(f"\n⚠️  VirusTotal demo error: {str(e)}")
        print("Note: This is expected if internet is unavailable or API key is invalid")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
Web Guard provides THREE layers of protection:

1. Local Blacklist         → Instant detection of known malicious domains
2. VirusTotal API          → Real-time scanning against 70+ antivirus engines
3. Clipboard Monitoring    → Alerts on suspicious URLs in clipboard

Results are logged to: logs/threat_logs.json
Dashboard available at: http://localhost:5000 (when running dashboard.py)
    """)
    
    log.info("Web Guard demonstration completed")


if __name__ == "__main__":
    main()

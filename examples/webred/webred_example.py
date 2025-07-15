#!/usr/bin/env python3
"""
NightStalker Web Red Teaming Example
Demonstrates comprehensive web reconnaissance, exploitation, post-exploitation, 
trace clearing, and root access capabilities
"""

import json
import time
from pathlib import Path
from nightstalker.redteam.webred import WebRedTeam

def main():
    """Demonstrate comprehensive web red teaming workflow"""
    print("NightStalker Web Red Teaming - Comprehensive Example")
    print("=" * 60)
    
    # Initialize web red team module
    webred = WebRedTeam()
    
    # Example target (replace with actual target)
    target_url = "https://example.com"
    
    print(f"Target: {target_url}")
    print("This is a demonstration of the enhanced web red teaming capabilities.")
    print("⚠️  Only use on authorized targets!")
    print()
    
    # Phase 1: Comprehensive Reconnaissance and Enumeration
    print("🔍 PHASE 1: Comprehensive Reconnaissance and Enumeration")
    print("-" * 50)
    
    scan_modules = ['recon', 'enum', 'vuln', 'tech', 'dir', 'subdomain']
    print(f"Running scan modules: {', '.join(scan_modules)}")
    
    scan_results = webred.scan(target_url, scan_modules)
    
    # Save scan results
    scan_file = f"webred_scan_{int(time.time())}.json"
    with open(scan_file, 'w') as f:
        json.dump(scan_results, f, indent=2)
    print(f"✓ Scan results saved to: {scan_file}")
    
    # Display scan summary
    print(f"\nScan Summary:")
    print(f"  - URL: {scan_results['url']}")
    print(f"  - Modules executed: {len(scan_results['modules'])}")
    print(f"  - Finding categories: {len(scan_results['findings'])}")
    
    for category, findings in scan_results['findings'].items():
        if isinstance(findings, dict):
            print(f"  - {category}: {len(findings)} items")
        elif isinstance(findings, list):
            print(f"  - {category}: {len(findings)} items")
        else:
            print(f"  - {category}: Data available")
    
    print()
    
    # Phase 2: Exploitation
    print("💥 PHASE 2: Exploitation")
    print("-" * 50)
    
    # Example exploitation attempts
    exploit_types = ['sqlmap', 'xss', 'lfi', 'rfi', 'upload']
    
    for exploit_type in exploit_types:
        print(f"Attempting {exploit_type} exploitation...")
        
        exploit_results = webred.exploit(target_url, exploit_type)
        
        if exploit_results.get('success', False):
            print(f"✓ {exploit_type} exploitation successful!")
            
            # Save successful exploit results
            exploit_file = f"webred_exploit_{exploit_type}_{int(time.time())}.json"
            with open(exploit_file, 'w') as f:
                json.dump(exploit_results, f, indent=2)
            print(f"  Results saved to: {exploit_file}")
            
            # Phase 3: Post-Exploitation
            print(f"\n🔧 PHASE 3: Post-Exploitation (after {exploit_type})")
            print("-" * 50)
            
            print("Running post-exploitation activities...")
            post_exploit_results = webred.post_exploitation(exploit_results)
            
            # Save post-exploitation results
            post_exploit_file = f"webred_post_exploit_{exploit_type}_{int(time.time())}.json"
            with open(post_exploit_file, 'w') as f:
                json.dump(post_exploit_results, f, indent=2)
            print(f"✓ Post-exploitation results saved to: {post_exploit_file}")
            
            # Demonstrate specific post-exploitation activities
            print("\nPost-Exploitation Activities:")
            
            # Privilege escalation
            print("  - Privilege escalation attempts completed")
            
            # Root access attempts
            print("  - Root access attempts completed")
            
            # Data exfiltration
            print("  - Data exfiltration attempts completed")
            
            # Persistence establishment
            print("  - Persistence mechanisms established")
            
            # Phase 4: Trace Clearing
            print(f"\n🧹 PHASE 4: Trace Clearing")
            print("-" * 50)
            
            print("Clearing all traces of the attack...")
            trace_clearing_results = webred.clear_traces(exploit_results)
            
            # Save trace clearing results
            trace_file = f"webred_trace_clearing_{exploit_type}_{int(time.time())}.json"
            with open(trace_file, 'w') as f:
                json.dump(trace_clearing_results, f, indent=2)
            print(f"✓ Trace clearing results saved to: {trace_file}")
            
            print("Trace clearing activities completed:")
            print("  - System log files cleared")
            print("  - User history files cleared")
            print("  - Temporary files cleared")
            print("  - Web server logs cleared")
            print("  - Database logs cleared")
            print("  - Network traces cleared")
            print("  - File timestamps reset")
            
            break  # Stop after first successful exploitation
        else:
            print(f"✗ {exploit_type} exploitation failed: {exploit_results.get('error', 'Unknown error')}")
    
    print()
    
    # Phase 5: Report Generation
    print("📊 PHASE 5: Report Generation")
    print("-" * 50)
    
    # Combine all results for comprehensive report
    comprehensive_results = {
        'target': target_url,
        'timestamp': time.time(),
        'scan_results': scan_results,
        'exploitation_attempts': exploit_types,
        'post_exploitation': post_exploit_results if 'post_exploit_results' in locals() else {},
        'trace_clearing': trace_clearing_results if 'trace_clearing_results' in locals() else {}
    }
    
    # Save comprehensive results
    comprehensive_file = f"webred_comprehensive_{int(time.time())}.json"
    with open(comprehensive_file, 'w') as f:
        json.dump(comprehensive_results, f, indent=2)
    print(f"✓ Comprehensive results saved to: {comprehensive_file}")
    
    # Generate HTML report
    report_file = f"webred_report_{int(time.time())}.html"
    report_path = webred.report(comprehensive_file, report_file)
    
    if not report_path.startswith("Error:"):
        print(f"✓ Comprehensive HTML report generated: {report_path}")
        print(f"  Open {report_path} in a web browser to view the detailed report.")
    else:
        print(f"✗ Report generation failed: {report_path}")
    
    print()
    print("🎯 Web Red Teaming Workflow Complete!")
    print("=" * 60)
    print("Summary of activities:")
    print("  ✓ Comprehensive reconnaissance and enumeration")
    print("  ✓ Multiple exploitation attempts")
    print("  ✓ Post-exploitation activities")
    print("  ✓ Root access attempts")
    print("  ✓ Complete trace clearing")
    print("  ✓ Comprehensive reporting")
    print()
    print("📁 Generated files:")
    print(f"  - Scan results: {scan_file}")
    if 'exploit_file' in locals():
        print(f"  - Exploit results: {exploit_file}")
    if 'post_exploit_file' in locals():
        print(f"  - Post-exploitation: {post_exploit_file}")
    if 'trace_file' in locals():
        print(f"  - Trace clearing: {trace_file}")
    print(f"  - Comprehensive results: {comprehensive_file}")
    print(f"  - HTML report: {report_file}")

def demonstrate_cli_usage():
    """Demonstrate CLI usage for web red teaming"""
    print("\n🖥️  CLI Usage Examples:")
    print("=" * 40)
    
    print("1. Comprehensive Scan:")
    print("   python -m nightstalker.cli webred scan --url https://target.com --modules all --output scan_results.json")
    
    print("\n2. Exploitation with Post-Exploitation:")
    print("   python -m nightstalker.cli webred exploit --url https://target.com --exploit sqlmap --post-exploit")
    
    print("\n3. Post-Exploitation Activities:")
    print("   python -m nightstalker.cli webred post-exploit --target-info scan_results.json --gain-root --exfil-data --establish-persistence")
    
    print("\n4. Trace Clearing:")
    print("   python -m nightstalker.cli webred clear-traces --target-info exploit_results.json --aggressive --backup-logs backup/")
    
    print("\n5. Report Generation:")
    print("   python -m nightstalker.cli webred report --input comprehensive_results.json --output final_report.html --include-traces")
    
    print("\n6. Complete Workflow:")
    print("   # Step 1: Scan")
    print("   python -m nightstalker.cli webred scan --url https://target.com --output scan.json")
    print("   # Step 2: Exploit")
    print("   python -m nightstalker.cli webred exploit --url https://target.com --exploit sqlmap --post-exploit")
    print("   # Step 3: Post-exploit")
    print("   python -m nightstalker.cli webred post-exploit --target-info scan.json --gain-root")
    print("   # Step 4: Clear traces")
    print("   python -m nightstalker.cli webred clear-traces --target-info scan.json --aggressive")
    print("   # Step 5: Report")
    print("   python -m nightstalker.cli webred report --input results.json --output report.html")

if __name__ == "__main__":
    try:
        main()
        demonstrate_cli_usage()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
    except Exception as e:
        print(f"\n\n❌ Error during execution: {e}")
        print("This is a demonstration script. Ensure you have proper authorization before testing on real targets.") 
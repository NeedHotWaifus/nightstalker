"""
Polymorphic Engine Module
Genetic algorithm-based payload mutation and evolution
"""

import random
import hashlib
import base64
import struct
import logging
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass
from pathlib import Path
import json
import time

logger = logging.getLogger(__name__)

@dataclass
class MutationRule:
    """Represents a mutation rule for payload evolution"""
    name: str
    description: str
    mutation_function: Callable
    probability: float
    enabled: bool = True

@dataclass
class PayloadVariant:
    """Represents a payload variant with metadata"""
    data: bytes
    mutation_history: List[str]
    fitness_score: float
    generation: int
    parent_hash: Optional[str] = None
    execution_time: float = 0.0
    detection_rate: float = 0.0

class PolymorphicEngine:
    """Advanced polymorphic engine for payload evolution"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.population: List[PayloadVariant] = []
        self.mutation_rules: Dict[str, MutationRule] = {}
        self.fitness_history: List[float] = []
        self.generation_count = 0
        
        # Genetic algorithm parameters
        self.population_size = self.config.get('population_size', 50)
        self.mutation_rate = self.config.get('mutation_rate', 0.3)
        self.crossover_rate = self.config.get('crossover_rate', 0.7)
        self.elite_size = self.config.get('elite_size', 5)
        self.max_generations = self.config.get('max_generations', 100)
        
        # Fitness evaluation parameters
        self.fitness_weights = {
            'stealth': 0.4,
            'effectiveness': 0.3,
            'size': 0.1,
            'complexity': 0.2
        }
        
        self._setup_mutation_rules()
    
    def _setup_mutation_rules(self):
        """Setup available mutation rules"""
        self.mutation_rules = {
            'bit_flip': MutationRule(
                name='bit_flip',
                description='Flip random bits in payload',
                mutation_function=self._bit_flip_mutation,
                probability=0.2
            ),
            'byte_substitution': MutationRule(
                name='byte_substitution',
                description='Substitute random bytes',
                mutation_function=self._byte_substitution_mutation,
                probability=0.15
            ),
            'insertion': MutationRule(
                name='insertion',
                description='Insert random bytes',
                mutation_function=self._insertion_mutation,
                probability=0.1
            ),
            'deletion': MutationRule(
                name='deletion',
                description='Delete random bytes',
                mutation_function=self._deletion_mutation,
                probability=0.1
            ),
            'repetition': MutationRule(
                name='repetition',
                description='Repeat payload segments',
                mutation_function=self._repetition_mutation,
                probability=0.1
            ),
            'encoding': MutationRule(
                name='encoding',
                description='Apply encoding transformations',
                mutation_function=self._encoding_mutation,
                probability=0.1
            ),
            'encryption': MutationRule(
                name='encryption',
                description='Apply encryption layers',
                mutation_function=self._encryption_mutation,
                probability=0.1
            ),
            'obfuscation': MutationRule(
                name='obfuscation',
                description='Apply obfuscation techniques',
                mutation_function=self._obfuscation_mutation,
                probability=0.15
            )
        }
    
    def initialize_population(self, base_payload: bytes, size: int = None):
        """Initialize population with base payload variants"""
        if size is None:
            size = self.population_size
        
        self.population = []
        
        for i in range(size):
            # Create variant with random mutations
            variant_data = base_payload.copy()
            mutation_history = []
            
            # Apply random mutations
            num_mutations = random.randint(1, 3)
            for _ in range(num_mutations):
                mutation_rule = self._select_mutation_rule()
                if mutation_rule:
                    variant_data = mutation_rule.mutation_function(variant_data)
                    mutation_history.append(mutation_rule.name)
            
            variant = PayloadVariant(
                data=variant_data,
                mutation_history=mutation_history,
                fitness_score=0.0,
                generation=0,
                parent_hash=hashlib.md5(base_payload).hexdigest()
            )
            
            self.population.append(variant)
        
        logger.info(f"Initialized population with {len(self.population)} variants")
    
    def _select_mutation_rule(self) -> Optional[MutationRule]:
        """Select a mutation rule based on probabilities"""
        available_rules = [
            rule for rule in self.mutation_rules.values() 
            if rule.enabled and random.random() < rule.probability
        ]
        
        if available_rules:
            return random.choice(available_rules)
        return None
    
    def _bit_flip_mutation(self, data: bytes) -> bytes:
        """Flip random bits in the payload"""
        if len(data) == 0:
            return data
        
        data_array = bytearray(data)
        num_flips = random.randint(1, min(10, len(data_array)))
        
        for _ in range(num_flips):
            pos = random.randint(0, len(data_array) - 1)
            bit_pos = random.randint(0, 7)
            data_array[pos] ^= (1 << bit_pos)
        
        return bytes(data_array)
    
    def _byte_substitution_mutation(self, data: bytes) -> bytes:
        """Substitute random bytes with new values"""
        if len(data) == 0:
            return data
        
        data_array = bytearray(data)
        num_substitutions = random.randint(1, min(5, len(data_array)))
        
        for _ in range(num_substitutions):
            pos = random.randint(0, len(data_array) - 1)
            new_byte = random.randint(0, 255)
            data_array[pos] = new_byte
        
        return bytes(data_array)
    
    def _insertion_mutation(self, data: bytes) -> bytes:
        """Insert random bytes at random positions"""
        if len(data) == 0:
            return bytes([random.randint(0, 255)])
        
        data_array = bytearray(data)
        num_insertions = random.randint(1, 3)
        
        for _ in range(num_insertions):
            pos = random.randint(0, len(data_array))
            insert_byte = random.randint(0, 255)
            data_array.insert(pos, insert_byte)
        
        return bytes(data_array)
    
    def _deletion_mutation(self, data: bytes) -> bytes:
        """Delete random bytes"""
        if len(data) <= 1:
            return data
        
        data_array = bytearray(data)
        num_deletions = random.randint(1, min(3, len(data_array) - 1))
        
        for _ in range(num_deletions):
            pos = random.randint(0, len(data_array) - 1)
            del data_array[pos]
        
        return bytes(data_array)
    
    def _repetition_mutation(self, data: bytes) -> bytes:
        """Repeat parts of the payload"""
        if len(data) < 2:
            return data + data
        
        start = random.randint(0, len(data) - 1)
        end = random.randint(start + 1, len(data))
        repeat_count = random.randint(1, 3)
        
        repeated_part = data[start:end] * repeat_count
        return data + repeated_part
    
    def _encoding_mutation(self, data: bytes) -> bytes:
        """Apply encoding transformations"""
        encodings = ['base64', 'hex', 'rot13', 'xor']
        encoding = random.choice(encodings)
        
        try:
            if encoding == 'base64':
                return base64.b64encode(data)
            elif encoding == 'hex':
                return data.hex().encode()
            elif encoding == 'rot13':
                # Simple ROT13 for bytes
                return bytes((b + 13) % 256 for b in data)
            elif encoding == 'xor':
                # XOR with random key
                key = random.randint(1, 255)
                return bytes(b ^ key for b in data)
        except Exception as e:
            logger.warning(f"Encoding mutation failed: {e}")
        
        return data
    
    def _encryption_mutation(self, data: bytes) -> bytes:
        """Apply encryption layers"""
        try:
            # Simple XOR encryption with random key
            key_length = random.randint(4, 16)
            key = bytes(random.randint(0, 255) for _ in range(key_length))
            
            encrypted = bytearray()
            for i, byte in enumerate(data):
                key_byte = key[i % len(key)]
                encrypted.append(byte ^ key_byte)
            
            # Prepend key length and key
            return struct.pack('<H', key_length) + key + bytes(encrypted)
            
        except Exception as e:
            logger.warning(f"Encryption mutation failed: {e}")
            return data
    
    def _obfuscation_mutation(self, data: bytes) -> bytes:
        """Apply obfuscation techniques"""
        obfuscations = ['padding', 'junk_code', 'string_obfuscation']
        obfuscation = random.choice(obfuscations)
        
        try:
            if obfuscation == 'padding':
                # Add random padding
                padding_size = random.randint(1, 16)
                padding = bytes(random.randint(0, 255) for _ in range(padding_size))
                return data + padding
            
            elif obfuscation == 'junk_code':
                # Add junk bytes
                junk_size = random.randint(1, 8)
                junk = bytes(random.randint(0, 255) for _ in range(junk_size))
                pos = random.randint(0, len(data))
                return data[:pos] + junk + data[pos:]
            
            elif obfuscation == 'string_obfuscation':
                # Simple string obfuscation
                return data.replace(b'\x00', b'\x01').replace(b'\x01', b'\x00')
                
        except Exception as e:
            logger.warning(f"Obfuscation mutation failed: {e}")
        
        return data
    
    def evaluate_fitness(self, variant: PayloadVariant, 
                        evaluation_func: Callable = None) -> float:
        """Evaluate fitness of a payload variant"""
        if evaluation_func:
            return evaluation_func(variant)
        
        # Default fitness evaluation
        fitness = 0.0
        
        # Stealth score (based on entropy and patterns)
        stealth_score = self._calculate_stealth_score(variant.data)
        fitness += self.fitness_weights['stealth'] * stealth_score
        
        # Effectiveness score (based on size and complexity)
        effectiveness_score = self._calculate_effectiveness_score(variant.data)
        fitness += self.fitness_weights['effectiveness'] * effectiveness_score
        
        # Size score (prefer smaller payloads)
        size_score = max(0, 1 - len(variant.data) / 10000)  # Normalize to 10KB
        fitness += self.fitness_weights['size'] * size_score
        
        # Complexity score (based on mutation history)
        complexity_score = len(variant.mutation_history) / 10  # Normalize
        fitness += self.fitness_weights['complexity'] * complexity_score
        
        return min(1.0, fitness)
    
    def _calculate_stealth_score(self, data: bytes) -> float:
        """Calculate stealth score based on entropy and patterns"""
        if len(data) == 0:
            return 0.0
        
        # Calculate byte entropy
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * (p.bit_length() - 1)
        
        # Normalize entropy (0-1)
        entropy_score = min(1.0, entropy / 8.0)
        
        # Check for suspicious patterns
        suspicious_patterns = [
            b'\x90\x90\x90',  # NOP sled
            b'\x00\x00\x00',  # Null bytes
            b'\xff\xff\xff',  # All ones
            b'cmd.exe',
            b'powershell',
            b'calc.exe'
        ]
        
        pattern_penalty = 0.0
        for pattern in suspicious_patterns:
            if pattern in data:
                pattern_penalty += 0.1
        
        return max(0.0, entropy_score - pattern_penalty)
    
    def _calculate_effectiveness_score(self, data: bytes) -> float:
        """Calculate effectiveness score"""
        if len(data) == 0:
            return 0.0
        
        # Base effectiveness on payload characteristics
        score = 0.5  # Base score
        
        # Prefer non-zero bytes
        non_zero_ratio = sum(1 for b in data if b != 0) / len(data)
        score += 0.3 * non_zero_ratio
        
        # Prefer reasonable size
        if 100 <= len(data) <= 5000:
            score += 0.2
        
        return min(1.0, score)
    
    def select_parents(self) -> List[PayloadVariant]:
        """Select parents for crossover using tournament selection"""
        tournament_size = 3
        parents = []
        
        for _ in range(2):
            tournament = random.sample(self.population, tournament_size)
            winner = max(tournament, key=lambda v: v.fitness_score)
            parents.append(winner)
        
        return parents
    
    def crossover(self, parent1: PayloadVariant, parent2: PayloadVariant) -> Tuple[PayloadVariant, PayloadVariant]:
        """Perform crossover between two payload variants"""
        data1 = parent1.data
        data2 = parent2.data
        
        if len(data1) < 2 or len(data2) < 2:
            return parent1, parent2
        
        # Single-point crossover
        point1 = random.randint(1, len(data1) - 1)
        point2 = random.randint(1, len(data2) - 1)
        
        child1_data = data1[:point1] + data2[point2:]
        child2_data = data2[:point2] + data1[point1:]
        
        # Combine mutation histories
        combined_history = list(set(parent1.mutation_history + parent2.mutation_history))
        
        child1 = PayloadVariant(
            data=child1_data,
            mutation_history=combined_history + ['crossover'],
            fitness_score=0.0,
            generation=self.generation_count + 1,
            parent_hash=hashlib.md5(parent1.data).hexdigest()
        )
        
        child2 = PayloadVariant(
            data=child2_data,
            mutation_history=combined_history + ['crossover'],
            fitness_score=0.0,
            generation=self.generation_count + 1,
            parent_hash=hashlib.md5(parent2.data).hexdigest()
        )
        
        return child1, child2
    
    def mutate_variant(self, variant: PayloadVariant) -> PayloadVariant:
        """Apply mutations to a payload variant"""
        mutated_data = variant.data.copy()
        new_history = variant.mutation_history.copy()
        
        # Apply random mutations
        num_mutations = random.randint(1, 2)
        for _ in range(num_mutations):
            mutation_rule = self._select_mutation_rule()
            if mutation_rule:
                mutated_data = mutation_rule.mutation_function(mutated_data)
                new_history.append(mutation_rule.name)
        
        return PayloadVariant(
            data=mutated_data,
            mutation_history=new_history,
            fitness_score=0.0,
            generation=self.generation_count + 1,
            parent_hash=hashlib.md5(variant.data).hexdigest()
        )
    
    def evolve_generation(self, evaluation_func: Callable = None):
        """Evolve the population to the next generation"""
        # Evaluate current population
        for variant in self.population:
            variant.fitness_score = self.evaluate_fitness(variant, evaluation_func)
        
        # Sort by fitness
        self.population.sort(key=lambda v: v.fitness_score, reverse=True)
        
        # Record fitness statistics
        avg_fitness = sum(v.fitness_score for v in self.population) / len(self.population)
        self.fitness_history.append(avg_fitness)
        
        # Create new population
        new_population = []
        
        # Keep elite individuals
        elite = self.population[:self.elite_size]
        new_population.extend(elite)
        
        # Generate new individuals
        while len(new_population) < self.population_size:
            if random.random() < self.crossover_rate:
                # Crossover
                parents = self.select_parents()
                child1, child2 = self.crossover(parents[0], parents[1])
                
                # Mutate children
                if random.random() < self.mutation_rate:
                    child1 = self.mutate_variant(child1)
                if random.random() < self.mutation_rate:
                    child2 = self.mutate_variant(child2)
                
                new_population.extend([child1, child2])
            else:
                # Mutation only
                parent = random.choice(self.population)
                child = self.mutate_variant(parent)
                new_population.append(child)
        
        # Trim to population size
        self.population = new_population[:self.population_size]
        self.generation_count += 1
        
        logger.info(f"Generation {self.generation_count}: Avg fitness = {avg_fitness:.4f}")
    
    def run_evolution(self, base_payload: bytes, generations: int = None, 
                     evaluation_func: Callable = None) -> PayloadVariant:
        """Run the complete evolution process"""
        if generations is None:
            generations = self.max_generations
        
        logger.info(f"Starting evolution with {generations} generations")
        
        # Initialize population
        self.initialize_population(base_payload)
        
        # Run evolution
        for generation in range(generations):
            self.evolve_generation(evaluation_func)
            
            # Check for convergence
            if len(self.fitness_history) >= 10:
                recent_fitness = self.fitness_history[-10:]
                if max(recent_fitness) - min(recent_fitness) < 0.01:
                    logger.info("Evolution converged")
                    break
        
        # Return best variant
        best_variant = max(self.population, key=lambda v: v.fitness_score)
        logger.info(f"Evolution completed. Best fitness: {best_variant.fitness_score:.4f}")
        
        return best_variant
    
    def get_evolution_stats(self) -> Dict[str, Any]:
        """Get statistics about the evolution process"""
        if not self.population:
            return {}
        
        current_fitness = [v.fitness_score for v in self.population]
        
        return {
            'generation_count': self.generation_count,
            'population_size': len(self.population),
            'current_avg_fitness': sum(current_fitness) / len(current_fitness),
            'current_max_fitness': max(current_fitness),
            'current_min_fitness': min(current_fitness),
            'fitness_history': self.fitness_history,
            'best_variant': {
                'fitness': max(current_fitness),
                'size': len(max(self.population, key=lambda v: v.fitness_score).data),
                'mutations': max(self.population, key=lambda v: v.fitness_score).mutation_history
            }
        }
    
    def save_evolution_data(self, file_path: str):
        """Save evolution data to file"""
        try:
            evolution_data = {
                'generation_count': self.generation_count,
                'fitness_history': self.fitness_history,
                'population_stats': self.get_evolution_stats(),
                'best_variants': [
                    {
                        'data': base64.b64encode(v.data).decode(),
                        'fitness': v.fitness_score,
                        'mutations': v.mutation_history,
                        'generation': v.generation
                    }
                    for v in sorted(self.population, key=lambda v: v.fitness_score, reverse=True)[:10]
                ]
            }
            
            with open(file_path, 'w') as f:
                json.dump(evolution_data, f, indent=2)
            
            logger.info(f"Evolution data saved to {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to save evolution data: {e}")
    
    def load_evolution_data(self, file_path: str):
        """Load evolution data from file"""
        try:
            with open(file_path, 'r') as f:
                evolution_data = json.load(f)
            
            self.generation_count = evolution_data.get('generation_count', 0)
            self.fitness_history = evolution_data.get('fitness_history', [])
            
            # Reconstruct population from best variants
            self.population = []
            for variant_data in evolution_data.get('best_variants', []):
                data = base64.b64decode(variant_data['data'])
                variant = PayloadVariant(
                    data=data,
                    mutation_history=variant_data['mutations'],
                    fitness_score=variant_data['fitness'],
                    generation=variant_data['generation']
                )
                self.population.append(variant)
            
            logger.info(f"Evolution data loaded from {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to load evolution data: {e}") 
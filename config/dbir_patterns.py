"""
Cyber-SOC Auto-Responder DBIR Patterns Module

This module loads and manages the 2024 Verizon DBIR incident patterns
for intelligent threat scoring and risk assessment.
"""

import yaml
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

class ThreatActorType(Enum):
    """Threat actor classification"""
    ORGANIZED_CRIME = "organized_crime"
    NATION_STATE = "nation_state"
    ACTIVIST = "activist"
    MALICIOUS_INSIDER = "malicious_insider"
    UNINTENTIONAL_INSIDER = "unintentional_insider"

class IncidentPattern(Enum):
    """DBIR incident patterns"""
    SYSTEM_INTRUSION = "system_intrusion"
    SOCIAL_ENGINEERING = "social_engineering"
    WEB_APPLICATION_ATTACKS = "web_application_attacks"
    DENIAL_OF_SERVICE = "denial_of_service"
    LOST_STOLEN_ASSETS = "lost_stolen_assets"
    MISCELLANEOUS_ERRORS = "miscellaneous_errors"
    PRIVILEGE_MISUSE = "privilege_misuse"
    EVERYTHING_ELSE = "everything_else"

@dataclass
class PatternDetails:
    """Details for a specific incident pattern"""
    description: str
    base_score: float
    indicators: List[str]
    common_assets: List[str]
    time_to_discovery_days: int

@dataclass
class ThreatActorDetails:
    """Details for a specific threat actor type"""
    frequency: int
    sophistication: str
    motivation: str

class DBIRPatterns:
    """
    Manages DBIR patterns for threat intelligence and scoring.
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir is None:
            config_dir = Path(__file__).parent
        
        self.config_dir = config_dir
        self._patterns_data = self._load_patterns()
        
        # Parse patterns into structured objects
        self.patterns = self._parse_patterns()
        self.threat_actors = self._parse_threat_actors()
        self.industry_multipliers = self._patterns_data.get("industry_risk_multipliers", {})
        self.asset_criticality = self._patterns_data.get("asset_criticality", {})
        self.temporal_factors = self._patterns_data.get("temporal_factors", {})
    
    def _load_patterns(self) -> Dict[str, Any]:
        """Load DBIR patterns from YAML file"""
        patterns_file = self.config_dir / "dbir_patterns.yaml"
        
        if not patterns_file.exists():
            raise FileNotFoundError(f"DBIR patterns file not found: {patterns_file}")
        
        with open(patterns_file, 'r') as f:
            return yaml.safe_load(f)
    
    def _parse_patterns(self) -> Dict[IncidentPattern, PatternDetails]:
        """Parse incident patterns into structured objects"""
        patterns = {}
        
        incident_patterns = self._patterns_data.get("incident_patterns", {})
        
        for pattern_key, pattern_data in incident_patterns.items():
            try:
                pattern_enum = IncidentPattern(pattern_key)
                patterns[pattern_enum] = PatternDetails(
                    description=pattern_data.get("description", ""),
                    base_score=pattern_data.get("base_score", 5.0),
                    indicators=pattern_data.get("indicators", []),
                    common_assets=pattern_data.get("common_assets", []),
                    time_to_discovery_days=pattern_data.get("time_to_discovery_days", 30)
                )
            except ValueError:
                # Skip unknown patterns
                continue
        
        return patterns
    
    def _parse_threat_actors(self) -> Dict[ThreatActorType, ThreatActorDetails]:
        """Parse threat actor information into structured objects"""
        actors = {}
        
        threat_actors_data = self._patterns_data.get("threat_actors", {})
        
        # Parse external actors
        external = threat_actors_data.get("external", {})
        for actor_key, actor_data in external.items():
            try:
                actor_enum = ThreatActorType(actor_key)
                actors[actor_enum] = ThreatActorDetails(
                    frequency=actor_data.get("frequency", 0),
                    sophistication=actor_data.get("sophistication", "unknown"),
                    motivation=actor_data.get("motivation", "unknown")
                )
            except ValueError:
                continue
        
        # Parse internal actors
        internal = threat_actors_data.get("internal", {})
        for actor_key, actor_data in internal.items():
            try:
                actor_enum = ThreatActorType(actor_key)
                actors[actor_enum] = ThreatActorDetails(
                    frequency=actor_data.get("frequency", 0),
                    sophistication=actor_data.get("sophistication", "unknown"),
                    motivation=actor_data.get("motivation", "unknown")
                )
            except ValueError:
                continue
        
        return actors
    
    def get_pattern_score(self, pattern: IncidentPattern) -> float:
        """Get base score for an incident pattern"""
        if pattern in self.patterns:
            return self.patterns[pattern].base_score
        return 5.0  # Default score
    
    def get_pattern_indicators(self, pattern: IncidentPattern) -> List[str]:
        """Get indicators associated with an incident pattern"""
        if pattern in self.patterns:
            return self.patterns[pattern].indicators
        return []
    
    def identify_pattern_from_indicators(self, indicators: List[str]) -> Optional[IncidentPattern]:
        """
        Identify the most likely incident pattern based on observed indicators.
        
        Args:
            indicators: List of observed indicators
            
        Returns:
            Most likely incident pattern or None if no strong match
        """
        pattern_scores = {}
        
        for pattern, details in self.patterns.items():
            matches = 0
            for indicator in indicators:
                if any(pattern_indicator in indicator.lower() 
                      for pattern_indicator in details.indicators):
                    matches += 1
            
            if matches > 0:
                # Score based on percentage of pattern indicators matched
                score = matches / len(details.indicators) if details.indicators else 0
                pattern_scores[pattern] = score
        
        if pattern_scores:
            # Return pattern with highest match score
            best_pattern = max(pattern_scores, key=pattern_scores.get)
            # Only return if we have a reasonable confidence (>20% indicators matched)
            if pattern_scores[best_pattern] > 0.2:
                return best_pattern
        
        return None
    
    def calculate_risk_score(
        self,
        base_score: float,
        industry: Optional[str] = None,
        asset_criticality: Optional[str] = None,
        time_factor: Optional[str] = None,
        threat_actor: Optional[ThreatActorType] = None
    ) -> float:
        """
        Calculate adjusted risk score based on contextual factors.
        
        Args:
            base_score: Base risk score
            industry: Industry type for risk adjustment
            asset_criticality: Asset criticality level
            time_factor: Temporal factor (business_hours, after_hours, etc.)
            threat_actor: Associated threat actor type
            
        Returns:
            Adjusted risk score
        """
        adjusted_score = base_score
        
        # Apply industry multiplier
        if industry and industry in self.industry_multipliers:
            adjusted_score *= self.industry_multipliers[industry]
        
        # Apply asset criticality multiplier
        if asset_criticality and asset_criticality in self.asset_criticality:
            adjusted_score *= self.asset_criticality[asset_criticality]
        
        # Apply temporal factor
        if time_factor and time_factor in self.temporal_factors:
            adjusted_score *= self.temporal_factors[time_factor]
        
        # Apply threat actor sophistication factor
        if threat_actor and threat_actor in self.threat_actors:
            sophistication = self.threat_actors[threat_actor].sophistication
            sophistication_multipliers = {
                "very_high": 1.4,
                "high": 1.2,
                "medium": 1.0,
                "low": 0.8
            }
            adjusted_score *= sophistication_multipliers.get(sophistication, 1.0)
        
        # Ensure score stays within reasonable bounds (0-10)
        return min(max(adjusted_score, 0.0), 10.0)
    
    def get_expected_discovery_time(self, pattern: IncidentPattern) -> int:
        """Get expected time to discovery for a pattern in days"""
        if pattern in self.patterns:
            return self.patterns[pattern].time_to_discovery_days
        return 30  # Default
    
    def get_common_assets(self, pattern: IncidentPattern) -> List[str]:
        """Get commonly affected assets for a pattern"""
        if pattern in self.patterns:
            return self.patterns[pattern].common_assets
        return []
    
    def get_threat_actor_likelihood(self, pattern: IncidentPattern) -> Dict[ThreatActorType, float]:
        """
        Get likelihood of different threat actors for a given pattern.
        
        Returns normalized probabilities for each threat actor type.
        """
        # This is a simplified mapping - in practice you'd want more sophisticated correlation
        pattern_actor_mapping = {
            IncidentPattern.SYSTEM_INTRUSION: {
                ThreatActorType.ORGANIZED_CRIME: 0.4,
                ThreatActorType.NATION_STATE: 0.3,
                ThreatActorType.ACTIVIST: 0.1,
                ThreatActorType.MALICIOUS_INSIDER: 0.2
            },
            IncidentPattern.SOCIAL_ENGINEERING: {
                ThreatActorType.ORGANIZED_CRIME: 0.6,
                ThreatActorType.NATION_STATE: 0.2,
                ThreatActorType.ACTIVIST: 0.1,
                ThreatActorType.MALICIOUS_INSIDER: 0.1
            },
            IncidentPattern.PRIVILEGE_MISUSE: {
                ThreatActorType.MALICIOUS_INSIDER: 0.7,
                ThreatActorType.UNINTENTIONAL_INSIDER: 0.3
            },
            IncidentPattern.MISCELLANEOUS_ERRORS: {
                ThreatActorType.UNINTENTIONAL_INSIDER: 1.0
            }
        }
        
        return pattern_actor_mapping.get(pattern, {
            ThreatActorType.ORGANIZED_CRIME: 0.25,
            ThreatActorType.NATION_STATE: 0.25,
            ThreatActorType.ACTIVIST: 0.25,
            ThreatActorType.MALICIOUS_INSIDER: 0.25
        }) 
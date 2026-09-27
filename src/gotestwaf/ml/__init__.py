"""Advanced ML engine for WAF testing intelligence.

Architecture:
    - FeatureEngine: Extracts rich features from payloads and responses
    - ResponseClassifier: Ensemble classifier for WAF response analysis
    - BypassPredictor: Stacking ensemble for bypass probability prediction
    - DriftDetector: Statistical drift detection for model monitoring
    - HybridEngine: Orchestrates all ML components with fallback chain
    - ModelRegistry: Version tracking and hot-reload
"""

from gotestwaf.ml.engine import HybridMLEngine

__all__ = ["HybridMLEngine"]

"""
core/exceptions.py
Comprehensive exception hierarchy for Shadow NDR ML v5.0.
"""

class ShadowNDRError(Exception):
    """Base exception for entire Shadow NDR system."""
    pass

# Configuration & Secrets
class ConfigError(ShadowNDRError): pass
class SecurityError(ShadowNDRError): pass
class PostQuantumError(ShadowNDRError): pass
class ShamirError(ShadowNDRError): pass
class TPMError(ShadowNDRError): pass

# Model Layer
class ModelError(ShadowNDRError): pass
class ModelLoadError(ModelError): pass
class ModelSaveError(ModelError): pass
class InferenceError(ModelError): pass

# Poisoning & Adversarial
class PoisoningError(ShadowNDRError): pass
class ReversePoisoningError(PoisoningError): pass
class DataContaminationError(PoisoningError): pass

# Quarantine
class QuarantineError(ShadowNDRError): pass
class AirGapError(QuarantineError): pass

# Suicide / Self‑Destruct
class SuicideError(ShadowNDRError): pass
class SelfDestructTriggered(SuicideError): pass

# Honeypot & Deception
class HoneypotError(ShadowNDRError): pass
class DeceptionError(ShadowNDRError): pass
class CanaryTokenError(HoneypotError): pass

# Fingerprinting & Profiling
class FingerprintError(ShadowNDRError): pass
class ProfilingError(FingerprintError): pass

# Quantum & Noise
class QuantumError(ShadowNDRError): pass
class QRNGError(QuantumError): pass

# Self‑Healing
class SelfHealError(ShadowNDRError): pass
class RollbackError(SelfHealError): pass

# API & Network
class APIError(ShadowNDRError): pass
class RateLimitError(APIError): pass
class AuthenticationError(APIError): pass
class AuthorizationError(APIError): pass

# Orchestrator
class OrchestratorError(ShadowNDRError): pass
class SchedulerError(OrchestratorError): pass
class ResourceExhaustionError(OrchestratorError): pass

# Red Team / Simulation
class RedTeamError(ShadowNDRError): pass
class ChaosInjectionError(RedTeamError): pass
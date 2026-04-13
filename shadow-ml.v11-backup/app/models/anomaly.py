# app/core/anomaly_detector.py
import threading
import time
import warnings
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
import shap
from loguru import logger
from scipy import stats
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler, StandardScaler

from app.config import AnomalyConfig
from app.preprocessing.feature_extractor import TemporalFeatureExtractor
from app.preprocessing.normalizers import PercentileScoreNormalizer
from app.preprocessing.augmentations import synthesize_anomalies
from app.preprocessing.scalers import get_scaler
from app.ml.isolation_forest import IFDetector
from app.ml.lof import LOFDetector
from app.ml.ecod import ECODDetector
from app.ml.half_space_trees import HSTDetector
from app.ml.autoencoder import AEDetector
from app.ml.one_class_svm import OCSVMDetector
from app.ml.lstm_attn import LSTMDetector
from app.ml.graph_anomaly import GraphDetector
from app.ml.maml import MAMLDetector
from app.ml.transformer import TransformerDetector
from app.ml.contrastive import ContrastiveDetector
from app.ml.gnn_flow import GNNFlowDetector
from app.ml.zero_day import ZeroDayDetector
from app.aviation.domain_model import AviationDomainModel
from app.aviation.adsb_spoofing import ADSBSpoofingDetector
from app.aviation.flight_path import FlightPathDetector
from app.aviation.blackbox import BlackBoxAnalyzer
from app.aviation.forensic import ForensicAnalyzer
from app.aviation.threat_intel import ThreatIntelFeed
from app.services.model_registry import ModelVersionRegistry
from app.services.monitoring import ModelMonitoringDashboard
from app.services.risk_scoring import RiskScoringEngine
from app.services.batch_predictor import BatchPredictor
from app.self_healing.vuln_detector import VulnerabilityDetector
from app.self_healing.healing_engine import SelfHealingEngine
from app.profiling.attacker_profiler import AttackerProfiler
from app.digital_twin.network_twin import NetworkDigitalTwin
from app.enterprise.multi_tenant import MultiTenantDetector
from app.enterprise.federated import FederatedLearner
from app.utils.helpers import b2f, safe_divide
from app.utils.metrics import (
    ml_score_histogram,
    packets_processed,
    processing_latency,
    critical_alerts_total,
    dlq_publish_total,
    rate_limited_packets,
    adsb_messages,
    emergency_squawk,
)
from app.utils.gpu import _gpu
from app.utils.concurrency import safe_go, with_retry

warnings.filterwarnings("ignore")


class AnomalyDetector:
    """
    AnomalyDetector v10 — Aviation Ultimate Edition

    Orchestrates 13 ML models + aviation-specific modules.
    """

    def __init__(self, config: Optional[AnomalyConfig] = None):
        self.config = config or AnomalyConfig()
        self._lock = threading.RLock()

        # Preprocessing components
        self.imputer: Optional[SimpleImputer] = None
        self.scaler: Optional[Union[RobustScaler, StandardScaler]] = None
        self.temporal: Optional[TemporalFeatureExtractor] = None

        # Core ML models (lazy loaded)
        self.if_model: Optional[IFDetector] = None
        self.lof_model: Optional[LOFDetector] = None
        self.ecod_model: Optional[ECODDetector] = None
        self.hst_model: Optional[HSTDetector] = None
        self.ae_model: Optional[AEDetector] = None
        self.ocsvm_model: Optional[OCSVMDetector] = None
        self.lstm_model: Optional[LSTMDetector] = None
        self.graph_model: Optional[GraphDetector] = None
        self.maml: Optional[MAMLDetector] = None
        self.transformer: Optional[TransformerDetector] = None
        self.contrastive: Optional[ContrastiveDetector] = None
        self.gnn: Optional[GNNFlowDetector] = None
        self.zero_day: Optional[ZeroDayDetector] = None

        # Aviation modules (v10)
        self.aviation_domain: Optional[AviationDomainModel] = None
        self.adsb_spoof: Optional[ADSBSpoofingDetector] = None
        self.flight_path: Optional[FlightPathDetector] = None
        self.blackbox: Optional[BlackBoxAnalyzer] = None
        self.forensic: Optional[ForensicAnalyzer] = None
        self.threat_intel: Optional[ThreatIntelFeed] = None

        # Services
        self.monitoring: Optional[ModelMonitoringDashboard] = None
        self.risk_engine = RiskScoringEngine()
        self.batch_predictor: Optional[BatchPredictor] = None
        self.registry = ModelVersionRegistry()
        self.multi_tenant = MultiTenantDetector()
        self.federated = FederatedLearner()
        self.healer = SelfHealingEngine()
        self.profiler = AttackerProfiler()
        self.digital_twin = NetworkDigitalTwin()

        # Norms
        self._norms: Dict[str, PercentileScoreNormalizer] = {}
        self._aviation_norm = PercentileScoreNormalizer()
        self._domain_norm = PercentileScoreNormalizer()
        self._maml_norm = PercentileScoreNormalizer()
        self._transformer_norm = PercentileScoreNormalizer()
        self._contrastive_norm = PercentileScoreNormalizer()

        # State
        self._n_train = 0
        self.feature_names: List[str] = []
        self.raw_feature_names: List[str] = []
        self._training_distribution: Optional[np.ndarray] = None
        self._warm_buffer: List[np.ndarray] = []
        self._adaptive_threshold: Optional[float] = None
        self._shap_explainer: Optional[Any] = None
        self._buffer: List[np.ndarray] = []

        # Drift detector
        self.drift_detector = None
        if self.config.drift_detection:
            try:
                from river import drift as river_drift
                self.drift_detector = river_drift.ADWIN(delta=self.config.adwin_delta)
            except ImportError:
                from app.utils.drift import SimpleADWINFallback
                self.drift_detector = SimpleADWINFallback()

        # Load existing models if they exist
        self._load_models()

    # ------------------------------------------------------------------------
    # Model persistence
    # ------------------------------------------------------------------------
    def _load_models(self) -> None:
        """Load models from disk if they exist."""
        if self.config.model_path.exists() and self.config.scaler_path.exists():
            try:
                state = joblib.load(self.config.model_path)
                for key in [
                    "if_model", "lof_model", "ecod_model", "hst_model",
                    "ae_model", "ocsvm_model", "lstm_model", "graph_model",
                    "maml", "transformer", "contrastive", "gnn", "zero_day",
                    "_norms", "_domain_norm", "_maml_norm", "_transformer_norm",
                    "_contrastive_norm", "feature_names", "raw_feature_names",
                    "_adaptive_threshold", "_training_distribution", "temporal",
                    "_n_train", "aviation_domain", "adsb_spoof", "flight_path",
                ]:
                    if key in state:
                        setattr(self, key, state[key])
                self.scaler, self.imputer = joblib.load(self.config.scaler_path)
                self._warm_buffer = state.get("warm_buffer", [])
                logger.info(f"✅ Loaded v10 models — {self._n_train} samples")
            except Exception as e:
                logger.error(f"Failed to load models: {e}")

    def _save_models(self) -> None:
        """Save all models to disk."""
        self.config.model_path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "if_model": self.if_model,
            "lof_model": self.lof_model,
            "ecod_model": self.ecod_model,
            "hst_model": self.hst_model,
            "ae_model": self.ae_model,
            "ocsvm_model": self.ocsvm_model,
            "lstm_model": self.lstm_model,
            "graph_model": self.graph_model,
            "maml": self.maml,
            "transformer": self.transformer,
            "contrastive": self.contrastive,
            "gnn": self.gnn,
            "zero_day": self.zero_day,
            "_norms": self._norms,
            "_domain_norm": self._domain_norm,
            "_maml_norm": self._maml_norm,
            "_transformer_norm": self._transformer_norm,
            "_contrastive_norm": self._contrastive_norm,
            "feature_names": self.feature_names,
            "raw_feature_names": self.raw_feature_names,
            "_adaptive_threshold": self._adaptive_threshold,
            "_training_distribution": self._training_distribution,
            "temporal": self.temporal,
            "_n_train": self._n_train,
            "warm_buffer": self._warm_buffer[-self.config.max_history_size:],
            "aviation_domain": self.aviation_domain,
            "adsb_spoof": self.adsb_spoof,
            "flight_path": self.flight_path,
        }
        joblib.dump(state, self.config.model_path)
        joblib.dump((self.scaler, self.imputer), self.config.scaler_path)
        logger.info("💾 Models saved")

    # ------------------------------------------------------------------------
    # Preprocessing
    # ------------------------------------------------------------------------
    def _preprocess(self, X: np.ndarray, fit: bool = False) -> np.ndarray:
        """Preprocess input features."""
        if self.config.handle_missing:
            if fit:
                self.imputer = SimpleImputer(strategy="median")
                X = self.imputer.fit_transform(X)
            else:
                X = self.imputer.transform(X) if self.imputer else np.nan_to_num(X)

        if self.config.use_temporal and self.temporal is not None:
            if fit:
                self.temporal.fit(X, self.raw_feature_names)
            X = self.temporal.transform_batch(X)

        if fit:
            self.scaler = get_scaler(self.config.scaler_type)
            X = self.scaler.fit_transform(X)
        else:
            X = self.scaler.transform(X)

        return X

    # ------------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------------
    def train(
        self,
        X: np.ndarray,
        y: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
        packets: Optional[List[Dict]] = None,
    ) -> "AnomalyDetector":
        """Train all models on the provided data."""
        with self._lock:
            n, d = X.shape
            if n < 30:
                logger.warning(f"Too few samples ({n}). Training aborted.")
                return self

            self.raw_feature_names = feature_names or [f"sensor_{i}" for i in range(d)]

            # Warm start: append to existing buffer
            if self.config.warm_start and self._warm_buffer:
                X = np.vstack([np.array(self._warm_buffer[-self.config.max_history_size:]), X])
                n = X.shape[0]

            # Temporal feature extraction
            if self.config.use_temporal:
                self.temporal = TemporalFeatureExtractor(
                    self.config.temporal_window,
                    self.config.temporal_lags,
                    self.config.use_fft,
                    self.config.use_context,
                )
            Xp = self._preprocess(X, fit=True)
            self.feature_names = (
                self.temporal.output_names if self.temporal
                else [f"feat_{i}" for i in range(Xp.shape[1])]
            )
            self._training_distribution = Xp.copy()
            self._n_train = n

            # Augment anomalies if needed
            Xa, ya = Xp, y
            if self.config.augment_anomalies and n >= 50:
                n_synth = max(10, int(n * self.config.augment_ratio))
                X_synth = synthesize_anomalies(Xp, n_synth, self.config.augment_strategy, self.config.random_state)
                Xa = np.vstack([Xp, X_synth])
                if y is not None:
                    ya = np.concatenate([y, np.ones(n_synth)])

            # ----- Train individual models -----
            # Isolation Forest
            self.if_model = IFDetector(
                n_estimators=self.config.n_estimators,
                contamination=self.config.contamination,
                max_samples=self.config.max_samples,
                random_state=self.config.random_state,
            )
            self.if_model.fit(Xa)
            self._norms["if"] = PercentileScoreNormalizer().fit(-self.if_model.score_samples(Xp))
            logger.info("✅ IsolationForest trained")

            # LOF
            if self.config.use_lof:
                self.lof_model = LOFDetector(
                    n_neighbors=self.config.lof_n_neighbors,
                    contamination=self.config.contamination,
                )
                self.lof_model.fit(Xa)
                self._norms["lof"] = PercentileScoreNormalizer().fit(-self.lof_model.score_samples(Xp))
                logger.info("✅ LOF trained")

            # ECOD
            if self.config.use_ecod:
                self.ecod_model = ECODDetector(contamination=self.config.contamination)
                self.ecod_model.fit(Xa)
                self._norms["ecod"] = PercentileScoreNormalizer().fit(self.ecod_model.decision_function(Xp))
                logger.info("✅ ECOD trained")

            # HalfSpaceTrees
            if self.config.use_hst:
                self.hst_model = HSTDetector(random_state=self.config.random_state)
                self.hst_model.fit(Xp)
                self._norms["hst"] = PercentileScoreNormalizer().fit(self.hst_model.score_samples(Xp))
                logger.info("✅ HST trained")

            # Autoencoder
            if self.config.use_autoencoder:
                self.ae_model = AEDetector(
                    bottleneck=self.config.ae_bottleneck,
                    hidden=self.config.ae_hidden,
                    epochs=self.config.ae_epochs,
                )
                self.ae_model.fit(Xp)
                self._norms["ae"] = PercentileScoreNormalizer().fit(-self.ae_model.score_samples(Xp))
                logger.info("✅ Autoencoder trained")

            # One‑Class SVM
            if self.config.use_ocsvm:
                self.ocsvm_model = OCSVMDetector(nu=self.config.ocsvm_nu)
                self.ocsvm_model.fit(Xa)
                self._norms["ocsvm"] = PercentileScoreNormalizer().fit(-self.ocsvm_model.score_samples(Xp))
                logger.info("✅ OCSVM trained")

            # LSTM
            if self.config.use_lstm:
                self.lstm_model = LSTMDetector(
                    seq_len=self.config.lstm_seq_len,
                    hidden=self.config.lstm_hidden,
                    num_layers=self.config.lstm_layers,
                    epochs=self.config.lstm_epochs,
                )
                self.lstm_model.fit(Xp)
                self._norms["lstm"] = PercentileScoreNormalizer().fit(-self.lstm_model.score_samples(Xp))
                logger.info("✅ LSTM trained")

            # Graph anomaly (NetworkX)
            if self.config.use_graph and packets:
                self.graph_model = GraphDetector(contamination=self.config.contamination)
                self.graph_model.fit(packets)
                logger.info("✅ Graph trained")

            # GNN (FlowGraph)
            if self.config.use_gnn and packets:
                self.gnn = GNNFlowDetector(hidden=self.config.gnn_hidden)
                self.gnn.fit(packets)
                logger.info("✅ GNN trained")

            # Transformer
            if self.config.use_transformer:
                self.transformer = TransformerDetector(
                    seq_len=self.config.transformer_seq_len,
                    epochs=self.config.transformer_epochs,
                )
                self.transformer.fit(Xp)
                ts_scores = -self.transformer.score_samples(Xp)
                self._norms["transformer"] = PercentileScoreNormalizer().fit(ts_scores)
                logger.info("✅ Transformer trained")

            # Contrastive learner
            if self.config.use_contrastive:
                self.contrastive = ContrastiveDetector(
                    embed_dim=self.config.contrastive_embed_dim,
                    epochs=self.config.contrastive_epochs,
                )
                self.contrastive.fit(Xp)
                cs = self.contrastive.score_samples(Xp)
                self._norms["contrastive"] = PercentileScoreNormalizer().fit(cs)
                logger.info("✅ Contrastive trained")

            # Zero‑day detector
            if self.config.use_zero_day_detector:
                self.zero_day = ZeroDayDetector()
                self.zero_day.fit(Xp)
                logger.info("✅ Zero‑Day trained")

            # Aviation modules (train on ADS‑B data)
            if self.config.use_aviation_domain and packets:
                self.aviation_domain = AviationDomainModel()
                # No training needed, rule-based
            if self.config.use_adsb_spoofing and packets:
                adsb_packets = [p for p in packets if p.get("protocol") == "adsb"]
                if adsb_packets:
                    self.adsb_spoof = ADSBSpoofingDetector()
                    self.adsb_spoof.fit(adsb_packets)
                    logger.info("✅ ADS‑B spoofing detector trained")

            # Flight path detector (if we have sequential trajectories)
            if self.config.use_flight_path and Xp.shape[0] >= self.config.transformer_seq_len:
                self.flight_path = FlightPathDetector()
                self.flight_path.fit(Xp)
                logger.info("✅ Flight path detector trained")

            # Initialize other components
            self._domain_norm = PercentileScoreNormalizer().fit(np.linspace(0, 1, 100))
            self._maml_norm = PercentileScoreNormalizer().fit(np.linspace(0, 1, 100))

            # Compute ensemble scores and threshold
            domain_scores = np.zeros(len(Xp))
            sm = self._score_all(Xp, domain_scores)
            weights = np.array(self.config.fallback_weights[:sm.shape[1]])
            weights /= weights.sum()
            ef = sm @ weights
            self._adaptive_threshold = float(np.percentile(ef, self.config.adaptive_percentile))

            # Train stacking if labels available
            if self.config.use_stacking and ya is not None:
                stacking = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000)
                stacking.fit(sm[:len(ya)], ya.astype(int))
                # Store in service? We'll keep it as a simple attribute.
                self._stacking = stacking

            # Conformal calibration
            if self.config.use_conformal:
                self._conformal_calibrate(ef[ef < self._adaptive_threshold])

            # SHAP explainer
            if self.config.use_shap:
                self._init_shap(Xp)

            # Warm buffer update
            if self.config.warm_start:
                self._warm_buffer.extend(X.tolist())
                if len(self._warm_buffer) > self.config.max_history_size:
                    self._warm_buffer = self._warm_buffer[-self.config.max_history_size:]

            # Monitoring
            self.monitoring = ModelMonitoringDashboard(self)
            self.batch_predictor = BatchPredictor(self, n_workers=self.config.n_workers)

            self._save_models()
            logger.info(f"🎯 Training complete: {n} samples, {Xp.shape[1]} features, {sm.shape[1]} models")
            return self

    def _score_all(
        self,
        X: np.ndarray,
        domain_scores: Optional[np.ndarray] = None,
        maml_scores: Optional[np.ndarray] = None,
        gnn_scores: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        """Collect scores from all active models."""
        cols = []

        # IF
        cols.append(self._norms["if"].transform(-self.if_model.score_samples(X)))

        # LOF
        if self.lof_model:
            cols.append(self._norms["lof"].transform(-self.lof_model.score_samples(X)))

        # ECOD
        if self.ecod_model:
            cols.append(self._norms["ecod"].transform(self.ecod_model.decision_function(X)))

        # HST
        if self.hst_model:
            raw = self.hst_model.score_samples(X)
            mn, mx = raw.min(), raw.max()
            cols.append((raw - mn) / (mx - mn + 1e-9))

        # AE
        if self.ae_model:
            cols.append(self._norms["ae"].transform(-self.ae_model.score_samples(X)))

        # OCSVM
        if self.ocsvm_model:
            cols.append(self._norms["ocsvm"].transform(-self.ocsvm_model.score_samples(X)))

        # LSTM
        if self.lstm_model:
            cols.append(self._norms["lstm"].transform(-self.lstm_model.score_samples(X)))

        # Graph (if packets available, not used here – would need separate handling)
        # We'll skip graph scores for now as they require packets.

        # MAML
        if maml_scores is not None:
            cols.append(self._maml_norm.transform(maml_scores))

        # Transformer
        if self.transformer:
            ts = -self.transformer.score_samples(X)
            cols.append(self._norms["transformer"].transform(ts))

        # Contrastive
        if self.contrastive:
            cs = self.contrastive.score_samples(X)
            cols.append(self._norms["contrastive"].transform(cs))

        # GNN (requires packets mapping, simplified)
        if gnn_scores is not None:
            cols.append(gnn_scores)

        # Domain (aviation) scores
        if domain_scores is not None:
            cols.append(self._domain_norm.transform(domain_scores))

        return np.column_stack(cols) if len(cols) > 1 else cols[0].reshape(-1, 1)

    def _conformal_calibrate(self, scores: np.ndarray) -> None:
        """Calibrate conformal predictor."""
        self._conformal_scores = np.sort(scores)[::-1]

    def _conformal_p_value(self, score: float) -> float:
        """Compute conformal p‑value."""
        if not hasattr(self, "_conformal_scores") or self._conformal_scores is None:
            return 0.5
        return np.searchsorted(-self._conformal_scores, -score, side="right") / len(self._conformal_scores)

    def _init_shap(self, Xp: np.ndarray) -> None:
        """Initialize SHAP explainer."""
        try:
            self._shap_explainer = shap.TreeExplainer(
                self.if_model._model, data=Xp[:self.config.shap_background_samples]
            )
        except Exception:
            try:
                self._shap_explainer = shap.KernelExplainer(
                    lambda x: self.if_model.score_samples(x), shap.sample(Xp, 50)
                )
            except Exception:
                self._shap_explainer = None

    # ------------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------------
    def predict(
        self,
        X: np.ndarray,
        packets: Optional[List[Dict]] = None,
        return_p_values: bool = False,
    ) -> Union[Tuple[np.ndarray, np.ndarray], Tuple[np.ndarray, np.ndarray, np.ndarray]]:
        """Predict anomalies for input samples."""
        with self._lock:
            self._assert_trained()
            t0 = time.perf_counter()
            if X.ndim == 1:
                X = X.reshape(1, -1)

            Xp = self._preprocess(X, fit=False)

            # Domain scores (aviation)
            domain_scores = np.zeros(len(Xp))
            if packets and len(packets) >= len(Xp):
                for i, pkt in enumerate(packets[:len(Xp)]):
                    if self.aviation_domain:
                        s, _ = self.aviation_domain.score_packet(pkt)
                        domain_scores[i] = s
                    if self.adsb_spoof:
                        s, _ = self.adsb_spoof.score(pkt)
                        domain_scores[i] = max(domain_scores[i], s)

            # MAML scores (if support provided)
            # Not used in simple predict; for now skip.

            # GNN scores (map IP to scores)
            gnn_scores = None
            if self.gnn and packets:
                ip_scores = self.gnn.score_packets(packets)
                gnn_scores = np.array([
                    ip_scores.get(p.get("src_ip", ""), 0.5) for p in packets[:len(Xp)]
                ] + [0.5] * max(0, len(Xp) - len(packets)))
                mn, mx = gnn_scores.min(), gnn_scores.max()
                if mx > mn:
                    gnn_scores = (gnn_scores - mn) / (mx - mn + 1e-8)

            # Score matrix
            sm = self._score_all(Xp, domain_scores, gnn_scores=gnn_scores)

            # Ensemble
            if hasattr(self, "_stacking"):
                ens = self._stacking.predict_proba(sm)[:, 1]
            else:
                weights = np.array(self.config.fallback_weights[:sm.shape[1]])
                weights /= weights.sum()
                ens = sm @ weights

            # Conformal adjustment
            p_vals = np.array([self._conformal_p_value(s) for s in ens])
            is_anomaly = (ens > self._adaptive_threshold) | (p_vals < self.config.conformal_alpha)

            # Drift detection
            if self.drift_detector:
                for s in ens:
                    self.drift_detector.update(s)

            # Log metrics
            latency_ms = (time.perf_counter() - t0) * 1000
            if self.monitoring:
                for s in ens:
                    self.monitoring.log_prediction(s, latency_ms / len(ens))

            ml_score_histogram.observe(ens.mean())  # simplified

            return (is_anomaly, ens, p_vals) if return_p_values else (is_anomaly, ens)

    def predict_single(
        self,
        x: np.ndarray,
        timestamp: Optional[pd.Timestamp] = None,
        packet: Optional[Dict] = None,
        return_p_value: bool = False,
    ) -> Union[Tuple[bool, float], Tuple[bool, float, float]]:
        """Predict for a single sample."""
        with self._lock:
            self._assert_trained()
            t0 = time.perf_counter()

            if self.imputer:
                x = self.imputer.transform(x.reshape(1, -1))[0]
            else:
                x = np.nan_to_num(x)

            if self.config.use_temporal and self.temporal:
                x = self.temporal.transform_single(x, timestamp)

            xs = self.scaler.transform(x.reshape(1, -1))

            domain_score = 0.0
            if packet and self.aviation_domain:
                s, _ = self.aviation_domain.score_packet(packet)
                domain_score = s
                if self.adsb_spoof:
                    s, _ = self.adsb_spoof.score(packet)
                    domain_score = max(domain_score, s)

            sm = self._score_all(xs, np.array([domain_score]))
            if hasattr(self, "_stacking"):
                ens = float(self._stacking.predict_proba(sm)[0, 1])
            else:
                weights = np.array(self.config.fallback_weights[:sm.shape[1]])
                weights /= weights.sum()
                ens = float(sm @ weights)

            p_val = self._conformal_p_value(ens)
            is_anomaly = (ens > self._adaptive_threshold) or (p_val < self.config.conformal_alpha)

            latency_ms = (time.perf_counter() - t0) * 1000
            if self.monitoring:
                self.monitoring.log_prediction(ens, latency_ms)

            if return_p_value:
                return is_anomaly, ens, p_val
            return is_anomaly, ens

    def _assert_trained(self) -> None:
        if self.if_model is None or self.scaler is None:
            raise RuntimeError("Model not trained. Call train() first.")

    # ------------------------------------------------------------------------
    # Aviation‑specific public methods
    # ------------------------------------------------------------------------
    def analyze_flight_path(self, seq: np.ndarray) -> Dict[str, Any]:
        """Return flight path anomaly score."""
        if self.flight_path:
            score = self.flight_path.score(seq)
            hijack_score, alerts = self.flight_path.detect_hijacking_pattern(seq)
            return {"score": score, "hijack_score": hijack_score, "alerts": alerts}
        return {"score": 0.0, "hijack_score": 0.0, "alerts": []}

    def forensic_report(self, start: datetime, end: datetime) -> Dict[str, Any]:
        """Generate forensic report."""
        if self.forensic:
            return self.forensic.generate_report(start, end)
        return {}

    def record_forensic_event(self, event: Dict) -> None:
        """Record an event for forensic analysis."""
        if self.forensic:
            self.forensic.record_event(event)

    def check_threat_intel(self, icao24: Optional[str] = None, ip: Optional[str] = None) -> Dict[str, Any]:
        """Check threat intelligence for an aircraft or IP."""
        result = {}
        if icao24 and self.threat_intel:
            is_mal, score = self.threat_intel.check_aircraft(icao24)
            result["icao24"] = {"is_malicious": is_mal, "score": score}
        if ip and self.threat_intel:
            is_mal, score = self.threat_intel.check_ip(ip)
            result["ip"] = {"is_malicious": is_mal, "score": score}
        return result

    # ------------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        """Return model summary."""
        return {
            "version": "10.0.0",
            "trained": self.if_model is not None,
            "n_train": self._n_train,
            "n_features_raw": len(self.raw_feature_names),
            "n_features_processed": len(self.feature_names),
            "adaptive_threshold": self._adaptive_threshold,
            "gpu_available": _gpu.has_cuda,
            "models_active": {
                "IsolationForest": self.if_model is not None,
                "LOF": self.lof_model is not None,
                "ECOD": self.ecod_model is not None,
                "HalfSpaceTrees": self.hst_model is not None,
                "Autoencoder": self.ae_model is not None,
                "OneClassSVM": self.ocsvm_model is not None,
                "LSTM": self.lstm_model is not None,
                "GraphAnomaly": self.graph_model is not None,
                "MAML": self.maml is not None,
                "Transformer": self.transformer is not None,
                "Contrastive": self.contrastive is not None,
                "GNN": self.gnn is not None,
                "ZeroDay": self.zero_day is not None,
                "AviationDomain": self.aviation_domain is not None,
                "ADSBSpoofing": self.adsb_spoof is not None,
                "FlightPath": self.flight_path is not None,
            },
        }
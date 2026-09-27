"""Response Autoencoder — learns normal response patterns to detect WAF blocks.

Instead of hardcoded WAF keywords and Jaccard similarity thresholds,
this autoencoder LEARNS what a "normal" response looks like from
multiple baseline samples, then uses reconstruction error to classify:
- Low reconstruction error → response matches learned pattern → BYPASS
- High reconstruction error → response is anomalous → likely WAF block

Architecture:
    Encoder: input_dim → 64 → 32 → 16 (bottleneck)
    Decoder: 16 → 32 → 64 → input_dim
    Regularization: L2 weight decay + dropout + early stopping

Training: Online learning from scan responses (no pre-training needed)
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field

import numpy as np

import structlog

logger = structlog.get_logger()

FEATURE_DIM = 30  # Response feature vector dimension


@dataclass
class ResponseAutoencoder:
    """Lightweight autoencoder for response classification.

    Uses numpy-only implementation (no PyTorch dependency) for
    fast online learning during scan.
    """

    # Architecture
    input_dim: int = FEATURE_DIM
    hidden1: int = 64
    hidden2: int = 32
    bottleneck: int = 16

    # Hyperparameters (tuned)
    learning_rate: float = 0.001
    weight_decay: float = 0.0001  # L2 regularization
    dropout_rate: float = 0.15

    # Learned weights (initialized lazily)
    _weights: dict = field(default_factory=dict)
    _is_trained: bool = False
    _training_errors: list[float] = field(default_factory=list)
    _threshold: float = 0.0
    _mean: np.ndarray | None = None
    _std: np.ndarray | None = None

    def _init_weights(self) -> None:
        """Xavier initialization for stable training."""
        # Persist the RNG on the instance so dropout masks and per-epoch
        # shuffles are also seeded — without this, every retrain produced a
        # different threshold even on identical input, undermining
        # reproducibility and downstream classifier consistency.
        self._rng = np.random.RandomState(42)
        rng = self._rng
        def xavier(fan_in, fan_out):
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            return rng.uniform(-limit, limit, (fan_in, fan_out)).astype(np.float64)

        # Encoder
        self._weights['W1'] = xavier(self.input_dim, self.hidden1)
        self._weights['b1'] = np.zeros(self.hidden1)
        self._weights['W2'] = xavier(self.hidden1, self.hidden2)
        self._weights['b2'] = np.zeros(self.hidden2)
        self._weights['W3'] = xavier(self.hidden2, self.bottleneck)
        self._weights['b3'] = np.zeros(self.bottleneck)
        # Decoder
        self._weights['W4'] = xavier(self.bottleneck, self.hidden2)
        self._weights['b4'] = np.zeros(self.hidden2)
        self._weights['W5'] = xavier(self.hidden2, self.hidden1)
        self._weights['b5'] = np.zeros(self.hidden1)
        self._weights['W6'] = xavier(self.hidden1, self.input_dim)
        self._weights['b6'] = np.zeros(self.input_dim)

    def _relu(self, x: np.ndarray) -> np.ndarray:
        return np.maximum(0, x)

    def _relu_grad(self, x: np.ndarray) -> np.ndarray:
        return (x > 0).astype(np.float64)

    def _forward(self, x: np.ndarray, training: bool = False) -> tuple:
        """Forward pass through encoder→decoder."""
        # Encoder
        z1 = x @ self._weights['W1'] + self._weights['b1']
        a1 = self._relu(z1)
        if training and 0 < self.dropout_rate < 1.0:
            rng = getattr(self, "_rng", None) or np.random
            mask1 = (rng.random(a1.shape) > self.dropout_rate).astype(np.float64)
            a1 = a1 * mask1 / (1 - self.dropout_rate)
        else:
            mask1 = None

        z2 = a1 @ self._weights['W2'] + self._weights['b2']
        a2 = self._relu(z2)

        z3 = a2 @ self._weights['W3'] + self._weights['b3']
        bottleneck = self._relu(z3)

        # Decoder
        z4 = bottleneck @ self._weights['W4'] + self._weights['b4']
        a4 = self._relu(z4)

        z5 = a4 @ self._weights['W5'] + self._weights['b5']
        a5 = self._relu(z5)

        z6 = a5 @ self._weights['W6'] + self._weights['b6']
        output = z6  # Linear output

        cache = (x, z1, a1, mask1, z2, a2, z3, bottleneck, z4, a4, z5, a5, z6)
        return output, cache

    def _backward(self, cache: tuple, output: np.ndarray) -> None:
        """Backpropagation with L2 regularization."""
        x, z1, a1, mask1, z2, a2, z3, bottleneck, z4, a4, z5, a5, z6 = cache
        batch_size = max(x.shape[0], 1)

        # Output error
        d6 = (output - x) / batch_size  # MSE gradient

        # Decoder gradients
        dW6 = a5.T @ d6 + self.weight_decay * self._weights['W6']
        db6 = d6.sum(axis=0)

        d5 = (d6 @ self._weights['W6'].T) * self._relu_grad(z5)
        dW5 = a4.T @ d5 + self.weight_decay * self._weights['W5']
        db5 = d5.sum(axis=0)

        d4 = (d5 @ self._weights['W5'].T) * self._relu_grad(z4)
        dW4 = bottleneck.T @ d4 + self.weight_decay * self._weights['W4']
        db4 = d4.sum(axis=0)

        # Encoder gradients
        d3 = (d4 @ self._weights['W4'].T) * self._relu_grad(z3)
        dW3 = a2.T @ d3 + self.weight_decay * self._weights['W3']
        db3 = d3.sum(axis=0)

        d2 = (d3 @ self._weights['W3'].T) * self._relu_grad(z2)
        dW2 = a1.T @ d2 + self.weight_decay * self._weights['W2']
        db2 = d2.sum(axis=0)

        d1 = (d2 @ self._weights['W2'].T) * self._relu_grad(z1)
        if mask1 is not None:
            d1 = d1 * mask1
        dW1 = x.T @ d1 + self.weight_decay * self._weights['W1']
        db1 = d1.sum(axis=0)

        # Gradient clipping
        for grad in [dW1, dW2, dW3, dW4, dW5, dW6]:
            np.clip(grad, -1.0, 1.0, out=grad)

        # Update weights
        lr = self.learning_rate
        self._weights['W1'] -= lr * dW1; self._weights['b1'] -= lr * db1
        self._weights['W2'] -= lr * dW2; self._weights['b2'] -= lr * db2
        self._weights['W3'] -= lr * dW3; self._weights['b3'] -= lr * db3
        self._weights['W4'] -= lr * dW4; self._weights['b4'] -= lr * db4
        self._weights['W5'] -= lr * dW5; self._weights['b5'] -= lr * db5
        self._weights['W6'] -= lr * dW6; self._weights['b6'] -= lr * db6

    def extract_response_features(self, status_code: int, body: bytes, baseline_body: bytes) -> np.ndarray:
        """Extract fixed-size feature vector from HTTP response."""
        f = np.zeros(FEATURE_DIM, dtype=np.float64)

        body_text = body[:5000].decode("utf-8", errors="replace").lower()
        baseline_text = baseline_body[:5000].decode("utf-8", errors="replace").lower() if baseline_body else ""
        n = max(len(body_text), 1)

        # [0-2] Status features
        f[0] = status_code / 600.0
        f[1] = 1.0 if status_code == 200 else 0.0
        f[2] = 1.0 if status_code in (403, 401, 429, 500, 502, 503) else 0.0

        # [3-5] Size features
        f[3] = min(len(body) / 50000.0, 1.0)
        f[4] = len(body) / max(len(baseline_body), 1) if baseline_body else 0.0
        f[4] = min(f[4], 5.0) / 5.0
        f[5] = 1.0 if abs(len(body) - len(baseline_body)) < 200 else 0.0 if baseline_body else 0.5

        # [6-8] Content type indicators
        f[6] = 1.0 if "<html" in body_text else 0.0
        f[7] = 1.0 if "json" in body_text[:100] or body_text.startswith("{") else 0.0
        f[8] = 1.0 if "xml" in body_text[:100] else 0.0

        # [9-14] WAF signature features (learned weights, not binary)
        waf_groups = [
            ["blocked", "denied", "forbidden", "rejected"],
            ["firewall", "waf", "security", "violation"],
            ["error 1020", "attention required", "ray id"],
            ["incapsula", "cloudflare", "modsecurity", "imperva"],
            ["captcha", "challenge", "robot", "verify"],
            ["rate limit", "too many", "throttl"],
        ]
        for i, group in enumerate(waf_groups):
            f[9 + i] = min(sum(1 for kw in group if kw in body_text) / max(len(group), 1), 1.0)

        # [15-17] Entropy and structure
        if body_text:
            freq: dict[str, int] = {}
            for c in body_text[:2000]:
                freq[c] = freq.get(c, 0) + 1
            probs = np.array(list(freq.values()), dtype=np.float64) / len(body_text[:2000])
            f[15] = float(-np.sum(probs * np.log2(probs + 1e-10))) / 8.0
        f[16] = body_text.count("<") / max(n, 1) * 10  # HTML tag density
        f[17] = len(set(body_text.split())) / max(len(body_text.split()), 1)  # Vocabulary richness

        # [18-22] Baseline similarity features
        if baseline_text:
            # Token overlap
            body_tokens = set(body_text.split())
            base_tokens = set(baseline_text.split())
            if body_tokens and base_tokens:
                f[18] = len(body_tokens & base_tokens) / max(len(body_tokens | base_tokens), 1)
                f[19] = len(body_tokens & base_tokens) / max(len(base_tokens), 1)

            # Title match
            import re
            body_title = re.search(r"<title>(.*?)</title>", body_text)
            base_title = re.search(r"<title>(.*?)</title>", baseline_text)
            if body_title and base_title:
                f[20] = 1.0 if body_title.group(1) == base_title.group(1) else 0.0

            # Body hash similarity (first 500 chars of structural content)
            body_struct = re.sub(r"[^<>/a-z]", "", body_text[:500])
            base_struct = re.sub(r"[^<>/a-z]", "", baseline_text[:500])
            if body_struct and base_struct:
                struct_tokens = set(body_struct[i:i+8] for i in range(max(1, len(body_struct)-7)))
                base_struct_tokens = set(base_struct[i:i+8] for i in range(max(1, len(base_struct)-7)))
                f[21] = len(struct_tokens & base_struct_tokens) / max(len(struct_tokens | base_struct_tokens), 1)

            f[22] = 1.0 if len(body) > 0 and abs(len(body) - len(baseline_body)) / max(len(baseline_body), 1) < 0.1 else 0.0

        # [23-29] Character composition
        if body_text:
            f[23] = sum(1 for c in body_text if c.isalpha()) / n
            f[24] = sum(1 for c in body_text if c.isdigit()) / n
            f[25] = sum(1 for c in body_text if c in "<>{}[]()") / n
            f[26] = sum(1 for c in body_text if c.isspace()) / n
            f[27] = len(body_text.split()) / max(n / 5, 1)  # Words per 5 chars
            f[28] = body_text.count("\n") / max(n, 1) * 100
            f[29] = 1.0 if len(body_text) < 500 else 0.0  # Short response flag

        return f

    def train_on_baselines(self, baseline_features: list[np.ndarray], epochs: int = 100) -> dict:
        """Train autoencoder on baseline (normal) response features.

        Args:
            baseline_features: List of feature vectors from normal responses.
            epochs: Training epochs (with early stopping).

        Returns:
            Training metrics.
        """
        if len(baseline_features) < 2:
            return {"status": "insufficient_data", "samples": len(baseline_features)}

        X = np.array(baseline_features)

        # Reinitialize weights + reset RNG FIRST so that augmentation noise,
        # weight init, dropout, and per-epoch shuffle all draw from the same
        # freshly-seeded RNG. Doing this before noise generation guarantees
        # reproducibility on every retrain — previously, augmentation noise
        # on a retrain used leftover RNG state from the prior training run.
        self._init_weights()  # creates fresh self._rng = RandomState(42)
        self._training_errors = []
        self._threshold = 0.0

        # Augment training data with small noise to improve generalization
        # This prevents overfitting on tiny datasets (e.g., 3-5 baseline samples)
        augmented = [X]
        for _ in range(4):  # 4x augmentation → 5x total samples
            noise = self._rng.normal(0, 0.02, X.shape)
            augmented.append(X + noise)
        X_aug = np.concatenate(augmented, axis=0)

        # Robust normalization: use larger epsilon to prevent explosion
        # when features have near-zero variance (common with similar baselines)
        self._mean = X_aug.mean(axis=0)
        raw_std = X_aug.std(axis=0)
        self._std = np.maximum(raw_std, 0.1)  # Floor at 0.1 — prevents extreme normalization
        X_norm = (X_aug - self._mean) / self._std

        # Clip normalized values to prevent extreme activations
        X_norm = np.clip(X_norm, -5.0, 5.0)

        # Training with early stopping
        best_loss = float('inf')
        best_weights = {}
        patience = 15
        patience_counter = 0

        for epoch in range(epochs):
            # Shuffle
            _rng = getattr(self, "_rng", None) or np.random
            idx = _rng.permutation(len(X_norm))
            X_shuffled = X_norm[idx]

            # Forward + backward
            output, cache = self._forward(X_shuffled, training=True)
            loss = float(np.mean((output - X_shuffled) ** 2))
            self._backward(cache, output)

            # Early stopping with weight checkpointing
            if loss < best_loss - 0.00001:
                best_loss = loss
                patience_counter = 0
                best_weights = {k: v.copy() for k, v in self._weights.items()}
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    break

        # Restore best weights
        if best_weights:
            self._weights = best_weights

        # Compute threshold on ORIGINAL (non-augmented) data
        X_orig_norm = (X - self._mean) / self._std
        X_orig_norm = np.clip(X_orig_norm, -5.0, 5.0)
        output_final, _ = self._forward(X_orig_norm, training=False)
        errors = np.mean((output_final - X_orig_norm) ** 2, axis=1)
        self._training_errors = errors.tolist()

        # Threshold: data-derived, not floored. The previous `* 10.0` multiplier
        # plus a hard floor of 1.0 made `ratio = score / threshold` almost
        # always << 1, so the classifier (line 376-391) collapsed to "bypass"
        # for nearly every response — defeating the autoencoder layer entirely.
        # Use 3x max-train-error as a safety buffer, OR mean + 3σ, whichever
        # is larger. No floor: a model with extremely tight reconstruction
        # SHOULD have a tight threshold.
        max_train_error = float(np.max(errors))
        mean_plus_std = float(np.mean(errors) + 3 * np.std(errors))
        self._threshold = max(max_train_error * 3.0, mean_plus_std)
        self._is_trained = True

        return {
            "status": "trained",
            "samples": len(X),
            "augmented_samples": len(X_aug),
            "epochs": epoch + 1,
            "final_loss": round(best_loss, 6),
            "threshold": round(self._threshold, 6),
            "mean_error": round(float(np.mean(errors)), 6),
            "max_train_error": round(max_train_error, 6),
            "std_error": round(float(np.std(errors)), 6),
        }

    def get_anomaly_score(self, features: np.ndarray) -> float:
        """Get reconstruction error for a single response.

        Returns:
            Anomaly score (higher = more anomalous = more likely WAF block).
        """
        if not self._is_trained or self._mean is None:
            return 0.0

        x = ((features - self._mean) / self._std).reshape(1, -1)
        x = np.clip(x, -5.0, 5.0)  # Match training normalization
        output, _ = self._forward(x, training=False)
        error = float(np.mean((output - x) ** 2))
        return error

    def classify(self, features: np.ndarray) -> tuple[str, float]:
        """Classify a response as normal (bypass) or anomalous (blocked).

        Returns:
            (label, confidence) where label is "bypass" or "blocked".
        """
        if not self._is_trained:
            return "unknown", 0.0

        score = self.get_anomaly_score(features)
        ratio = score / max(self._threshold, 1e-8)

        # Below threshold → bypass (normal response matches learned pattern)
        if ratio <= 0.3:
            return "bypass", 0.95  # Very close to training data
        elif ratio <= 0.7:
            return "bypass", 0.85
        elif ratio <= 1.0:
            return "bypass", 0.70  # Near boundary but still below threshold

        # Above threshold → blocked (anomalous response)
        elif ratio <= 2.0:
            conf = 0.60 + (ratio - 1.0) * 0.25  # 0.60 → 0.85
            return "blocked", min(conf, 0.85)
        elif ratio <= 5.0:
            conf = 0.85 + (ratio - 2.0) / 3.0 * 0.10  # 0.85 → 0.95
            return "blocked", min(conf, 0.95)
        else:
            return "blocked", 0.96  # Very anomalous

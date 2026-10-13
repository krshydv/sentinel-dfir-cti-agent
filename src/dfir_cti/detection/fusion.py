import numpy as np
from sklearn.linear_model import LogisticRegression


class ScoreFusion:
    def __init__(self, strategy="weighted", weights=None, threshold=0.5):
        self.strategy = strategy
        self.weights = weights or {"isolation_forest": 0.2, "xgboost": 0.5, "autoencoder": 0.3}
        self.threshold = threshold
        self.meta = None
        self.order = ["isolation_forest", "xgboost", "autoencoder"]

    def _stack(self, scores):
        return np.column_stack([scores[k] for k in self.order])

    def fit(self, scores, y):
        if self.strategy == "meta":
            self.meta = LogisticRegression(max_iter=1000, class_weight="balanced")
            self.meta.fit(self._stack(scores), y)
        return self

    def fuse(self, scores):
        if self.strategy == "meta" and self.meta is not None:
            return self.meta.predict_proba(self._stack(scores))[:, 1]
        total = sum(self.weights[k] for k in self.order)
        return sum(self.weights[k] * np.asarray(scores[k]) for k in self.order) / total

    def predict(self, scores):
        return (self.fuse(scores) >= self.threshold).astype(int)

    def tune_threshold(self, scores, y, grid=None):
        from sklearn.metrics import f1_score

        grid = grid if grid is not None else np.linspace(0.05, 0.95, 91)
        fused = self.fuse(scores)
        best_t, best_f = self.threshold, -1.0
        for t in grid:
            f = f1_score(y, (fused >= t).astype(int), zero_division=0)
            if f > best_f:
                best_t, best_f = float(t), f
        self.threshold = best_t
        return best_t, best_f

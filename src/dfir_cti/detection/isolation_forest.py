import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class IsolationForestDetector:
    def __init__(self, n_estimators=200, contamination="auto", random_state=42):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._lo = 0.0
        self._hi = 1.0

    def fit(self, X):
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        raw = -self.model.score_samples(Xs)
        self._lo, self._hi = float(np.percentile(raw, 1)), float(np.percentile(raw, 99))
        return self

    def score(self, X):
        Xs = self.scaler.transform(X)
        raw = -self.model.score_samples(Xs)
        span = max(self._hi - self._lo, 1e-9)
        return np.clip((raw - self._lo) / span, 0.0, 1.0)

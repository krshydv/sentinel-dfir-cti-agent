import numpy as np
from xgboost import XGBClassifier


class XGBAttackClassifier:
    def __init__(self, n_estimators=300, max_depth=6, learning_rate=0.1, random_state=42):
        self.model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=random_state,
            eval_metric="logloss",
            n_jobs=-1,
        )

    def fit(self, X, y):
        pos = max(int(np.sum(y == 1)), 1)
        neg = max(int(np.sum(y == 0)), 1)
        self.model.set_params(scale_pos_weight=neg / pos)
        self.model.fit(X, y)
        return self

    def score(self, X):
        return self.model.predict_proba(X)[:, 1]

    def feature_importance(self, names):
        return dict(sorted(zip(names, self.model.feature_importances_), key=lambda kv: -kv[1]))

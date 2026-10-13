import numpy as np
import torch
from sklearn.preprocessing import StandardScaler
from torch import nn


class _AE(nn.Module):
    def __init__(self, in_dim, hidden_dims):
        super().__init__()
        enc, prev = [], in_dim
        for h in hidden_dims:
            enc += [nn.Linear(prev, h), nn.ReLU()]
            prev = h
        dec = []
        for h in reversed(hidden_dims[:-1]):
            dec += [nn.Linear(prev, h), nn.ReLU()]
            prev = h
        dec.append(nn.Linear(prev, in_dim))
        self.encoder = nn.Sequential(*enc)
        self.decoder = nn.Sequential(*dec)

    def forward(self, x):
        return self.decoder(self.encoder(x))


class AutoencoderDetector:
    def __init__(self, hidden_dims=(64, 32, 16), epochs=30, batch_size=256, learning_rate=1e-3, random_state=42):
        self.hidden_dims = list(hidden_dims)
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.net = None
        self._lo = 0.0
        self._hi = 1.0
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

    def fit(self, X_normal):
        torch.manual_seed(self.random_state)
        Xs = np.clip(self.scaler.fit_transform(X_normal), -10, 10).astype(np.float32)
        self.net = _AE(Xs.shape[1], self.hidden_dims).to(self.device)
        opt = torch.optim.Adam(self.net.parameters(), lr=self.learning_rate)
        loss_fn = nn.MSELoss()
        data = torch.from_numpy(Xs)
        n = len(data)
        for _ in range(self.epochs):
            perm = torch.randperm(n)
            for i in range(0, n, self.batch_size):
                batch = data[perm[i : i + self.batch_size]].to(self.device)
                opt.zero_grad()
                loss = loss_fn(self.net(batch), batch)
                loss.backward()
                opt.step()
        err = self._errors(Xs)
        self._lo, self._hi = float(np.percentile(err, 50)), float(np.percentile(err, 99.5))
        return self

    def _errors(self, Xs):
        self.net.eval()
        out = []
        with torch.no_grad():
            for i in range(0, len(Xs), 4096):
                b = torch.from_numpy(Xs[i : i + 4096]).to(self.device)
                out.append(((self.net(b) - b) ** 2).mean(dim=1).cpu().numpy())
        return np.concatenate(out)

    def reconstruction_error(self, X):
        Xs = np.clip(self.scaler.transform(X), -10, 10).astype(np.float32)
        return self._errors(Xs)

    def score(self, X):
        err = self.reconstruction_error(X)
        span = max(self._hi - self._lo, 1e-9)
        return np.clip((err - self._lo) / span, 0.0, 1.0)

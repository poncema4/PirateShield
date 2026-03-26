"""

PirateShield - Neural Network Validator
=========================================
Trains a PyTorch Autoencoder on your synthetic network events,
then cross-validates its anomaly scores against the existing
3-layer hybrid model (SARIMA + DBSCAN + PCA)

"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, classification_report

SCRIPT_DIR = Path(__file__).resolve().parent
def find_data_dir():
    candidate = SCRIPT_DIR
    for _ in range(6):
        if (candidate / "data").exists():
            return candidate / "data"
        candidate = candidate.parent
    return SCRIPT_DIR / "data"

DATA_DIR    = find_data_dir()
DATA_FILE   = DATA_DIR / "synthetic_events" / "synthetic_network_events.json"
HYBRID_FILE = DATA_DIR / "risk_scores" / "network" / "network_risk_scores.json"
NN_OUTPUT   = DATA_DIR / "risk_scores" / "network" / "neural_network_risk_scores.json"

MODEL_DIR = SCRIPT_DIR
if str(MODEL_DIR) not in sys.path:
    sys.path.insert(0, str(MODEL_DIR))

try:
    from network_anomaly_model import (
        events_to_dataframe, compute_risk_scores, FEATURE_COLS
    )
    HYBRID_AVAILABLE = True
except ImportError:
    print("[WARN] network_anomaly_model not found - hybrid scores will be loaded from JSON only")
    HYBRID_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    print("[ERROR] PyTorch not installed. Run:")
    print("  pip install torch --break-system-packages")
    sys.exit(1)

class Autoencoder(nn.Module):
    """
    Simple fully-connected autoencoder
    Architecture: 9 → 16 → 8 → 4 → 8 → 16 → 9
    Uses ReLU activations in hidden layers, sigmoid on the output
    (features are StandardScaler-normalised but we still benefit from
    the bounded reconstruction for stability)
    """
    def __init__(self, input_dim: int = 9):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

def train_autoencoder(
    X_train: np.ndarray,
    epochs: int = 400,
    lr: float = 1e-3,
    batch_size: int = 8,
) -> tuple[Autoencoder, list[float]]:
    """Train on the provided feature matrix and return (model, loss_history)"""
    model = Autoencoder(input_dim=X_train.shape[1])
    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    tensor = torch.tensor(X_train, dtype=torch.float32)
    losses = []

    model.train()
    for epoch in range(epochs):
        perm = torch.randperm(len(tensor))
        epoch_loss = 0.0
        for i in range(0, len(tensor), batch_size):
            batch = tensor[perm[i : i + batch_size]]
            optimizer.zero_grad()
            out = model(batch)
            loss = criterion(out, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * len(batch)
        losses.append(epoch_loss / len(tensor))

    return model, losses

def reconstruction_scores(model: Autoencoder, X: np.ndarray) -> np.ndarray:
    """Per-sample MSE reconstruction error, normalised to [0, 1]"""
    model.eval()
    with torch.no_grad():
        tensor = torch.tensor(X, dtype=torch.float32)
        recon = model(tensor).numpy()
    errors = np.mean((X - recon) ** 2, axis=1)
    max_err = errors.max() if errors.max() > 0 else 1.0
    return np.clip(errors / max_err, 0, 1)

def main():
    print("=" * 62)
    print("PirateShield - Neural Network Validator")
    print("=" * 62)

    if not DATA_FILE.exists():
        print(f"[ERROR] Data file not found: {DATA_FILE}")
        print("Make sure DATA_FILE points to your synthetic_network_events.json")
        sys.exit(1)

    with open(DATA_FILE) as f:
        events = json.load(f)
    print(f"\nLoaded {len(events)} events from {DATA_FILE.name}")

    if HYBRID_AVAILABLE:
        df = events_to_dataframe(events)
        df = compute_risk_scores(df)
        hybrid_scores = df["risk_score"].values
        hybrid_labels = df["risk_label"].values
    else:
        if not HYBRID_FILE.exists():
            print(f"[ERROR] Hybrid scores file not found: {HYBRID_FILE}")
            sys.exit(1)
        with open(HYBRID_FILE) as f:
            saved = json.load(f)
        hybrid_scores = np.array([r["risk_score"] for r in saved])
        hybrid_labels = np.array([r["risk_label"] for r in saved])

        import importlib
        try:
            mod = importlib.import_module("network_anomaly_model")
            df = mod.events_to_dataframe(events)
        except Exception:
            print("[ERROR] Cannot import network_anomaly_model for features")
            sys.exit(1)

    features = df[FEATURE_COLS].values.astype(float)
    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    print("\nTraining autoencoder …", end=" ", flush=True)
    model, loss_history = train_autoencoder(X, epochs=500, lr=5e-4, batch_size=4)
    final_loss = loss_history[-1]
    print(f"done  (final MSE loss: {final_loss:.6f})")

    nn_scores = reconstruction_scores(model, X)

    label_order = {"Normal": 0, "Suspicious": 1, "High Risk": 2, "Critical": 3}

    def classify(score: float) -> str:
        if score <= 0.30: return "Normal"
        if score <= 0.55: return "Suspicious"
        if score <= 0.75: return "High Risk"
        return "Critical"

    nn_labels = np.array([classify(s) for s in nn_scores])

    print(f"\n{'Event Type':<22} {'Hybrid':>7} {'NN':>7} {'Hybrid Label':<13} {'NN Label':<13} {'Agree'}")
    print("─" * 78)

    agree_count = 0
    for i, row in df.iterrows():
        h_score = hybrid_scores[i]
        n_score = nn_scores[i]
        h_label = hybrid_labels[i]
        n_label = nn_labels[i]
        h_tier = label_order.get(h_label, 0)
        n_tier = label_order.get(n_label, 0)
        agree = abs(h_tier - n_tier) <= 1
        if agree:
            agree_count += 1
        marker = "✓" if agree else "✗"
        print(f"{row['event_type']:<22} {h_score:>7.4f} {n_score:>7.4f} "
              f"{h_label:<13} {n_label:<13} {marker}")

    pct = agree_count / len(df) * 100
    print(f"\nAgreement (within 1 tier): {agree_count}/{len(df)} = {pct:.1f}%")

    correlation = np.corrcoef(hybrid_scores, nn_scores)[0, 1]
    print(f"Pearson correlation (hybrid vs NN): {correlation:.4f}")

    if correlation >= 0.7:
        print("  → Strong agreement — NN validates your hybrid model ✓")
    elif correlation >= 0.4:
        print("  → Moderate agreement — NN partially validates hybrid model")
    else:
        print("  → Low agreement — consider retraining on more labelled data")

    y_true = np.array([1 if l in ("High Risk", "Critical") else 0 for l in hybrid_labels])
    if y_true.sum() > 0 and y_true.sum() < len(y_true):
        auc = roc_auc_score(y_true, nn_scores)
        print(f"AUC-ROC (NN scores vs hybrid labels): {auc:.4f}")
        if auc >= 0.75:
            print("  → NN can independently detect High/Critical events ✓")

    output = []
    for i, row in df.iterrows():
        output.append({
            "event_id":     row["event_id"],
            "event_type":   row["event_type"],
            "source_ip":    row.get("source_ip"),
            "nn_score":     float(round(nn_scores[i], 4)),
            "nn_label":     nn_labels[i],
            "hybrid_score": float(round(hybrid_scores[i], 4)),
            "hybrid_label": hybrid_labels[i],
            "agree":        abs(label_order.get(nn_labels[i], 0) -
                               label_order.get(hybrid_labels[i], 0)) <= 1,
        })

    NN_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(NN_OUTPUT, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nNN scores saved → {NN_OUTPUT}")

    try:
        import matplotlib.pyplot as plt
        import matplotlib.colors as mcolors

        color_map = {
            "Normal": "#22c55e",
            "Suspicious": "#f59e0b",
            "High Risk": "#f97316",
            "Critical": "#ef4444",
        }
        colors = [color_map[l] for l in hybrid_labels]

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        ax = axes[0]
        ax.scatter(hybrid_scores, nn_scores, c=colors, s=80, edgecolors="white", linewidths=0.5)
        ax.plot([0, 1], [0, 1], "--", color="#94a3b8", linewidth=1, label="y=x")
        ax.set_xlabel("Hybrid risk score")
        ax.set_ylabel("NN autoencoder score")
        ax.set_title(f"Score correlation  r={correlation:.3f}")
        ax.set_xlim(-0.05, 1.05)
        ax.set_ylim(-0.05, 1.05)

        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor=v, label=k) for k, v in color_map.items()]
        ax.legend(handles=legend_elements, fontsize=9, loc="upper left")

        ax2 = axes[1]
        xticks = range(len(df))
        bar_colors = [color_map[l] for l in nn_labels]
        ax2.bar(xticks, nn_scores, color=bar_colors, edgecolor="white", linewidth=0.4)
        ax2.set_xticks(list(xticks))
        ax2.set_xticklabels([row["event_type"][:10] for _, row in df.iterrows()],
                            rotation=45, ha="right", fontsize=8)
        ax2.set_ylabel("NN anomaly score")
        ax2.set_title("NN scores per event")
        ax2.set_ylim(0, 1.1)
        ax2.axhline(0.30, color="#22c55e", linewidth=0.8, linestyle="--", alpha=0.7)
        ax2.axhline(0.55, color="#f59e0b", linewidth=0.8, linestyle="--", alpha=0.7)
        ax2.axhline(0.75, color="#f97316", linewidth=0.8, linestyle="--", alpha=0.7)

        plt.tight_layout()
        plot_path = NN_OUTPUT.parent / "nn_vs_hybrid_plot.png"
        plt.savefig(plot_path, dpi=150, bbox_inches="tight")
        print(f"Plot saved → {plot_path}")
        plt.show()

    except ImportError:
        print("\n(Install matplotlib to generate the comparison plot)")

    print("\n" + "=" * 62)
    print("Validation complete.")
    print("=" * 62)

if __name__ == "__main__":
    main()
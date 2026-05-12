# Layer 2 autoencoder - train and evaluate on ADFA-LD dataset
# Feature extraction: term frequency per trace (Zhang)
# Anomaly score: mean squared reconstruction error
# Evaluation: 10-fold cross-validation, reports TPR / FPR / AUC
#
# Usage:
#   python device_autoEN.py --data-dir /path/to/ADFA-LD \
#                           --save-model ../../data/models/autoencoder_model.keras \
#                           --vocab ../../data/models/syscall_vocab.json

import json
import argparse
import numpy as np
from pathlib import Path

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from sklearn.metrics import roc_auc_score

# CONSTANTS -------------------------------------------------------

K_FOLDS = 10
EPOCHS = 50
BATCH_SIZE = 32
THRESHOLD_PERCENTILE = 95   # 95th percentile of normal train errors sets the anomaly threshold
ENCODER_DIM1 = 64
BOTTLENECK_DIM = 32
RANDOM_SEED = 42


# DATA LOADING ----------------------------------------------------

def parse_adfa_ld(data_dir: Path):
    """Load normal and attack traces from the labeled ADFA-LD directory."""
    # labeled ADFA-LD directory layout (verazuo version):
    #   data_dir/
    #     Training_Data_Master/   <- normal traces (used for training)
    #     Attack_Data_Master/     <- subdirs per attack type
    #
    # each trace file is space-separated integer syscall IDs on one line

    normal_dir = data_dir / "Training_Data_Master"
    attack_dir = data_dir / "Attack_Data_Master"

    if not normal_dir.exists():
        raise FileNotFoundError(f"Normal traces directory not found: {normal_dir}")
    if not attack_dir.exists():
        raise FileNotFoundError(f"Attack traces directory not found: {attack_dir}")

    normal_traces = _load_traces_from_dir(normal_dir, recurse=False)
    attack_traces = _load_traces_from_dir(attack_dir, recurse=True)

    return normal_traces, attack_traces


def _load_traces_from_dir(directory: Path, recurse: bool) -> list:
    """Read all trace files in a directory into lists of integer syscall IDs."""
    traces = []
    pattern = "**/*" if recurse else "*"

    for filepath in sorted(directory.glob(pattern)):
        if not filepath.is_file():
            continue
        raw = filepath.read_text(errors="ignore").strip()
        if not raw:
            continue
        try:
            syscalls = list(map(int, raw.split()))
            if len(syscalls) > 0:
                traces.append(syscalls)
        except ValueError:
            continue

    return traces


# FEATURE EXTRACTION ----------------------------------------------

def build_vocab(traces: list) -> dict:
    """Build syscall ID to vector index mapping from normal traces only."""
    unique_ids = set()
    for trace in traces:
        unique_ids.update(trace)
    vocab = {syscall_id: idx for idx, syscall_id in enumerate(sorted(unique_ids))}
    return vocab


def trace_to_tf_vector(trace: list, vocab: dict) -> np.ndarray:
    """Convert one trace to a TF vector (Zhang et al. 2021, Eq. 3).

    tf(s, T) = count of syscall s in trace T / total syscalls in T
    Syscall IDs not in vocab (unseen in normal data) are ignored.
    """
    vec = np.zeros(len(vocab), dtype=np.float32)
    total = len(trace)
    if total == 0:
        return vec
    for syscall_id in trace:
        idx = vocab.get(syscall_id)
        if idx is not None:
            vec[idx] += 1
    vec /= total
    return vec


def traces_to_tf_vectors(traces: list, vocab: dict) -> np.ndarray:
    """Convert a list of traces to a matrix of TF vectors."""
    return np.array([trace_to_tf_vector(t, vocab) for t in traces], dtype=np.float32)


# MODEL -----------------------------------------------------------

def build_autoencoder(input_dim: int) -> keras.Model:
    """Build and compile the autoencoder.

    Architecture: input_dim -> 64 -> 32 -> 64 -> input_dim
    Encoder uses ReLU. Output uses sigmoid since TF values are in [0, 1].
    """
    inputs = keras.Input(shape=(input_dim,))
    encoded = layers.Dense(ENCODER_DIM1, activation="relu")(inputs)
    bottleneck = layers.Dense(BOTTLENECK_DIM, activation="relu")(encoded)
    decoded = layers.Dense(ENCODER_DIM1, activation="relu")(bottleneck)
    outputs = layers.Dense(input_dim, activation="sigmoid")(decoded)

    model = keras.Model(inputs, outputs, name="endpoint_autoencoder")
    model.compile(optimizer="adam", loss="mse")
    return model


def reconstruction_errors(model: keras.Model, vectors: np.ndarray) -> np.ndarray:
    """Return per-sample mean squared reconstruction error."""
    reconstructed = model.predict(vectors, verbose=0)
    errors = np.mean((vectors - reconstructed) ** 2, axis=1)
    return errors


# EVALUATION ------------------------------------------------------

def cross_validate(normal_vecs: np.ndarray, attack_vecs: np.ndarray) -> dict:
    """10-fold CV matching Zhang et al. setup.

    Each fold: train on 9/10 normal, test on 1/10 normal + all attacks.
    Threshold = THRESHOLD_PERCENTILE of training fold reconstruction errors.
    Reports TPR, FPR, AUC per fold then averages.
    """
    rng = np.random.default_rng(RANDOM_SEED)
    indices = np.arange(len(normal_vecs))
    rng.shuffle(indices)
    folds = np.array_split(indices, K_FOLDS)

    fold_tprs, fold_fprs, fold_aucs = [], [], []

    print(f"\n{'Fold':>5}  {'TPR':>6}  {'FPR':>6}  {'AUC':>6}")
    print("-" * 30)

    for fold_idx in range(K_FOLDS):
        test_normal_idx = folds[fold_idx]
        train_idx = np.concatenate([folds[i] for i in range(K_FOLDS) if i != fold_idx])

        train_vecs = normal_vecs[train_idx]
        test_normal_vecs = normal_vecs[test_normal_idx]

        model = build_autoencoder(normal_vecs.shape[1])
        model.fit(
            train_vecs, train_vecs,
            epochs=EPOCHS,
            batch_size=BATCH_SIZE,
            verbose=0,
            shuffle=True,
        )

        train_errors = reconstruction_errors(model, train_vecs)
        threshold = np.percentile(train_errors, THRESHOLD_PERCENTILE)

        test_normal_errors = reconstruction_errors(model, test_normal_vecs)
        attack_errors = reconstruction_errors(model, attack_vecs)

        all_errors = np.concatenate([test_normal_errors, attack_errors])
        all_labels = np.concatenate([
            np.zeros(len(test_normal_errors)),
            np.ones(len(attack_errors)),
        ])

        predictions = (all_errors > threshold).astype(int)

        tp = np.sum((predictions == 1) & (all_labels == 1))
        fp = np.sum((predictions == 1) & (all_labels == 0))
        tn = np.sum((predictions == 0) & (all_labels == 0))
        fn = np.sum((predictions == 0) & (all_labels == 1))

        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        auc = roc_auc_score(all_labels, all_errors)

        fold_tprs.append(tpr)
        fold_fprs.append(fpr)
        fold_aucs.append(auc)

        print(f"{fold_idx + 1:>5}  {tpr:>6.3f}  {fpr:>6.3f}  {auc:>6.3f}")

    print("-" * 30)
    print(f"{'Mean':>5}  {np.mean(fold_tprs):>6.3f}  {np.mean(fold_fprs):>6.3f}  {np.mean(fold_aucs):>6.3f}")
    print(f"{'Std':>5}  {np.std(fold_tprs):>6.3f}  {np.std(fold_fprs):>6.3f}  {np.std(fold_aucs):>6.3f}")

    return {
        "mean_tpr": float(np.mean(fold_tprs)),
        "mean_fpr": float(np.mean(fold_fprs)),
        "mean_auc": float(np.mean(fold_aucs)),
        "std_tpr": float(np.std(fold_tprs)),
        "std_fpr": float(np.std(fold_fprs)),
        "std_auc": float(np.std(fold_aucs)),
    }


# MAIN ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Train Layer 2 autoencoder on ADFA-LD")
    parser.add_argument("--data-dir", type=Path, required=True,
                        help="Path to labeled ADFA-LD dataset root")
    parser.add_argument("--save-model", type=Path,
                        default=Path("../../data/models/autoencoder_model.keras"),
                        help="Output path for trained Keras model")
    parser.add_argument("--vocab", type=Path,
                        default=Path("../../data/models/syscall_vocab.json"),
                        help="Output path for syscall vocab JSON")
    args = parser.parse_args()

    tf.random.set_seed(RANDOM_SEED)

    # LOAD DATA -------
    print("Loading ADFA-LD dataset...")
    normal_traces, attack_traces = parse_adfa_ld(args.data_dir)
    print(f"  Normal traces:  {len(normal_traces)}")
    print(f"  Attack traces:  {len(attack_traces)}")

    if len(normal_traces) == 0:
        raise ValueError("No normal traces loaded - check --data-dir path")
    if len(attack_traces) == 0:
        raise ValueError("No attack traces loaded - check --data-dir path")

    avg_normal_len = np.mean([len(t) for t in normal_traces])
    avg_attack_len = np.mean([len(t) for t in attack_traces])
    print(f"  Avg normal trace length: {avg_normal_len:.1f} syscalls")
    print(f"  Avg attack trace length: {avg_attack_len:.1f} syscalls")

    # FEATURES -------
    print("\nBuilding vocabulary and extracting TF vectors...")
    vocab = build_vocab(normal_traces)
    print(f"  Vocab size (unique syscall IDs in normal data): {len(vocab)}")

    normal_vecs = traces_to_tf_vectors(normal_traces, vocab)
    attack_vecs = traces_to_tf_vectors(attack_traces, vocab)
    print(f"  Normal matrix: {normal_vecs.shape}")
    print(f"  Attack matrix: {attack_vecs.shape}")

    # CROSS-VALIDATION -------
    print(f"\nRunning {K_FOLDS}-fold cross-validation ({EPOCHS} epochs per fold)...")
    results = cross_validate(normal_vecs, attack_vecs)

    print(f"\nFinal CV results:")
    print(f"  TPR: {results['mean_tpr']:.3f} +/- {results['std_tpr']:.3f}")
    print(f"  FPR: {results['mean_fpr']:.3f} +/- {results['std_fpr']:.3f}")
    print(f"  AUC: {results['mean_auc']:.3f} +/- {results['std_auc']:.3f}")

    # FINAL MODEL -------
    print("\nTraining final model on all normal data...")
    final_model = build_autoencoder(normal_vecs.shape[1])
    final_model.fit(
        normal_vecs, normal_vecs,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        verbose=1,
        shuffle=True,
    )

    final_errors = reconstruction_errors(final_model, normal_vecs)
    final_threshold = float(np.percentile(final_errors, THRESHOLD_PERCENTILE))
    print(f"  Final anomaly threshold ({THRESHOLD_PERCENTILE}th percentile): {final_threshold:.6f}")

    # SAVE -------
    args.save_model.parent.mkdir(parents=True, exist_ok=True)
    final_model.save(args.save_model)
    print(f"\nModel saved to {args.save_model}")

    vocab_data = {
        "vocab": {str(k): v for k, v in vocab.items()},
        "threshold": final_threshold,
        "input_dim": len(vocab),
    }
    args.vocab.parent.mkdir(parents=True, exist_ok=True)
    args.vocab.write_text(json.dumps(vocab_data, indent=2))
    print(f"Vocab saved to {args.vocab}")


if __name__ == "__main__":
    main()
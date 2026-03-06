import math
import numpy as np
from datetime import datetime
from typing import List
from sklearn.ensemble import IsolationForest
from schemas.agent_result import AgentResult
from engine.pipeline.sessionizer import Session


def extract_features(session: Session) -> dict:
    """
    Extracts behavioral features from a single session.

    These features capture HOW a user interacts with the API,
    not WHAT they access. This is what separates behavioral
    analysis from semantic analysis.
    """
    events = session.events
    count = len(events)

    if count < 2:
        return {
            "request_count": count,
            "avg_interval": 0,
            "std_interval": 0,
            "endpoint_entropy": 0,
            "error_rate": 0,
            "burstiness": count,
            "unique_endpoints": 1 if count else 0,
            "sequential_id_score": 0,
        }

    # ---- Timing features ----
    times = [datetime.fromisoformat(e.timestamp) for e in events]
    intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
    avg_interval = sum(intervals) / len(intervals)
    std_interval = (sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5

    # ---- Endpoint diversity (Shannon entropy) ----
    endpoints = [e.endpoint for e in events]
    freq = {}
    for ep in endpoints:
        freq[ep] = freq.get(ep, 0) + 1
    entropy = -sum((c / count) * math.log2(c / count) for c in freq.values())

    # ---- Error rate ----
    errors = sum(1 for e in events if e.status_code >= 400)
    error_rate = errors / count

    # ---- Burstiness ----
    burst = 0
    for i, t in enumerate(times):
        window_count = sum(1 for t2 in times if 0 <= (t2 - t).total_seconds() <= 5)
        burst = max(burst, window_count)

    # ---- Sequential ID detection ----
    ids = []
    for ep in endpoints:
        parts = ep.rstrip("/").split("/")
        if parts and parts[-1].isdigit():
            ids.append(int(parts[-1]))
    seq_score = 0.0
    if len(ids) >= 2:
        diffs = [ids[i + 1] - ids[i] for i in range(len(ids) - 1)]
        seq_score = sum(1 for d in diffs if d == 1) / len(diffs)

    return {
        "request_count": count,
        "avg_interval": avg_interval,
        "std_interval": std_interval,
        "endpoint_entropy": entropy,
        "error_rate": error_rate,
        "burstiness": burst,
        "unique_endpoints": len(freq),
        "sequential_id_score": seq_score,
    }


def features_to_vector(features: dict) -> list:
    """Convert feature dict to a numeric list for the model."""
    return [
        features["request_count"],
        features["avg_interval"],
        features["std_interval"],
        features["endpoint_entropy"],
        features["error_rate"],
        features["burstiness"],
        features["unique_endpoints"],
        features["sequential_id_score"],
    ]


def analyze(sessions: List[Session]) -> List[AgentResult]:
    """
    Analyzes sessions using Isolation Forest.

    How it works:
    1. Extract features from every session
    2. Feed all feature vectors into Isolation Forest
    3. The model scores each session: -1 = anomaly, 1 = normal
    4. Convert model scores to 0.0-1.0 risk scores
    """
    if not sessions:
        return []

    # Step 1: Extract features for all sessions
    all_features = []
    for session in sessions:
        all_features.append(extract_features(session))

    # Step 2: Convert to numeric matrix
    feature_matrix = np.array([features_to_vector(f) for f in all_features])

    # Step 3: Train Isolation Forest
    # contamination = expected % of anomalies (0.3 = ~30%)
    # random_state = fixed seed for reproducible results
    model = IsolationForest(
        contamination=0.3,
        random_state=42,
        n_estimators=100,
    )
    model.fit(feature_matrix)

    # Step 4: Get anomaly scores
    # decision_function returns: negative = more anomalous, positive = more normal
    raw_scores = model.decision_function(feature_matrix)
    # predictions: -1 = anomaly, 1 = normal
    predictions = model.predict(feature_matrix)

    # Step 5: Convert to 0.0-1.0 risk scores
    # Normalize: most negative raw score → 1.0, most positive → 0.0
    min_score = raw_scores.min()
    max_score = raw_scores.max()
    if max_score - min_score == 0:
        normalized = np.zeros_like(raw_scores)
    else:
        normalized = 1 - (raw_scores - min_score) / (max_score - min_score)

    # Step 6: Build results
    results = []
    for i, session in enumerate(sessions):
        risk_score = round(float(normalized[i]), 2)
        is_anomaly = predictions[i] == -1
        features = all_features[i]

        # Generate flags based on features (explain WHY it's suspicious)
        flags = []
        if features["avg_interval"] < 1.0 and features["request_count"] > 10:
            flags.append("high_request_rate")
        if features["std_interval"] < 0.2 and features["request_count"] > 10:
            flags.append("consistent_timing")
        if features["sequential_id_score"] > 0.5:
            flags.append("sequential_id_access")
        if features["error_rate"] > 0.5:
            flags.append("high_error_rate")
        if features["burstiness"] > 20:
            flags.append("burst_detected")
        if is_anomaly:
            flags.append("model_anomaly")

        results.append(AgentResult(
            agent="behavioral",
            risk_score=risk_score,
            flags=flags,
            explanation=f"Session {session.session_id}: {', '.join(flags) or 'normal'}",
            metadata={**features, "is_anomaly": is_anomaly},
        ))

    return results
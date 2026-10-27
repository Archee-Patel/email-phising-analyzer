from dataclasses import dataclass
import math
from typing import Dict, List, Sequence, Tuple

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

from .datasets import EmailRecord
from .email_features import flatten_features


FEATURE_GROUPS = ("headers", "links", "wording")
MODEL_NAMES = ("Logistic regression", "Random forest")


@dataclass
class TrainedModel:
    pipeline: object
    groups: Tuple[str, ...]
    model_name: str

    def phishing_probability(self, features: Dict[str, Dict[str, object]]) -> float:
        row = flatten_features(features, list(self.groups))
        return float(self.pipeline.predict_proba([row])[0][1])


def _pipeline(model_name: str, random_state: int):
    if model_name == "Logistic regression":
        classifier = LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=random_state
        )
    elif model_name == "Random forest":
        classifier = RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1,
        )
    else:
        raise ValueError("Unsupported model: {}".format(model_name))
    return make_pipeline(DictVectorizer(), classifier)


def _rows(records: Sequence[EmailRecord], groups: Sequence[str]):
    return [flatten_features(record.features, list(groups)) for record in records]


def _metrics(model, records: Sequence[EmailRecord], groups: Sequence[str]):
    predictions = model.predict(_rows(records, groups))
    labels = [record.label for record in records]
    return (
        precision_score(labels, predictions, zero_division=0),
        recall_score(labels, predictions, zero_division=0),
    )


def _validate_class_counts(records: Sequence[EmailRecord], description: str) -> None:
    counts = {label: sum(record.label == label for record in records) for label in (0, 1)}
    if min(counts.values()) < 2:
        raise ValueError(
            "{} needs at least two messages in each class; found "
            "{} legitimate and {} phishing.".format(description, counts[0], counts[1])
        )


def evaluate_within_dataset(
    records: Sequence[EmailRecord], test_size: float = 0.25, random_state: int = 42
) -> pd.DataFrame:
    _validate_class_counts(records, "Within-dataset evaluation")
    test_count = math.ceil(test_size * len(records))
    if test_count < 2 or len(records) - test_count < 2:
        raise ValueError(
            "Within-dataset evaluation needs at least two messages in both "
            "the training and test partitions."
        )
    indices = list(range(len(records)))
    labels = [record.label for record in records]
    train_indices, test_indices = train_test_split(
        indices,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )
    training = [records[index] for index in train_indices]
    testing = [records[index] for index in test_indices]

    results = []
    for group in FEATURE_GROUPS:
        for model_name in MODEL_NAMES:
            model = _pipeline(model_name, random_state)
            model.fit(_rows(training, (group,)), [record.label for record in training])
            precision, recall = _metrics(model, testing, (group,))
            results.append({
                "Feature group": group.title(),
                "Model": model_name,
                "Precision": precision,
                "Recall": recall,
                "Training emails": len(training),
                "Test emails": len(testing),
            })
    return pd.DataFrame(results)


def evaluate_cross_dataset(
    source_records: Sequence[EmailRecord],
    target_records: Sequence[EmailRecord],
    random_state: int = 42,
) -> pd.DataFrame:
    _validate_class_counts(source_records, "Cross-dataset source")
    _validate_class_counts(target_records, "Cross-dataset target")
    source_name = source_records[0].dataset
    target_name = target_records[0].dataset
    if source_name == target_name:
        raise ValueError("Cross-dataset evaluation requires two different datasets.")

    results = []
    for group in FEATURE_GROUPS:
        for model_name in MODEL_NAMES:
            model = _pipeline(model_name, random_state)
            model.fit(
                _rows(source_records, (group,)),
                [record.label for record in source_records],
            )
            precision, recall = _metrics(model, target_records, (group,))
            results.append({
                "Feature group": group.title(),
                "Model": model_name,
                "Precision": precision,
                "Recall": recall,
                "Training dataset": source_name,
                "Test dataset": target_name,
                "Training emails": len(source_records),
                "Test emails": len(target_records),
            })
    return pd.DataFrame(results)


def train_model(
    records: Sequence[EmailRecord], model_name: str, groups: Tuple[str, ...] = FEATURE_GROUPS
) -> TrainedModel:
    _validate_class_counts(records, "Model training")
    pipeline = _pipeline(model_name, random_state=42)
    pipeline.fit(_rows(records, groups), [record.label for record in records])
    return TrainedModel(pipeline=pipeline, groups=groups, model_name=model_name)

import email
import email.policy
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from .email_features import FeatureGroups, extract_feature_groups


POSITIVE_LABELS = {"phishing", "phish", "spam", "malicious"}
NEGATIVE_LABELS = {"legitimate", "ham", "benign", "non-phishing", "nonphishing"}


@dataclass
class EmailRecord:
    dataset: str
    label: int
    features: FeatureGroups


def _label_for_directory(directory_name: str) -> int:
    normalized = directory_name.strip().lower().replace("_", "-").replace(" ", "-")
    if normalized in POSITIVE_LABELS:
        return 1
    if normalized in NEGATIVE_LABELS:
        return 0
    raise ValueError(
        "Class folders must be named phishing (or phish/spam) and legitimate "
        "(or ham/benign). Found {!r}.".format(directory_name)
    )


def load_dataset(dataset_path: Path) -> List[EmailRecord]:
    """Load .eml messages from <dataset>/<class> folders."""
    if not dataset_path.is_dir():
        raise ValueError("Dataset directory does not exist: {}".format(dataset_path))

    records: List[EmailRecord] = []
    class_directories = [
        path for path in dataset_path.iterdir() if path.is_dir()
    ]
    for class_directory in sorted(class_directories):
        label = _label_for_directory(class_directory.name)
        for eml_path in sorted(class_directory.rglob("*.eml")):
            with eml_path.open("rb") as eml_file:
                message = email.message_from_binary_file(
                    eml_file, policy=email.policy.default
                )
            records.append(
                EmailRecord(
                    dataset=dataset_path.name,
                    label=label,
                    features=extract_feature_groups(message),
                )
            )

    if not records:
        raise ValueError("No .eml messages found in {}".format(dataset_path))
    labels = {record.label for record in records}
    if labels != {0, 1}:
        raise ValueError(
            "Dataset {} must contain both phishing and legitimate messages."
            .format(dataset_path.name)
        )
    return records


def discover_datasets(root: Path) -> List[Tuple[str, Path]]:
    if not root.is_dir():
        return []
    discovered = []
    for path in sorted(child for child in root.iterdir() if child.is_dir()):
        class_names = {
            child.name.strip().lower().replace("_", "-").replace(" ", "-")
            for child in path.iterdir()
            if child.is_dir()
        }
        has_positive = bool(class_names & POSITIVE_LABELS)
        has_negative = bool(class_names & NEGATIVE_LABELS)
        if has_positive and has_negative:
            discovered.append((path.name, path))
    return discovered

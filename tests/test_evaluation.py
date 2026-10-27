import unittest

from phishing_analyzer.datasets import EmailRecord
from phishing_analyzer.evaluation import evaluate_cross_dataset, evaluate_within_dataset


def records(dataset, count_per_class=12):
    examples = []
    for label in (0, 1):
        for index in range(count_per_class):
            signal = label if index % 3 else 1 - label
            features = {
                "headers": {"signal": signal, "category": "phish" if label else "ham"},
                "links": {"signal": signal},
                "wording": {"signal": signal},
            }
            examples.append(EmailRecord(dataset, label, features))
    return examples


class EvaluationTests(unittest.TestCase):
    def test_within_dataset_compares_every_group_and_model(self):
        result = evaluate_within_dataset(records("public_a"))
        self.assertEqual(len(result), 6)
        self.assertEqual(set(result["Feature group"]), {"Headers", "Links", "Wording"})
        self.assertTrue(result["Precision"].between(0, 1).all())
        self.assertTrue(result["Recall"].between(0, 1).all())

    def test_cross_dataset_uses_distinct_source_and_target(self):
        result = evaluate_cross_dataset(records("public_a"), records("public_b"))
        self.assertEqual(len(result), 6)
        self.assertEqual(set(result["Training dataset"]), {"public_a"})
        self.assertEqual(set(result["Test dataset"]), {"public_b"})

    def test_within_dataset_rejects_too_small_test_partition(self):
        with self.assertRaisesRegex(ValueError, "training and test partitions"):
            evaluate_within_dataset(records("tiny", count_per_class=2))


if __name__ == "__main__":
    unittest.main()

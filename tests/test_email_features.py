import email
import email.policy
import unittest

from phishing_analyzer.email_features import extract_feature_groups, explain_features


class EmailFeatureTests(unittest.TestCase):
    def parse(self, raw):
        return email.message_from_string(raw, policy=email.policy.default)

    def test_detects_reply_to_mismatch_and_suspicious_link(self):
        message = self.parse(
            "From: Security <security@example.com>\n"
            "Reply-To: attacker@other.example\n"
            "Subject: Urgent account verification\n"
            "Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            '<p>Verify your account immediately!</p>'
            '<a href="http://192.0.2.1/login">secure.example.com</a>'
        )
        features = extract_feature_groups(message)
        self.assertEqual(features["headers"]["sender_reply_to_domain_mismatch"], 1)
        self.assertEqual(features["links"]["url_domain_is_ip"], 1)
        self.assertIn(
            "Sender domain does not match the Reply-To domain.",
            explain_features(features),
        )

    def test_clean_message_does_not_invent_reply_to_mismatch(self):
        message = self.parse(
            "From: colleague@example.com\n"
            "Subject: Meeting notes\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Here are the notes from our meeting."
        )
        features = extract_feature_groups(message)
        self.assertEqual(features["headers"]["sender_reply_to_domain_mismatch"], 0)
        self.assertEqual(features["links"]["url_count"], 0)


if __name__ == "__main__":
    unittest.main()

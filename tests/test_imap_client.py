import unittest
from unittest.mock import Mock, patch

from phishing_analyzer.imap_client import fetch_recent_messages


class ImapClientTests(unittest.TestCase):
    @patch("phishing_analyzer.imap_client.imaplib.IMAP4_SSL")
    def test_selects_read_only_and_fetches_without_setting_seen(self, imap_class):
        connection = Mock()
        imap_class.return_value = connection
        connection.select.return_value = ("OK", [b""])
        connection.uid.side_effect = [
            ("OK", [b"1 2"]),
            ("OK", [(b"2 (BODY[])", b"From: a@example.com\nSubject: latest\n\ntext")]),
            ("OK", [(b"1 (BODY[])", b"From: b@example.com\nSubject: older\n\ntext")]),
        ]

        messages = fetch_recent_messages("imap.example.com", "user", "secret")

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].message["Subject"], "latest")
        connection.select.assert_called_once_with("INBOX", readonly=True)
        self.assertEqual(connection.uid.call_args_list[1].args[2], "(BODY.PEEK[])")
        self.assertEqual(connection.uid.call_args_list[2].args[2], "(BODY.PEEK[])")
        self.assertTrue(all(
            call.args[0] in {"search", "fetch"}
            for call in connection.uid.call_args_list
        ))
        connection.logout.assert_called_once()


if __name__ == "__main__":
    unittest.main()

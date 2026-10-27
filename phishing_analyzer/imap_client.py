import imaplib
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.message import Message
from typing import List


@dataclass
class MailboxMessage:
    uid: bytes
    message: Message


def fetch_recent_messages(
    host: str,
    username: str,
    password: str,
    mailbox: str = "INBOX",
    limit: int = 25,
    port: int = 993,
) -> List[MailboxMessage]:
    if not host.strip() or not username.strip():
        raise ValueError("IMAP host and username are required.")
    if not mailbox.strip() or "\r" in mailbox or "\n" in mailbox:
        raise ValueError("Mailbox name must be non-empty and contain no newlines.")
    if not 1 <= limit <= 500:
        raise ValueError("Message limit must be between 1 and 500.")

    connection = imaplib.IMAP4_SSL(host.strip(), port)
    try:
        connection.login(username, password)
        status, _ = connection.select(mailbox, readonly=True)
        if status != "OK":
            raise RuntimeError("Could not open the mailbox in read-only mode.")
        status, response = connection.uid("search", None, "ALL")
        if status != "OK" or not response or response[0] is None:
            raise RuntimeError("IMAP server did not return mailbox message IDs.")
        identifiers = response[0].split()[-limit:]

        messages: List[MailboxMessage] = []
        for identifier in reversed(identifiers):
            status, data = connection.uid("fetch", identifier, "(BODY.PEEK[])")
            if status != "OK":
                raise RuntimeError("Could not fetch message UID {}.".format(
                    identifier.decode("ascii", errors="replace")
                ))
            raw_messages = [
                item[1] for item in data
                if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], bytes)
            ]
            if not raw_messages:
                raise RuntimeError("IMAP fetch returned no message content.")
            messages.append(MailboxMessage(
                uid=identifier,
                message=BytesParser(policy=policy.default).parsebytes(raw_messages[0]),
            ))
        return messages
    finally:
        connection.logout()

#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Basic IMAP client example for Mailsis.

Connects to the Mailsis IMAP server, logs in, selects the INBOX, and
fetches the latest email message. Prints the subject line and the
plain-text body of the message.

This example uses hardcoded defaults and requires no command-line arguments.

Constants
---------
IMAP_SERVER      IMAP server hostname (default: 127.0.0.1).
IMAP_PORT        IMAP server port (default: 1430).
EMAIL_ACCOUNT    Login email address (default: recipient@localhost).
PASSWORD         Login password (default: password).

Prerequisites
-------------
Start the Mailsis IMAP server before running this script::

    cargo run -p mailsis-imap

You should also have at least one email in the mailbox. Send one using the
SMTP example first::

    cargo run -p mailsis-smtp          # start SMTP server in another terminal
    python smtp/examples/smtp_client.py

Example Usage
-------------
Read the latest email from INBOX::

    python imap/examples/imap_client.py

The script will:
  - Connect to 127.0.0.1:1430
  - Log in as recipient@localhost
  - Select INBOX (read-only)
  - Fetch and display the latest message's subject and plain-text body
"""

import imaplib
import email
from email.header import decode_header

IMAP_SERVER = "127.0.0.1"
IMAP_PORT = 1430
EMAIL_ACCOUNT = "recipient@localhost"
PASSWORD = "password"

# Connect and login
mail = imaplib.IMAP4(IMAP_SERVER, IMAP_PORT)
mail.login(EMAIL_ACCOUNT, PASSWORD)

# Select inbox (readonly=False for marking messages as read, etc.)
mail.select("inbox", readonly=True)

# Search for all messages
status, messages = mail.search(None, "ALL")
if status != "OK":
    print("No messages found.")
    exit()

# Get list of message IDs
message_ids = messages[0].split()

# Fetch latest message
latest_id = message_ids[-1]
status, data = mail.fetch(latest_id, "(RFC822)")

if status == "OK":
    msg = email.message_from_bytes(data[0][1])
    subject, encoding = decode_header(msg["Subject"])[0]
    if isinstance(subject, bytes):
        subject = subject.decode(encoding or "utf-8", errors="ignore")
    print("Subject:", subject)

    # Print body (plain text part)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                print(part.get_payload(decode=True).decode(errors="ignore"))
                break
    else:
        print(msg.get_payload(decode=True).decode(errors="ignore"))

mail.logout()

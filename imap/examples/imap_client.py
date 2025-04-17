#!/usr/bin/python
# -*- coding: utf-8 -*-

import imaplib
import email
from email.header import decode_header

IMAP_SERVER = "127.0.0.1"
IMAP_PORT = 1430
EMAIL_ACCOUNT = "recipient@example.com"
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

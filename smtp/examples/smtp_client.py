#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Basic SMTP client example for Mailsis.

Generates a random binary file, connects to the Mailsis SMTP server over
STARTTLS, and sends a test email with the file as an attachment. Prints
timing information for each step and cleans up the temporary file on exit.

This example uses hardcoded defaults and requires no command-line arguments.
For a configurable client with CLI options, see ``smtp_advanced.py``.

Constants
---------
SMTP_SERVER    SMTP server hostname (default: 127.0.0.1).
SMTP_PORT      SMTP server port (default: 2525).
SENDER         Sender email address (default: sender@localhost).
RECIPIENT      Recipient email address (default: recipient@localhost).
FILE_SIZE_MB   Size of the generated random attachment in megabytes (default: 1).

Prerequisites
-------------
Start the Mailsis SMTP server before running this script::

    cargo run -p mailsis-smtp

Example Usage
-------------
Run with default settings::

    python smtp/examples/smtp_client.py

The script will:
  - Generate a 1 MB random binary file (``random_data.bin``)
  - Connect to 127.0.0.1:2525 with STARTTLS
  - Send the email with the attachment
  - Print elapsed time for each step
  - Delete the temporary file
"""

import smtplib
import os
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 2525
SENDER = "sender@localhost"
RECIPIENT = "recipient@localhost"

# Size of the random file in MB
FILE_SIZE_MB = 1

# Generate random file
print(f"Generating random file of {FILE_SIZE_MB} MB...")
start_time = time.time()
file_path = "random_data.bin"
with open(file_path, "wb") as file:
    file.write(os.urandom(FILE_SIZE_MB * 1024 * 1024))
print(f"File generated in {time.time() - start_time:.2f}s")

# Connect to SMTP server
print("Connecting to SMTP server...")
connect_start = time.time()
smtp = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
smtp.starttls()
print(f"SMTP connection established in {time.time() - connect_start:.2f}s")

# Prepare email message
print("Preparing email message...")
email_start = time.time()

msg = MIMEMultipart()
msg["From"] = SENDER
msg["To"] = RECIPIENT
msg["Subject"] = "Large File Test"

body = f"This is a test email with a {FILE_SIZE_MB} MB file attachment."
msg.attach(MIMEText(body, "plain"))

with open(file_path, "rb") as file:
    attachment = MIMEApplication(file.read(), Name="random_data.bin")
    attachment["Content-Disposition"] = 'attachment; filename="random_data.bin"'
    msg.attach(attachment)

print(f"Email prepared in {time.time() - email_start:.2f}s")

# Send email
print("Sending email...")
send_start = time.time()
smtp.sendmail(SENDER, [RECIPIENT], msg.as_string())
print(f"Email sent successfully in {time.time() - send_start:.2f}s")
print(f"Total time: {time.time() - start_time:.2f}s")

smtp.quit()

# Cleanup
os.remove(file_path)

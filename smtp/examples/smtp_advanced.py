#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Advanced SMTP client example for Mailsis.

A feature-rich command-line SMTP client that supports plain text and HTML
emails, file attachments, STARTTLS encryption, and SMTP authentication.
Designed for Python 3.11+ and intended as both a testing tool and a
reference for integrating with the Mailsis SMTP server.

Parameters
----------
--from         Sender email address (default: sender@localhost).
--to           One or more recipient email addresses (default: recipient@localhost).
--cc           One or more CC recipient email addresses.
--bcc          One or more BCC recipient email addresses.
--subject      Email subject line (default: "Test Email").
--body         Plain-text body of the email (default: "Hello from Mailsis!").
--html         HTML body of the email. When provided, a multipart/alternative
               message is created with both plain-text and HTML parts.
--attachment   One or more file paths to attach to the email.
--host         SMTP server hostname (default: 127.0.0.1).
--port         SMTP server port (default: 2525).
--tls          Enable STARTTLS after connecting (flag, off by default).
--username     Username for SMTP authentication (PLAIN/LOGIN).
--password     Password for SMTP authentication.
--reply-to     Reply-To address.
--priority     Email priority: low, normal, or high.
--verbose      Print SMTP protocol debug output.

Example Usage
-------------
Send a simple text email::

    python smtp_advanced.py \\
        --from sender@localhost \\
        --to recipient@localhost \\
        --subject "Hello" \\
        --body "This is a test."

Send to multiple recipients with an attachment::

    python smtp_advanced.py \\
        --from sender@localhost \\
        --to alice@localhost bob@localhost \\
        --subject "Report" \\
        --body "See attached." \\
        --attachment report.pdf

Send an HTML email with STARTTLS and authentication::

    python smtp_advanced.py \\
        --from sender@localhost \\
        --to recipient@localhost \\
        --subject "Newsletter" \\
        --html "<h1>Welcome</h1><p>HTML content here.</p>" \\
        --tls \\
        --username sender@localhost \\
        --password secret

Send a high-priority email with CC, BCC, and Reply-To::

    python smtp_advanced.py \\
        --from sender@localhost \\
        --to recipient@localhost \\
        --cc manager@localhost \\
        --bcc archive@localhost \\
        --reply-to noreply@localhost \\
        --priority high \\
        --subject "Urgent" \\
        --body "Please review immediately."

Enable verbose SMTP protocol output for debugging::

    python smtp_advanced.py \\
        --from sender@localhost \\
        --to recipient@localhost \\
        --body "Debug test" \\
        --verbose
"""

import argparse
import mimetypes
import smtplib
import sys
import time

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

PRIORITY_HEADERS = {
    "low": ("5", "Non-Urgent", "bulk"),
    "normal": ("3", "Normal", "normal"),
    "high": ("1", "Urgent", "urgent"),
}


def build_message(args: argparse.Namespace) -> MIMEMultipart:
    """Build a MIME email message from the parsed CLI arguments."""
    msg = MIMEMultipart("mixed")
    msg["From"] = args.from_addr
    msg["To"] = ", ".join(args.to)
    msg["Subject"] = args.subject

    if args.cc:
        msg["Cc"] = ", ".join(args.cc)
    if args.reply_to:
        msg["Reply-To"] = args.reply_to

    # Priority headers
    if args.priority and args.priority != "normal":
        importance, priority, precedence = PRIORITY_HEADERS[args.priority]
        msg["X-Priority"] = importance
        msg["X-MSMail-Priority"] = priority
        msg["Importance"] = priority
        msg["Precedence"] = precedence

    # Body: plain text, or plain + HTML as multipart/alternative
    if args.html:
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(args.body, "plain", "utf-8"))
        alt.attach(MIMEText(args.html, "html", "utf-8"))
        msg.attach(alt)
    else:
        msg.attach(MIMEText(args.body, "plain", "utf-8"))

    # Attachments
    for file_path in args.attachment or []:
        path = Path(file_path)
        if not path.is_file():
            print(f"Warning: attachment not found, skipping: {path}", file=sys.stderr)
            continue
        content_type, _ = mimetypes.guess_type(str(path))
        _, subtype = (content_type or "application/octet-stream").split("/", 1)
        with open(path, "rb") as f:
            part = MIMEApplication(f.read(), Name=path.name, _subtype=subtype)
        part["Content-Disposition"] = f'attachment; filename="{path.name}"'
        msg.attach(part)
        print(f"  Attached: {path.name} ({path.stat().st_size:,} bytes)")

    return msg


def send(args: argparse.Namespace) -> None:
    """Connect to the SMTP server and send the email."""
    all_recipients = list(args.to)
    if args.cc:
        all_recipients.extend(args.cc)
    if args.bcc:
        all_recipients.extend(args.bcc)

    print(f"Connecting to {args.host}:{args.port} ...")
    start = time.time()

    smtp = smtplib.SMTP(args.host, args.port)
    if args.verbose:
        smtp.set_debuglevel(2)

    if args.tls:
        print("Starting TLS ...")
        smtp.starttls()

    if args.username and args.password:
        print(f"Authenticating as {args.username} ...")
        smtp.login(args.username, args.password)

    print("Building message ...")
    msg = build_message(args)

    print(f"Sending to {len(all_recipients)} recipient(s) ...")
    smtp.sendmail(args.from_addr, all_recipients, msg.as_string())
    smtp.quit()

    elapsed = time.time() - start
    print(f"Email sent successfully in {elapsed:.2f}s")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Advanced SMTP client for Mailsis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --to recipient@localhost --body 'Hello!'\n"
            "  %(prog)s --to a@localhost b@localhost --attachment report.pdf\n"
            "  %(prog)s --tls --username user --password pass --to r@localhost\n"
        ),
    )

    # Addresses
    parser.add_argument(
        "--from",
        dest="from_addr",
        default="sender@localhost",
        help="Sender address (default: sender@localhost)",
    )
    parser.add_argument(
        "--to",
        nargs="+",
        default=["recipient@localhost"],
        help="Recipient address(es) (default: recipient@localhost)",
    )
    parser.add_argument(
        "--cc", nargs="+", default=None, help="CC recipient address(es)"
    )
    parser.add_argument(
        "--bcc", nargs="+", default=None, help="BCC recipient address(es)"
    )
    parser.add_argument("--reply-to", default=None, help="Reply-To address")

    # Content
    parser.add_argument(
        "--subject", default="Test Email", help="Email subject (default: 'Test Email')"
    )
    parser.add_argument(
        "--body",
        default="Hello from Mailsis!",
        help="Plain-text body (default: 'Hello from Mailsis!')",
    )
    parser.add_argument(
        "--html", default=None, help="HTML body (creates multipart/alternative)"
    )
    parser.add_argument(
        "--attachment", nargs="+", default=None, help="File path(s) to attach"
    )
    parser.add_argument(
        "--priority",
        choices=["low", "normal", "high"],
        default="normal",
        help="Email priority (default: normal)",
    )

    # Connection
    parser.add_argument(
        "--host", default="127.0.0.1", help="SMTP server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=2525, help="SMTP server port (default: 2525)"
    )
    parser.add_argument("--tls", action="store_true", help="Enable STARTTLS")
    parser.add_argument("--username", default=None, help="SMTP auth username")
    parser.add_argument("--password", default=None, help="SMTP auth password")

    # Debug
    parser.add_argument(
        "--verbose", action="store_true", help="Enable SMTP debug output"
    )

    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    try:
        send(args)
    except smtplib.SMTPException as exc:
        print(f"SMTP error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Connection refused: {args.host}:{args.port}", file=sys.stderr)
        sys.exit(1)

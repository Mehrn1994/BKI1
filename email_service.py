"""
Email Service - Exchange/Outlook Integration via EWS
Connects to Exchange Server using user credentials (no admin permissions needed)
"""

from exchangelib import (
    Credentials, Account, Configuration, DELEGATE,
    Message, Mailbox, HTMLBody, FaultTolerance
)
from exchangelib.protocol import BaseProtocol
import json
import os
import sqlite3
import base64
from datetime import datetime

# Settings file path
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'email_settings.json')

# Disable SSL verification for internal Exchange (common in banks)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Allow self-signed certificates (common in enterprise environments)
BaseProtocol.HTTP_ADAPTER_CLS = None  # Will be set if needed

# Simple obfuscation for stored password (not plain text in JSON)
_OBF_PREFIX = 'obf:'

def _obfuscate(text):
    if not text:
        return ''
    return _OBF_PREFIX + base64.b64encode(text.encode('utf-8')).decode('ascii')

def _deobfuscate(text):
    if not text:
        return ''
    if text.startswith(_OBF_PREFIX):
        return base64.b64decode(text[len(_OBF_PREFIX):]).decode('utf-8')
    return text  # Legacy: plain text password


def load_settings():
    """Load email settings from JSON file (password is deobfuscated)"""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            settings = json.load(f)
        # Deobfuscate password for internal use
        if 'password' in settings:
            settings['password'] = _deobfuscate(settings['password'])
        return settings
    return {
        'configured': False,
        'email': '',
        'username': '',
        'password': '',
        'server': '',
        'folder_name': 'Inbox',
        'sender_filters': [],
        'use_autodiscover': True,
        'verify_ssl': False
    }


def save_settings(settings):
    """Save email settings to JSON file (password is obfuscated)"""
    to_save = dict(settings)
    if 'password' in to_save and to_save['password']:
        to_save['password'] = _obfuscate(to_save['password'])
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(to_save, f, ensure_ascii=False, indent=2)


def get_exchange_account(settings=None):
    """Connect to Exchange server and return Account object"""
    if settings is None:
        settings = load_settings()

    if not settings.get('configured'):
        return None

    credentials = Credentials(
        username=settings['username'],
        password=settings['password']
    )

    if settings.get('use_autodiscover', True):
        # Auto-discover Exchange server
        account = Account(
            primary_smtp_address=settings['email'],
            credentials=credentials,
            autodiscover=True,
            access_type=DELEGATE
        )
    else:
        # Manual server configuration
        config = Configuration(
            server=settings['server'],
            credentials=credentials,
            retry_policy=FaultTolerance(max_wait=30)
        )
        account = Account(
            primary_smtp_address=settings['email'],
            config=config,
            autodiscover=False,
            access_type=DELEGATE
        )

    return account


def test_connection(settings):
    """Test Exchange connection with given settings. Returns (success, message)"""
    try:
        credentials = Credentials(
            username=settings['username'],
            password=settings['password']
        )

        if settings.get('use_autodiscover', True):
            account = Account(
                primary_smtp_address=settings['email'],
                credentials=credentials,
                autodiscover=True,
                access_type=DELEGATE
            )
        else:
            config = Configuration(
                server=settings['server'],
                credentials=credentials,
                retry_policy=FaultTolerance(max_wait=15)
            )
            account = Account(
                primary_smtp_address=settings['email'],
                config=config,
                autodiscover=False,
                access_type=DELEGATE
            )

        # Try to access inbox to verify
        inbox = account.inbox
        count = inbox.total_count
        return True, f'اتصال موفق! تعداد ایمیل‌های صندوق ورودی: {count}'

    except Exception as e:
        error_msg = str(e)
        if 'autodiscover' in error_msg.lower():
            return False, f'خطا در Autodiscover. آدرس سرور را دستی وارد کنید: {error_msg}'
        elif 'unauthorized' in error_msg.lower() or '401' in error_msg:
            return False, 'نام کاربری یا رمز عبور اشتباه است'
        elif 'certificate' in error_msg.lower() or 'ssl' in error_msg.lower():
            return False, f'خطای SSL/Certificate: {error_msg}'
        else:
            return False, f'خطا در اتصال: {error_msg}'


def fetch_emails(max_count=50, existing_email_ids=None):
    """
    Fetch emails from Exchange inbox with sender filtering.
    Returns list of email dicts compatible with ticket system.
    """
    settings = load_settings()
    if not settings.get('configured'):
        return [], 'تنظیمات ایمیل انجام نشده است'

    if existing_email_ids is None:
        existing_email_ids = set()

    try:
        account = get_exchange_account(settings)
        if account is None:
            return [], 'اتصال به سرور ایمیل برقرار نشد'

        # Get the target folder
        folder_name = settings.get('folder_name', 'Inbox')
        if folder_name == 'Inbox' or not folder_name:
            folder = account.inbox
        else:
            # Try to find subfolder
            try:
                folder = account.inbox / folder_name
            except Exception:
                # Try root folder
                try:
                    folder = account.root / 'Top of Information Store' / folder_name
                except Exception:
                    folder = account.inbox

        # Build query
        sender_filters = settings.get('sender_filters', [])

        # Fetch emails - newest first
        if sender_filters:
            # Filter by sender(s)
            from exchangelib import Q
            q = None
            for sender_email in sender_filters:
                sender_email = sender_email.strip()
                if sender_email:
                    condition = Q(sender=sender_email)
                    q = q | condition if q else condition

            if q:
                items = folder.filter(q).order_by('-datetime_received')[:max_count]
            else:
                items = folder.all().order_by('-datetime_received')[:max_count]
        else:
            items = folder.all().order_by('-datetime_received')[:max_count]

        emails = []
        for item in items:
            try:
                email_id = str(item.message_id or item.id or '')
                # Clean up email_id for use as identifier
                email_id = email_id.replace('<', '').replace('>', '').replace(' ', '_')

                sender_email = ''
                sender_name = ''
                if item.sender:
                    sender_email = item.sender.email_address or ''
                    sender_name = item.sender.name or sender_email

                date_str = ''
                if item.datetime_received:
                    date_str = item.datetime_received.strftime('%Y-%m-%d %H:%M:%S')

                body_text = ''
                if item.text_body:
                    body_text = item.text_body[:2000]  # Limit body length
                elif item.body:
                    body_text = str(item.body)[:2000]

                emails.append({
                    'id': email_id,
                    'subject': item.subject or '(بدون موضوع)',
                    'sender': sender_name or sender_email,
                    'sender_email': sender_email,
                    'body': body_text,
                    'date': date_str,
                    'folder': folder_name,
                    'has_ticket': email_id in existing_email_ids,
                    '_message_id': str(item.message_id or ''),
                    '_item_id': str(item.id or '')
                })
            except Exception as e:
                print(f"Error processing email: {e}")
                continue

        return emails, None

    except Exception as e:
        error_msg = str(e)
        print(f"Email fetch error: {error_msg}")
        return [], f'خطا در دریافت ایمیل‌ها: {error_msg}'


def send_reply(ticket, reply_text, config_text=''):
    """
    Reply to the original email with the given text.
    Returns (success, message)
    """
    settings = load_settings()
    if not settings.get('configured'):
        return False, 'تنظیمات ایمیل انجام نشده است'

    try:
        account = get_exchange_account(settings)
        if account is None:
            return False, 'اتصال به سرور ایمیل برقرار نشد'

        # Create reply message
        # Convert plain text to HTML
        html_body = reply_text.replace('\n', '<br>')
        if config_text:
            html_body += '<br><br><pre style="direction:ltr; font-family:Courier New, monospace; font-size:12px; background:#f5f5f5; padding:10px; border:1px solid #ddd;">'
            html_body += config_text
            html_body += '</pre>'

        reply = Message(
            account=account,
            subject=f"Re: {ticket.get('email_subject', '')}",
            body=HTMLBody(html_body),
            to_recipients=[Mailbox(email_address=ticket.get('email_sender', ''))]
        )

        # Try to find and reply to original message
        original_sent = False
        email_id = ticket.get('email_id', '')

        if email_id:
            try:
                from exchangelib import Q
                # Search for original message
                items = account.inbox.filter(message_id__contains=email_id)[:1]
                for original in items:
                    # Use Exchange reply functionality
                    original.reply(
                        subject=f"Re: {ticket.get('email_subject', '')}",
                        body=HTMLBody(html_body)
                    )
                    original_sent = True
                    break
            except Exception as e:
                print(f"Could not find original email to reply: {e}")

        if not original_sent:
            # Send as new message if original not found
            reply.send()

        return True, 'ریپلای با موفقیت ارسال شد'

    except Exception as e:
        return False, f'خطا در ارسال ریپلای: {str(e)}'

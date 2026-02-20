from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_session import Session
import redis
import imaplib
import smtplib
from email.message import EmailMessage
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import os
import json
import datetime
import bleach
import uuid
import time
import threading
import random
from datetime import datetime, timedelta, timezone
from crypto_utils import security_manager, UserSecurityContext
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'email_mgr_sess:'

# Redis Setup
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
# Used for session storage
app.config['SESSION_REDIS'] = redis.from_url(redis_url)
# Used for data caching
cache_redis = redis.from_url(redis_url)

Session(app)

# Helper to get user context for encryption/decryption
def get_user_context(password):
    # In a real app, store a consistent salt per user in DB. 
    # For now, we derive a deterministic key from the password itself for cache stability across restarts (simplified).
    # Ideally: salt = redis.get(f"salt:{email}")
    # Using a fixed salt for demo purposes allows persistence across restarts without a separate user DB.
    # WARNING: Fixed salt reduces rainbow table protection. OK for demo but use unique salt in prod.
    fixed_salt = b'email_mgr_fixed_salt' 
    return UserSecurityContext(password, fixed_salt)

def get_imap_connection(email_addr, password):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_addr, password)
        return mail
    except Exception as e:
        print(f"IMAP Connection Error: {e}")
        return None

def get_smtp_connection(email_addr, password):
    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(email_addr, password)
        return server
    except Exception as e:
        print(f"SMTP Connection Error: {e}")
        return None

def decode_mime_words(s):
    if not s:
        return ""
    decoded_list = decode_header(s)
    result = []
    for content, encoding in decoded_list:
        if isinstance(content, bytes):
            if encoding:
                try:
                    content = content.decode(encoding)
                except LookupError:
                    content = content.decode('utf-8', errors='replace')
            else:
                content = content.decode('utf-8', errors='replace')
        result.append(content)
    return "".join(result)

def parse_email_content(msg):
    subject = decode_mime_words(msg.get("Subject"))
    sender = decode_mime_words(msg.get("From"))
    date = msg.get("Date")
    parsed_date = None
    if date:
        try:
            parsed_date = parsedate_to_datetime(date).isoformat()
        except:
            parsed_date = str(date)

    body = ""
    html_body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': decode_mime_words(filename),
                        'size': len(part.get_payload(decode=True) or b"")
                    })
                continue
            
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    decoded = payload.decode(errors='replace')
                    if content_type == "text/plain" and not body:
                        body = decoded
                    elif content_type == "text/html" and not html_body:
                        html_body = decoded
            except:
                pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode(errors='replace')
                if msg.get_content_type() == "text/html":
                    html_body = decoded
                else:
                    body = decoded
        except:
            pass

    # Fallback
    if not body and html_body:
        # Strip HTML for preview
        body = bleach.clean(html_body, tags=[], strip=True) 
    
    return {
        'subject': subject,
        'sender': sender,
        'date': parsed_date,
        'snippet': body[:100] + "..." if len(body) > 100 else body,
        'body_text': body,
        'body_html': html_body if html_body else f"<pre>{body}</pre>",
        'attachments': attachments,
        'has_attachments': len(attachments) > 0
    }

@app.route('/')
def login():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    email_addr = request.form.get('email')
    password = request.form.get('password')

    if not email_addr or not password:
        flash("Please provide both email and password.", "error")
        return redirect(url_for('login'))

    mail = get_imap_connection(email_addr, password)
    if mail:
        mail.logout()
        
        nonce, ciphertext = security_manager.encrypt(password)
        
        session['user_email'] = email_addr
        session['enc_password'] = ciphertext.hex()
        session['nonce'] = nonce.hex()
        
        return redirect(url_for('dashboard'))
    else:
        flash("Login failed. Check your email and App Password.", "error")
        return redirect(url_for('login'))

def get_stored_credentials():
    if 'user_email' not in session or 'enc_password' not in session:
        return None, None
    
    email_addr = session['user_email']
    enc_password_hex = session['enc_password']
    nonce_hex = session['nonce']
    
    try:
        password = security_manager.decrypt(
            bytes.fromhex(nonce_hex),
            bytes.fromhex(enc_password_hex)
        )
        return email_addr, password
    except Exception:
        session.clear()
        return None, None

@app.route('/dashboard')
def dashboard():
    email_addr, _ = get_stored_credentials()
    if not email_addr:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=email_addr)

@app.route('/api/emails/<folder>')
def api_emails(folder):
    email_addr, password = get_stored_credentials()
    if not email_addr:
        return jsonify({'error': 'Unauthorized'}), 401

    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 20))
    
    # Map friendly names to IMAP folders
    folder_map = {
        'inbox': 'INBOX',
        'sent': '[Gmail]/Sent Mail',
        'drafts': '[Gmail]/Drafts',
        'trash': '[Gmail]/Trash' 
    }
    imap_folder = folder_map.get(folder.lower(), 'INBOX')

    user_ctx = get_user_context(password)
    cache_key_base = f"email_cache:{email_addr}:{folder}"

    emails = []

    try:
        mail = get_imap_connection(email_addr, password)
        if not mail:
             return jsonify({'error': 'Connection failed'}), 500

        # Quote folder name for IMAP (spaces/special chars in names like [Gmail]/Sent Mail)
        status, _ = mail.select(f'"{imap_folder}"')
        if status != 'OK':
            mail.logout()
            return jsonify({'error': f'Folder {folder} not found'}), 404

        # Use UID search with SINCE filter for speed — only fetch recent emails
        # instead of enumerating the entire 5-year mailbox
        since_date = (datetime.datetime.now() - datetime.timedelta(days=90)).strftime("%d-%b-%Y")
        status, messages = mail.uid('search', None, f'(SINCE "{since_date}")')
        all_uids = messages[0].split() if messages[0] else []

        # If not enough emails in 90 days and user wants more, widen the search
        if len(all_uids) < offset + limit:
            status, messages = mail.uid('search', None, 'ALL')
            all_uids = messages[0].split() if messages[0] else []

        total_emails = len(all_uids)

        # Calculate slice (newest first)
        start = max(0, total_emails - offset - limit)
        end = max(0, total_emails - offset)
        batch_uids = all_uids[start:end][::-1]

        for uid_bytes in batch_uids:
            uid = uid_bytes.decode()
            cache_key = f"{cache_key_base}:{uid}"

            # Check cache
            cached_data = cache_redis.get(cache_key)
            if cached_data:
                try:
                    data = json.loads(cached_data)
                    nonce = bytes.fromhex(data['n'])
                    ciphertext = bytes.fromhex(data['c'])
                    decrypted_json = user_ctx.decrypt(nonce, ciphertext)
                    emails.append(json.loads(decrypted_json))
                    continue
                except:
                    pass

            # Fetch by UID (stable across sessions, unlike sequence numbers)
            try:
                res, msg_data = mail.uid('fetch', uid, '(RFC822)')
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        parsed = parse_email_content(msg)
                        parsed['id'] = uid

                        json_str = json.dumps(parsed)
                        nonce, ciphertext = user_ctx.encrypt(json_str)
                        encrypted_payload = json.dumps({
                            'n': nonce.hex(),
                            'c': ciphertext.hex()
                        })
                        cache_redis.setex(cache_key, 604800, encrypted_payload)

                        emails.append(parsed)
            except Exception as e:
                print(f"Error fetching email UID {uid}: {e}")

        mail.logout()
        return jsonify(emails)

    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/<folder>/<id>')
def api_email_detail(folder, id):
    email_addr, password = get_stored_credentials()
    if not email_addr:
        return jsonify({'error': 'Unauthorized'}), 401

    user_ctx = get_user_context(password)
    cache_key = f"email_cache:{email_addr}:{folder}:{id}"

    # Try cache first
    cached_data = cache_redis.get(cache_key)
    if cached_data:
        try:
            data = json.loads(cached_data)
            nonce = bytes.fromhex(data['n'])
            ciphertext = bytes.fromhex(data['c'])
            decrypted_json = user_ctx.decrypt(nonce, ciphertext)
            return jsonify(json.loads(decrypted_json))
        except Exception:
            pass

    # Fallback: fetch directly from IMAP by UID
    folder_map = {
        'inbox': 'INBOX',
        'sent': '[Gmail]/Sent Mail',
        'drafts': '[Gmail]/Drafts',
        'trash': '[Gmail]/Trash'
    }
    imap_folder = folder_map.get(folder.lower(), 'INBOX')

    try:
        mail = get_imap_connection(email_addr, password)
        if not mail:
            return jsonify({'error': 'Connection failed'}), 500

        mail.select(f'"{imap_folder}"')
        res, msg_data = mail.uid('fetch', id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                parsed = parse_email_content(msg)
                parsed['id'] = id

                # Cache it
                json_str = json.dumps(parsed)
                nonce, ciphertext = user_ctx.encrypt(json_str)
                encrypted_payload = json.dumps({'n': nonce.hex(), 'c': ciphertext.hex()})
                cache_redis.setex(cache_key, 604800, encrypted_payload)

                mail.logout()
                return jsonify(parsed)

        mail.logout()
    except Exception as e:
        print(f"Detail fallback error: {e}")

    return jsonify({'error': 'Email not found'}), 404

@app.route('/send', methods=['POST'])
def send_email():
    email_addr, password = get_stored_credentials()
    if not email_addr:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    # Handle multipart form data
    recipient = request.form.get('to')
    subject = request.form.get('subject')
    body = request.form.get('body')
    files = request.files.getlist('attachments')

    if not recipient or not subject or not body:
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    server = get_smtp_connection(email_addr, password)
    if not server:
        return jsonify({'success': False, 'message': 'SMTP Connection failed'}), 500

    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_addr
        msg['To'] = recipient
        msg.set_content(body)

        # Attach files
        for f in files:
            if f and f.filename:
                file_data = f.read()
                file_name = f.filename
                # Guess mimetype or default
                maintype = 'application' 
                subtype = 'octet-stream'
                msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=file_name)

        server.send_message(msg)
        server.quit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/bulk')
def bulk_send_page():
    email_addr, _ = get_stored_credentials()
    if not email_addr:
        return redirect(url_for('login'))
    return render_template('bulk.html', email=email_addr)

@app.route('/api/bulk-send', methods=['POST'])
def bulk_send():
    email_addr, password = get_stored_credentials()
    if not email_addr:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Invalid request'}), 400

    subject_template = data.get('subject', '')
    html_template = data.get('html_body', '')
    recipients = data.get('recipients', [])
    batch_size = int(data.get('batch_size', 0))
    time_delay = int(data.get('time_delay', 0))
    is_optimum = data.get('optimum_mode', False)

    if not subject_template or not html_template or not recipients:
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    # If simple send (no batching/delay), do it synchronously and return results
    if not is_optimum and batch_size == 0 and time_delay == 0:
        results = send_email_batch(email_addr, password, recipients, subject_template, html_template)
        sent_count = sum(1 for r in results if r['status'] == 'sent')
        return jsonify({
            'success': True,
            'message': f'{sent_count}/{len(recipients)} emails sent',
            'results': results
        })
    elif is_optimum:
        # User requested Optimum Drip Feed
        thread = threading.Thread(target=process_optimum_drip_feed, args=(
            email_addr, password, recipients, subject_template, html_template
        ))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': 'Optimum Drip Feed started. This may take days depending on list size.',
            'results': [] 
        })
    else:
        # Background send (Manual Batch)
        thread = threading.Thread(target=process_background_batch, args=(
            email_addr, password, recipients, subject_template, html_template, batch_size, time_delay
        ))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': 'Background sending started. Emails will be sent in batches.',
            'results': [] 
        })

def get_arizona_time():
    # Arizona is UTC-7 all year round (MST)
    return datetime.now(timezone.utc) - timedelta(hours=7)

def process_optimum_drip_feed(email_addr, password, recipients, subject_template, html_template):
    # Limits
    DAILY_LIMIT = 45 # Safely between 40-50
    # Hourly is implicit by the 8-15 min delay (4-7 per hour)
    
    total = len(recipients)
    sent_today = 0
    current_day_str = get_arizona_time().strftime('%Y-%m-%d')
    
    i = 0
    while i < total:
        now_az = get_arizona_time()
        
        # 1. Check Weekend (0=Mon, 6=Sun)
        if now_az.weekday() >= 5: # Saturday or Sunday
            # Sleep until Monday 9:00 AM
            # Calculate seconds until next Monday 9am
            days_ahead = 7 - now_az.weekday() # If Sat(5) -> 2 days. If Sun(6) -> 1 day.
            next_monday = (now_az + timedelta(days=days_ahead)).replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (next_monday - now_az).total_seconds()
            print(f"Weekend pause. Sleeping {sleep_seconds}s until Monday.")
            time.sleep(max(60, sleep_seconds))
            continue
            
        # 2. Check Daily Limit
        today_str = now_az.strftime('%Y-%m-%d')
        if today_str != current_day_str:
            # New day, reset counter
            current_day_str = today_str
            sent_today = 0
            
        if sent_today >= DAILY_LIMIT:
            # Sleep until tomorrow 9:00 AM
            tomorrow = (now_az + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (tomorrow - now_az).total_seconds()
            print(f"Daily limit reached ({DAILY_LIMIT}). Sleeping {sleep_seconds}s until tomorrow.")
            time.sleep(max(60, sleep_seconds))
            continue
            
        # 3. Check Time Window (9 AM - 5 PM)
        current_hour = now_az.hour
        if current_hour < 9:
            # Too early, sleep until 9 AM
            start_time = now_az.replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (start_time - now_az).total_seconds()
            print(f"Too early. Sleeping {sleep_seconds}s until 9 AM.")
            time.sleep(max(60, sleep_seconds))
            continue
        elif current_hour >= 17:
             # Too late, sleep until tomorrow 9 AM
            tomorrow = (now_az + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (tomorrow - now_az).total_seconds()
            print(f"Too late (After 5 PM). Sleeping {sleep_seconds}s until tomorrow.")
            time.sleep(max(60, sleep_seconds))
            continue
            
        # 4. Ready to Send
        recipient = recipients[i]
        # Send single email
        send_email_batch(email_addr, password, [recipient], subject_template, html_template)
        
        i += 1
        sent_today += 1
        
        # 5. Delay Confirmation (User Notice: 8-15 mins)
        if i < total:
            # Random delay 480s (8m) to 900s (15m)
            delay = random.randint(480, 900)
            print(f"Sent {i}/{total}. Sleeping {delay}s...")
            time.sleep(delay)

def process_background_batch(email_addr, password, recipients, subject_template, html_template, batch_size, time_delay):
    total = len(recipients)
    # If batch_size is 0 (all at once) but delay is set, treat as one big batch (or invalid combination? 
    # User said "0 being all at once". If delay is set but batch is 0, it just sends all at once instantly. 
    # The delay only applies BETWEEN batches. So effectively immediate.)
    if batch_size <= 0:
        batch_size = total
        
    for i in range(0, total, batch_size):
        batch = recipients[i : i + batch_size]
        
        # Connect fresh for each batch
        # We process the batch synchronously
        send_email_batch(email_addr, password, batch, subject_template, html_template)
        
        # Wait if there are more batches
        if i + batch_size < total:
            time.sleep(time_delay * 60)

def send_email_batch(email_addr, password, recipient_list, subject_template, html_template):
    server = get_smtp_connection(email_addr, password)
    results = []
    if not server:
        # If connection fails, mark all in this batch as failed
        for r in recipient_list:
            results.append({'email': r.get('email'), 'status': 'failed', 'message': 'SMTP Connection failed'})
        return results

    try:
        for recipient in recipient_list:
            to_email = recipient.get('email', '').strip()
            if not to_email:
                results.append({'email': to_email, 'status': 'skipped', 'message': 'No email'})
                continue

            # Replace template variables
            subject = subject_template
            body = html_template
            for key, value in recipient.items():
                placeholder = '{{' + key + '}}'
                subject = subject.replace(placeholder, str(value))
                body = body.replace(placeholder, str(value))

            try:
                msg = EmailMessage()
                msg['Subject'] = subject
                msg['From'] = email_addr
                msg['To'] = to_email
                msg.set_content(body, subtype='html')

                server.send_message(msg)
                results.append({'email': to_email, 'status': 'sent'})
                del msg
            except Exception as e:
                results.append({'email': to_email, 'status': 'failed', 'message': str(e)})

        server.quit()
    except Exception as e:
        # If server loop crashes
        pass
        
    return results

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=80, debug=True)
    except PermissionError:
        print("Permission denied on port 80. Trying 8080.")
        app.run(host='0.0.0.0', port=8080, debug=True)

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
import csv
import io
from datetime import datetime, timedelta, timezone
from crypto_utils import security_manager, UserSecurityContext
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# --- JOB MANAGER ---
class JobManager:
    def __init__(self):
        # We use the same Redis URL as the session
        self.redis = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379'))
        self.lock = threading.Lock()

    def _save_job(self, job):
        self.redis.set(f"job:{job['id']}", json.dumps(job))

    def _load_job(self, job_id):
        data = self.redis.get(f"job:{job_id}")
        return json.loads(data) if data else None

    def create_job(self, job_type, recipients, details=None):
        job_id = str(uuid.uuid4())
        # Initialize recipients
        for r in recipients:
            r['send_status'] = 'queued'
            r['send_time'] = None
            
        job = {
            'id': job_id,
            'type': job_type,
            'recipients': recipients,
            'total': len(recipients),
            'sent': 0,
            'failed': 0,
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'last_update': datetime.now().isoformat(),
            'last_email_sent': None,
            'estimated_completion': 'Calculating...',
            'details': details or {}
        }
        with self.lock:
            self._save_job(job)
        return job_id

    def set_status(self, job_id, status):
        with self.lock:
            job = self._load_job(job_id)
            if job:
                job['status'] = status
                job['last_update'] = datetime.now().isoformat()
                self._save_job(job)

    def get_status(self, job_id):
        # No lock needed for simple read usually, but good practice
        job = self._load_job(job_id)
        return job.get('status') if job else None

    def get_job(self, job_id):
        return self._load_job(job_id)

    def mark_recipient(self, job_id, index, status, error=None):
        with self.lock:
            job = self._load_job(job_id)
            if job and index < len(job['recipients']):
                rec = job['recipients'][index]
                rec['send_status'] = status
                rec['send_time'] = datetime.now().isoformat()
                if error:
                    rec['error'] = error
                
                if status == 'sent':
                    job['last_email_sent'] = {
                        'email': rec.get('email'),
                        'time': datetime.now().strftime('%I:%M %p')
                    }
                self._save_job(job)

    def update_progress(self, job_id, sent_inc=0, failed_inc=0, status=None):
        with self.lock:
            job = self._load_job(job_id)
            if job:
                job['sent'] += sent_inc
                job['failed'] += failed_inc
                job['last_update'] = datetime.now().isoformat()
                
                if status:
                    job['status'] = status
                
                # Estimate
                if job['status'] == 'running' and job['sent'] > 0:
                    try:
                        start = datetime.fromisoformat(job['start_time'])
                        elapsed = (datetime.now() - start).total_seconds()
                        avg = elapsed / job['sent']
                        remaining = job['total'] - (job['sent'] + job['failed'])
                        if remaining > 0:
                            est_sec = remaining * avg
                            if est_sec > 86400: job['estimated_completion'] = f"{int(est_sec/86400)} days"
                            elif est_sec > 3600: job['estimated_completion'] = f"{int(est_sec/3600)} hours"
                            elif est_sec > 60: job['estimated_completion'] = f"{int(est_sec/60)} mins"
                            else: job['estimated_completion'] = f"{int(est_sec)} secs"
                    except:
                        pass
                
                self._save_job(job)

    def get_user_jobs(self, email):
        user_jobs = []
        # Scan for jobs (in prod use a set per user)
        # For this scale, keys scan is okay
        keys = self.redis.keys("job:*")
        
        for k in keys:
            try:
                data = self.redis.get(k)
                if data:
                    job = json.loads(data)
                    if job['details'].get('user') == email:
                         # Calculate %
                        processed = job['sent'] + job['failed']
                        pct = int((processed / job['total']) * 100) if job['total'] > 0 else 0
                        
                        j_copy = {k: v for k, v in job.items() if k != 'recipients'}
                        j_copy['percent'] = pct
                        user_jobs.append(j_copy)
            except:
                continue
                
        return user_jobs
        
    def generate_csv(self, job_id, filter_type):
        job = self._load_job(job_id)
        if not job: return None
        
        recipients = job['recipients']
        output = io.StringIO()
        if not recipients: return ""
            
        keys = list(recipients[0].keys())
        if 'send_status' not in keys: keys.append('send_status')
        if 'send_time' not in keys: keys.append('send_time')
        if 'error' not in keys: keys.append('error')
        
        writer = csv.DictWriter(output, fieldnames=keys)
        writer.writeheader()
        
        for r in recipients:
            status = r.get('send_status', 'queued')
            include = False
            if filter_type == 'all': include = True
            elif filter_type == 'sent' and status == 'sent': include = True
            elif filter_type == 'failed' and status == 'failed': include = True
            elif filter_type == 'remaining' and status == 'queued': include = True
            
            if include:
                row = {k: r.get(k, '') for k in keys}
                writer.writerow(row)
                
        return output.getvalue()
        
    def restore_active_jobs(self):
        # Find jobs that were 'running' or 'paused' and restart their threads if needed
        # Actually we only auto-restart 'running' ones. 'paused' stay paused.
        keys = self.redis.keys("job:*")
        count = 0
        for k in keys:
            try:
                data = self.redis.get(k)
                job = json.loads(data)
                if job['status'] == 'running' or job['status'].startswith('Wait') or job['status'].startswith('Paused ('):
                    # It was active. We need to respawn the thread.
                    # Note: "Paused (Weekend)" is technically a running state waiting for time, versus "paused" (user action).
                    # If it was user-paused ('paused'), we leave it.
                    
                    if job['status'] == 'paused': continue
                    
                    # Reset status to running to re-trigger loops logic safely
                    self.set_status(job['id'], 'running')
                    
                    user_email = job['details'].get('user')
                    # We need the password... stored in session which is lost?
                    # The user encryption key is derived from password.
                    # We cannot resume without the password if we don't store it reversibly.
                    # BUT, for the demo, we are using session.
                    # Limit: If server restarts, memory threads die. We need password to resume sending.
                    # We don't have the user's password in Redis (only encrypted).
                    # We'd need to store the password encrypted with a system key to auto-resume headless.
                    # For this scope: We will mark them as "Paused (Server Restarted)" so user can resume.
                    
                    self.set_status(job['id'], 'paused')
                    # We can't actually auto-resume without the password/credentials.
                    # So we allow the user to Resume via UI? 
                    # The UI 'Resume' checks session credentials. Perfect.
                    count += 1
            except:
                pass
        if count > 0:
            print(f"Restored {count} jobs to PAUSED state (require user resume).")

job_manager = JobManager()
# Attempt restore (will just mark them paused so user can resume)
job_manager.restore_active_jobs()

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
        since_date = (datetime.now() - timedelta(days=90)).strftime("%d-%b-%Y")
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

@app.route('/history')
def history():
    email_addr, _ = get_stored_credentials()
    if not email_addr:
        return redirect(url_for('login'))
    return render_template('history.html', email=email_addr)

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
        # Save HTML template in details for resume support
        job_id = job_manager.create_job('Optimum Drip', recipients, {
            'user': email_addr, 
            'subject': subject_template,
            'html_body': html_template 
        })
        
        thread = threading.Thread(target=process_optimum_drip_feed, args=(
            job_id, email_addr, password, subject_template, html_template
        ))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': 'Optimum Drip Feed started.',
        })
    else:
        # Background send (Manual Batch)
        job_id = job_manager.create_job('Batch Send', recipients, {
            'user': email_addr, 
            'subject': subject_template,
            'html_body': html_template,
            'batch_size': batch_size,
            'time_delay': time_delay
        })

        thread = threading.Thread(target=process_background_batch, args=(
            job_id, email_addr, password, subject_template, html_template, batch_size, time_delay
        ))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': 'Background sending started.',
        })

@app.route('/api/jobs/<job_id>/action', methods=['POST'])
def job_action(job_id):
    email_addr, password = get_stored_credentials()
    if not email_addr: return jsonify({'error': 'Unauthorized'}), 401
    
    action = request.json.get('action')
    if action == 'pause':
        job_manager.set_status(job_id, 'paused')
        
    elif action == 'cancel':
        job_manager.set_status(job_id, 'cancelled')
        
    elif action == 'resume':
        # To resume, we need to restart the thread if it's dead
        # We need to know if it's optimum or batch
        job = job_manager.get_job(job_id)
        if not job: return jsonify({'error': 'Job not found'}), 404
        
        # Check if already running? 
        # Actually set_status sets it to running, but if the thread died (due to server restart), we need to respawn.
        # The worker functions handle 'resuming' by skipping already sent.
        
        job_manager.set_status(job_id, 'running')
        
        subject_template = job['details'].get('subject')
        # We need html_body... stored in details? We didn't store it.
        # FIX: We need to store html_template in job details or arguments to resume properly.
        # For now, we unfortunately can't resume fully without the template if it wasn't saved.
        # Let's assume we update create_job to save the template too.
        # But wait, create_job call didn't save html_template.
        # Update: We will add html_template to details in create_job calls below.
        html_template = job['details'].get('html_body', '')
        
        # Determine type
        if job['type'] == 'Optimum Drip':
             thread = threading.Thread(target=process_optimum_drip_feed, args=(
                job_id, email_addr, password, subject_template, html_template
            ))
             thread.daemon = True
             thread.start()
        else:
             # Batch
             # default batch args? We didn't save them either.
             # Assume defaults or save them.
             batch_size = job['details'].get('batch_size', 0)
             time_delay = job['details'].get('time_delay', 0)
             thread = threading.Thread(target=process_background_batch, args=(
                job_id, email_addr, password, subject_template, html_template, batch_size, time_delay
            ))
             thread.daemon = True
             thread.start()
    
    return jsonify({'success': True})

@app.route('/api/jobs/<job_id>/export/<filter_type>')
def job_export(job_id, filter_type):
    email_addr, _ = get_stored_credentials()
    if not email_addr: return "Unauthorized", 401
    
    csv_data = job_manager.generate_csv(job_id, filter_type)
    if csv_data is None:
        return "Job not found", 404
        
    return jsonify({'csv': csv_data, 'filename': f'job_{job_id}_{filter_type}.csv'})

@app.route('/api/jobs')
def api_jobs():
    email_addr, _ = get_stored_credentials()
    if not email_addr:
        return jsonify({'jobs': []})
        
    jobs = job_manager.get_user_jobs(email_addr)
    # Sort running first, then newest
    jobs.sort(key=lambda x: (x['status'] != 'running', x['start_time']), reverse=True) 
    return jsonify({'jobs': jobs})

def get_arizona_time():
    # Arizona is UTC-7 all year round (MST)
    return datetime.now(timezone.utc) - timedelta(hours=7)

def process_optimum_drip_feed(job_id, email_addr, password, subject_template, html_template):
    job = job_manager.get_job(job_id)
    if not job: return
    recipients = job['recipients']
    total = len(recipients)
    DAILY_LIMIT = 45 
    
    # Check if we are resuming (find first non-sent/failed)
    start_index = 0
    for idx, r in enumerate(recipients):
        if r['send_status'] == 'queued':
            start_index = idx
            break
            
    sent_today = 0
    current_day_str = get_arizona_time().strftime('%Y-%m-%d')
    
    i = start_index
    while i < total:
        # 0. Check Status (Pause/Cancel)
        status = job_manager.get_status(job_id)
        if status == 'paused':
            time.sleep(2)
            continue
        if status == 'cancelled':
            break
            
        now_az = get_arizona_time()
        
        # 1. Check Weekend
        if now_az.weekday() >= 5: 
            days_ahead = 7 - now_az.weekday()
            next_monday = (now_az + timedelta(days=days_ahead)).replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (next_monday - now_az).total_seconds()
            
            job_manager.update_progress(job_id, status=f"Paused (Weekend). Resuming Mon 9am.")
            time.sleep(max(60, sleep_seconds))
            job_manager.update_progress(job_id, status="running")
            continue
            
        # 2. Check Daily Limit
        today_str = now_az.strftime('%Y-%m-%d')
        if today_str != current_day_str:
            current_day_str = today_str
            sent_today = 0
            
        if sent_today >= DAILY_LIMIT:
            tomorrow = (now_az + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (tomorrow - now_az).total_seconds()
            
            job_manager.update_progress(job_id, status=f"Paused (Daily Limit). Resuming {tomorrow.strftime('%a 9am')}")
            time.sleep(max(60, sleep_seconds))
            job_manager.update_progress(job_id, status="running")
            continue
            
        # 3. Check Time Window
        current_hour = now_az.hour
        if current_hour < 9:
            start_time = now_az.replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (start_time - now_az).total_seconds()
            
            job_manager.update_progress(job_id, status="Paused (Outside Hours). Resuming 9am.")
            time.sleep(max(60, sleep_seconds))
            job_manager.update_progress(job_id, status="running")
            continue
        elif current_hour >= 17:
            tomorrow = (now_az + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
            sleep_seconds = (tomorrow - now_az).total_seconds()
            
            job_manager.update_progress(job_id, status="Paused (Outside Hours). Resuming 9am.")
            time.sleep(max(60, sleep_seconds))
            job_manager.update_progress(job_id, status="running")
            continue
            
        # 4. SEND
        recipient = recipients[i]
        res = send_email_batch(email_addr, password, [recipient], subject_template, html_template)
        
        success = 1 if res and res[0]['status'] == 'sent' else 0
        fail = 1 - success
        
        status_code = 'sent' if success else 'failed'
        error_msg = res[0].get('message') if fail else None
        
        job_manager.mark_recipient(job_id, i, status_code, error_msg)
        job_manager.update_progress(job_id, sent_inc=success, failed_inc=fail)
        
        i += 1
        sent_today += 1
        
        # 5. Delay
        if i < total:
            delay = random.randint(480, 900)
            # Update estimated time manually for accurate 'Wait state'
            job_manager.jobs[job_id]['estimated_completion'] = f"Wait {int(delay/60)}m..."
            
            # Sleep in small chunks to allow pause/cancel interrupt
            sleep_chunks = int(delay / 2)
            for _ in range(sleep_chunks):
                if job_manager.get_status(job_id) in ['paused', 'cancelled']: break
                time.sleep(2)
            
    if job_manager.get_status(job_id) != 'cancelled':
        job_manager.update_progress(job_id, status='completed')

def process_background_batch(job_id, email_addr, password, subject_template, html_template, batch_size, time_delay):
    job = job_manager.get_job(job_id)
    if not job: return
    recipients = job['recipients']
    total = len(recipients)
    if batch_size <= 0:
        batch_size = total
        
    i = 0
    # Resume logic if needed (check first queued)
    for idx, r in enumerate(recipients):
        if r['send_status'] == 'queued':
            i = idx
            break
            
    while i < total:
        # Check Status
        status = job_manager.get_status(job_id)
        if status == 'paused':
            time.sleep(2)
            continue
        if status == 'cancelled':
            break

        # Calculate batch end
        batch_end = min(i + batch_size, total)
        batch = recipients[i : batch_end]
        
        # Filter only queued in this range (in case of weird resume state)
        batch_to_send = [r for r in batch if r.get('send_status') == 'queued']
        
        if batch_to_send:
            res = send_email_batch(email_addr, password, batch_to_send, subject_template, html_template)
            
            # Map results back to update status
            success_count = 0
            fail_count = 0
            
            for res_item in res:
                # Find matching recipient in original list by email (assuming unique emails in batch)
                # Or better, rely on order if send_email_batch preserves it (it does)
                # But safer to match by email
                target_email = res_item.get('email')
                found_idx = -1
                for bi in range(i, batch_end):
                    if recipients[bi]['email'] == target_email:
                        found_idx = bi
                        break
                
                if found_idx != -1:
                    status_code = res_item['status'] # sent/failed/skipped
                    error_msg = res_item.get('message')
                    job_manager.mark_recipient(job_id, found_idx, status_code, error_msg)
                    
                    if status_code == 'sent': success_count += 1
                    elif status_code == 'failed': fail_count += 1
            
            job_manager.update_progress(job_id, sent_inc=success_count, failed_inc=fail_count)
        
        i += batch_size
        
        # Wait if there are more batches
        if i < total:
            with job_manager.lock:
                _job = job_manager._load_job(job_id)
                if _job:
                    _job['estimated_completion'] = f"Wait {time_delay}m..."
                    job_manager._save_job(_job)
            # Sleep in chunks to allow iterrupt
            sleep_chunks = int(time_delay * 60 / 2)
            for _ in range(sleep_chunks):
                 if job_manager.get_status(job_id) in ['paused', 'cancelled']: break
                 time.sleep(2)
            
    if job_manager.get_status(job_id) != 'cancelled':
        job_manager.update_progress(job_id, status='completed')

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

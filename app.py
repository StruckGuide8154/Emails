from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_session import Session
import redis
import imaplib
import smtplib
from email.message import EmailMessage
import email
from email.header import decode_header
import os
import json
import datetime
from crypto_utils import security_manager

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'email_mgr:'

# Redis Setup
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['SESSION_REDIS'] = redis.from_url(redis_url)

Session(app)

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

    # Validate against IMAP
    mail = get_imap_connection(email_addr, password)
    if mail:
        mail.logout()
        
        # Encrypt and store in session (which is stored in Redis)
        # We store the encrypted bytes as hex strings to be JSON serializable
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
    email_addr, password = get_stored_credentials()
    if not email_addr:
        return redirect(url_for('login'))
        
    return render_template('dashboard.html', email=email_addr)

@app.route('/api/emails')
def api_emails():
    email_addr, password = get_stored_credentials()
    if not email_addr:
        return jsonify({'error': 'Unauthorized'}), 401

    mail = get_imap_connection(email_addr, password)
    if not mail:
        return jsonify({'error': 'Connection failed'}), 500

    try:
        mail.select("inbox")
        # Fetch last 20 emails
        status, messages = mail.search(None, "ALL")
        mail_ids = messages[0].split()
        latest_ids = mail_ids[-20:]
        
        email_list = []
        for i in reversed(latest_ids):
            res, msg_data = mail.fetch(i, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = decode_mime_words(msg.get("Subject"))
                    sender = decode_mime_words(msg.get("From"))
                    date = msg.get("Date")
                    
                    # Simple body extraction (prefer text/plain)
                    body = "No content"
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                try:
                                    body = part.get_payload(decode=True).decode()
                                except:
                                    body = "Could not decode body"
                                break
                    else:
                        try:
                            body = msg.get_payload(decode=True).decode()
                        except:
                            body = "Could not decode body"

                    email_list.append({
                        'id': i.decode(),
                        'subject': subject,
                        'sender': sender,
                        'date': date,
                        'snippet': body[:100] + "..." if len(body) > 100 else body
                    })
        mail.logout()
        return jsonify(email_list)
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/send', methods=['POST'])
def send_email():
    email_addr, password = get_stored_credentials()
    if not email_addr:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.json
    recipient = data.get('to')
    subject = data.get('subject')
    body = data.get('body')

    if not recipient or not subject or not body:
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    server = get_smtp_connection(email_addr, password)
    if not server:
        return jsonify({'success': False, 'message': 'SMTP Connection failed'}), 500

    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = email_addr
        msg['To'] = recipient

        server.send_message(msg)
        server.quit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Run on 0.0.0.0:80 as requested
    # Note: Requires admin privileges on many OSs
    try:
        app.run(host='0.0.0.0', port=80, debug=True)
    except PermissionError:
        print("Permission denied on port 80. Trying 8080.")
        app.run(host='0.0.0.0', port=8080, debug=True)

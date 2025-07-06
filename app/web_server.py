import os
import json
import datetime
import logging
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, Response, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from app.email_client import get_email_client
from app.models import db, User, LinkedAccount

# --- Google OAuth Imports ---
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.auth.transport.requests

# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "a-very-secure-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper Functions ---
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

# --- Main Routes (Landing, Auth, Dashboard) ---
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first() # type: ignore
        if user is None or not user.check_password(password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    email = request.form.get('email')
    password = request.form.get('password')
    
    if User.query.filter_by(email=email).first():
        flash('Email address already registered.', 'error')
        return redirect(url_for('login'))
        
    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
    
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# --- Google OAuth Routes ---
@app.route('/login/google')
@login_required
def google_login():
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly'],
        redirect_uri=url_for('oauth2callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        'client_secret.json', scopes=['https://www.googleapis.com/auth/gmail.readonly'],
        state=state, redirect_uri=url_for('oauth2callback', _external=True))
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    service = build('gmail', 'v1', credentials=credentials)
    profile = service.users().getProfile(userId='me').execute()
    email_address = profile['emailAddress']

    # Check if this email is already linked
    existing_account = LinkedAccount.query.filter_by(email_address=email_address, user_id=current_user.id).first() # type: ignore
    if existing_account:
        # Update credentials
        existing_account.credentials = json.dumps(credentials_to_dict(credentials))
    else:
        # Create new linked account
        new_account = LinkedAccount(
            user_id=current_user.id, # type: ignore
            email_address=email_address, # type: ignore
            provider="gmail", # type: ignore
            credentials=json.dumps(credentials_to_dict(credentials)) # type: ignore
        )
        db.session.add(new_account)
    
    db.session.commit()
    return redirect(url_for('dashboard'))

# --- API Endpoints for Account Management ---
@app.route('/api/accounts', methods=['GET'])
@login_required
def get_accounts():
    accounts = LinkedAccount.query.filter_by(user_id=current_user.id).all()
    safe_accounts = {
        acc.email_address: {"provider": acc.provider, "imap_server": acc.imap_server} for acc in accounts
    }
    return jsonify(safe_accounts)

@app.route('/api/accounts', methods=['POST'])
@login_required
def add_account():
    data = request.get_json() or {}
    email = data.get('email_address')
    if not email:
        return jsonify({"status": "ERROR", "message": "Email address is required."}), 400
    
    new_account = LinkedAccount(
        user_id=current_user.id, # type: ignore
        email_address=email, # type: ignore
        provider=data.get("provider"), # type: ignore
        imap_server=data.get("imap_server"), # type: ignore
        credentials=json.dumps({"password": data.get("password")}) # Encrypt this in a real app
    )
    db.session.add(new_account)
    db.session.commit()
    return jsonify({"status": "OK", "message": f"Account {email} saved."})

@app.route('/api/accounts/update', methods=['POST'])
@login_required
def update_account():
    data = request.get_json() or {}
    email = data.get('email_address')
    account = LinkedAccount.query.filter_by(email_address=email, user_id=current_user.id).first_or_404() # type: ignore
    
    if data.get('password'):
        account.credentials = json.dumps({"password": data.get("password")}) # Encrypt this
    
    db.session.commit()
    return jsonify({"status": "OK", "message": f"Account {email} updated."})

@app.route('/api/accounts/delete', methods=['POST'])
@login_required
def delete_account():
    data = request.get_json() or {}
    email = data.get('email_address')
    account = LinkedAccount.query.filter_by(email_address=email, user_id=current_user.id).first_or_404() # type: ignore
    db.session.delete(account)
    db.session.commit()
    return jsonify({"status": "OK", "message": f"Account {email} deleted."})

@app.route('/api/test_connection', methods=['POST'])
@login_required
def test_connection():
    data = request.get_json() or {}
    try:
        client = get_email_client(
            data['provider'], data['email_address'], data.get('password'), data.get('imap_server')
        )
        client.connect()
        client.logout()
        return jsonify({"status": "OK", "message": "Connection successful!"})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# --- API Endpoints for Scanning & Results ---
@app.route('/api/results', methods=['POST'])
@login_required
def get_results():
    email_address = request.json.get('email_address')
    account = LinkedAccount.query.filter_by(email_address=email_address, user_id=current_user.id).first_or_404() # type: ignore
    
    links = json.loads(account.scan_results) if account.scan_results else {}
    history = json.loads(account.scan_history) if account.scan_history else []
    
    return jsonify({'links': links, 'scan_history': history})

@app.route('/api/unsubscribed', methods=['POST'])
@login_required
def get_unsubscribed_links():
    email_address = request.json.get('email_address')
    account = LinkedAccount.query.filter_by(email_address=email_address, user_id=current_user.id).first_or_404() # type: ignore
    
    log = json.loads(account.unsubscribed_log) if account.unsubscribed_log else {}
    return jsonify(log.get(email_address, {}))

@app.route('/api/unsubscribe', methods=['POST'])
@login_required
def log_unsubscribe():
    data = request.json
    email_address = data.get('email_address')
    link_href = data.get('href')
    account = LinkedAccount.query.filter_by(email_address=email_address, user_id=current_user.id).first_or_404() # type: ignore

    logs = json.loads(account.unsubscribed_log) if account.unsubscribed_log else {}
    if email_address not in logs:
        logs[email_address] = {}
        
    logs[email_address][link_href] = {
        "unsubscribed_date": datetime.datetime.utcnow().isoformat()
    }
    account.unsubscribed_log = json.dumps(logs)
    db.session.commit()
    return jsonify({"status": "OK"})

@app.route('/scan')
@login_required
def scan():
    email_address = request.args.get('email_address')
    num_emails_str = request.args.get('num_emails')
    since_date_str = request.args.get('since_date')
    
    account = LinkedAccount.query.filter_by(email_address=email_address, user_id=current_user.id).first_or_404() # type: ignore

    def generate_scan_progress():
        with app.app_context():
            try:
                creds_dict = json.loads(account.credentials) if account.credentials else {}
                
                if account.provider == 'gmail':
                    password_or_creds = creds_dict
                else:
                    password_or_creds = creds_dict.get('password')

                client = get_email_client(
                    account.provider, 
                    account.email_address, 
                    password_or_creds, 
                    account.imap_server
                )
                client.connect()

                scan_params = {}
                if num_emails_str:
                    scan_params['num_emails'] = int(num_emails_str)
                if since_date_str:
                    scan_params['since_date'] = since_date_str

                existing_results = json.loads(account.scan_results) if account.scan_results else {}
                
                total_new_links = 0
                for progress_update in client.scan_emails(**scan_params):
                    if not isinstance(progress_update, dict):
                        logging.warning(f"Received non-dict progress update: {progress_update}")
                        continue

                    if 'links' in progress_update: # Final update
                        new_links = progress_update.get('links', {})
                        # Merge results
                        for domain, links_list in new_links.items():
                            if domain not in existing_results:
                                existing_results[domain] = []
                            
                            existing_hrefs = {link['href'] for link in existing_results[domain]}
                            for link in links_list:
                                if link['href'] not in existing_hrefs:
                                    existing_results[domain].append(link)
                                    total_new_links +=1
                        
                        account.scan_results = json.dumps(existing_results)

                        # Update scan history
                        history = json.loads(account.scan_history) if account.scan_history else []
                        scan_entry = {
                            "scan_date": datetime.datetime.utcnow().isoformat(),
                            "description": progress_update.get("description"),
                            "date_range": progress_update.get("date_range"),
                            "new_links_found": total_new_links
                        }
                        history.append(scan_entry)
                        account.scan_history = json.dumps(history)
                        
                        db.session.commit()
                        
                        progress_update['links'] = existing_results
                        progress_update['scan_history'] = history
                        yield f"data: {json.dumps(progress_update)}\n\n"
                    else:
                        yield f"data: {json.dumps(progress_update)}\n\n"
                
                client.logout()

            except Exception as e:
                logging.error(f"Error during scan for {email_address}: {e}", exc_info=True)
                yield f'data: {json.dumps({"error": str(e)})}\n\n'

    return Response(generate_scan_progress(), mimetype='text/event-stream')

def run():
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=5001)

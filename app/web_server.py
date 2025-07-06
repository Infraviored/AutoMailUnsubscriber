from flask import Flask, render_template, jsonify, request, send_from_directory, redirect, url_for, session, Response
from app.email_client import get_email_client
import json
import os
import datetime
import logging

# --- Google OAuth Imports ---
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.auth.transport.requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "a-secure-secret-key-for-sessions") # For session
ACCOUNTS_FILE = 'accounts.json'  # Renamed from credentials.json
RESULTS_FILE = 'scan_results.json'
UNSUBSCRIBE_LINKS_FILE = 'unsubscribe_links.html'
UNSUBSCRIBED_LOG_FILE = 'unsubscribed_links.json'

def load_data(filepath, default=None):
    if default is None:
        default = {}
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        with open(filepath, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return default
    return default

def save_data(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def load_scan_results():
    if os.path.exists(RESULTS_FILE) and os.path.getsize(RESULTS_FILE) > 0:
        with open(RESULTS_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {"last_scan_time": None, "last_uid": None, "links": {}}
    return {"last_scan_time": None, "last_uid": None, "links": {}}

def save_scan_results(data):
    with open(RESULTS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def load_unsubscribed_log():
    if os.path.exists(UNSUBSCRIBED_LOG_FILE):
        if os.path.getsize(UNSUBSCRIBED_LOG_FILE) == 0:
            return {}
        with open(UNSUBSCRIBED_LOG_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_unsubscribed_log(data):
    with open(UNSUBSCRIBED_LOG_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def load_credentials():
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_credentials(data):
    with open(ACCOUNTS_FILE, 'w') as f:
        json.dump(data, f)

def append_links_to_file(links):
    # This function is now more complex to handle the table structure
    # and avoid duplicating entries if the scan is run multiple times.
    
    # We'll read the existing file to avoid overwriting, and just append new domains/links
    
    # A simple append is difficult with a proper HTML structure,
    # so for now we will just overwrite the file with the latest scan's results.
    # A more robust solution would be to parse the HTML and merge.
    
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Unsubscribe Links</title>
    <style>
        body { font-family: sans-serif; margin: 2em; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>All Unsubscribe Links Found</h1>
"""
    
    for domain, domain_links in links.items():
        html_content += f'<h2>{domain}</h2>\n'
        html_content += '<table>\n'
        html_content += '<tr><th>Received</th><th>Subject</th><th>Link</th></tr>\n'
        for link_data in domain_links:
            date_str = link_data.get('date', 'N/A')
            if date_str and date_str != 'N/A':
                date_str = datetime.datetime.fromisoformat(date_str).strftime('%Y-%m-%d %H:%M')
            
            subject = link_data.get('subject', 'No Subject')
            text = link_data.get('text', 'Link')
            href = link_data.get('href', '#')
            
            html_content += f'<tr><td>{date_str}</td><td>{subject}</td><td><a href="{href}" target="_blank">{text}</a></td></tr>\n'
        html_content += '</table>\n'

    html_content += "</body></html>"
    
    with open(UNSUBSCRIBE_LINKS_FILE, 'w', encoding='utf-8') as f:
        f.write(html_content)

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

@app.route('/login/google')
def google_login():
    # This allows http for local development.
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly'],
        redirect_uri=url_for('oauth2callback', _external=True))
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']

    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly'],
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True))

    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials

    # Get user's email address
    service = build('gmail', 'v1', credentials=credentials)
    profile = service.users().getProfile(userId='me').execute()
    email_address = profile['emailAddress']

    accounts = load_data(ACCOUNTS_FILE)
    accounts[email_address] = {
        "provider": "gmail",
        "credentials": credentials_to_dict(credentials)
    }
    save_data(ACCOUNTS_FILE, accounts)

    return redirect(url_for('index'))

@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    accounts = load_data(ACCOUNTS_FILE)
    # Return accounts without passwords for security
    safe_accounts = {email: {"provider": data.get("provider")} for email, data in accounts.items()}
    return jsonify(safe_accounts)

@app.route('/api/accounts', methods=['POST'])
def add_account():
    data = request.get_json() or {}
    email = data.get('email_address')
    if not email:
        return jsonify({"status": "ERROR", "message": "Email address is required."}), 400
    
    accounts = load_data(ACCOUNTS_FILE)
    accounts[email] = {
        "provider": data.get("provider"),
        "password": data.get("password"),
        "imap_server": data.get("imap_server")
    }
    save_data(ACCOUNTS_FILE, accounts)
    return jsonify({"status": "OK", "message": f"Account {email} saved."})

@app.route('/api/accounts/update', methods=['POST'])
def update_account():
    data = request.get_json() or {}
    email = data.get('email_address')
    if not email:
        return jsonify({"status": "ERROR", "message": "Email address is required."}), 400
    
    accounts = load_data(ACCOUNTS_FILE)
    if email not in accounts:
        return jsonify({"status": "ERROR", "message": "Account not found."}), 404

    account_data = accounts[email]
    
    if 'provider' in data:
        account_data['provider'] = data['provider']
    if data.get('password'):
        account_data['password'] = data['password']
    if 'imap_server' in data:
        account_data['imap_server'] = data.get('imap_server')
        
    accounts[email] = account_data
    save_data(ACCOUNTS_FILE, accounts)
    return jsonify({"status": "OK", "message": f"Account {email} updated."})

@app.route('/api/accounts/delete', methods=['POST'])
def delete_account():
    data = request.get_json() or {}
    email = data.get('email_address')
    if not email:
        return jsonify({"status": "ERROR", "message": "Email address is required."}), 400

    accounts = load_data(ACCOUNTS_FILE)
    if email in accounts:
        del accounts[email]
        save_data(ACCOUNTS_FILE, accounts)

    results = load_data(RESULTS_FILE)
    if email in results:
        del results[email]
        save_data(RESULTS_FILE, results)

    logs = load_data(UNSUBSCRIBED_LOG_FILE)
    if email in logs:
        del logs[email]
        save_data(UNSUBSCRIBED_LOG_FILE, logs)
        
    return jsonify({"status": "OK", "message": f"Account {email} deleted."})

@app.route('/api/test_connection', methods=['POST'])
def test_connection():
    data = request.get_json() or {}
    try:
        client = get_email_client(
            data['provider'], data['email_address'], data['password'], data.get('imap_server')
        )
        status, message = client.connect()
        if status == "OK":
            client.disconnect()
        return jsonify({"status": status, "message": message})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"An unexpected error occurred: {e}"}), 500

@app.route('/api/results', methods=['POST'])
def get_results():
    data = request.get_json() or {}
    email = data.get('email_address')
    results = load_data(RESULTS_FILE)
    account_results = results.get(email, {"last_scan_time": None, "links": {}})
    return jsonify(account_results)

@app.route('/api/unsubscribed', methods=['POST'])
def get_unsubscribed_links():
    data = request.get_json() or {}
    email = data.get('email_address')
    logs = load_data(UNSUBSCRIBED_LOG_FILE)
    account_logs = logs.get(email, {})
    return jsonify(account_logs)

@app.route('/api/unsubscribe', methods=['POST'])
def log_unsubscribe():
    data = request.get_json() or {}
    email = data.get('email_address')
    link_href = data.get('href')
    if not all([email, link_href]):
        return jsonify({"status": "ERROR", "message": "Missing fields."}), 400
    
    logs = load_data(UNSUBSCRIBED_LOG_FILE)
    if email not in logs:
        logs[email] = {}
    logs[email][link_href] = datetime.datetime.utcnow().isoformat()
    save_data(UNSUBSCRIBED_LOG_FILE, logs)
    
    return jsonify({"status": "OK"})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    email = request.args.get('email_address')
    num_emails_str = request.args.get('num_emails', '50')
    since_date = request.args.get('since_date')

    if not email:
        return Response(json.dumps({'error': 'Email address is required.'}), mimetype='application/json', status=400)

    try:
        num_emails = int(num_emails_str)
    except (ValueError, TypeError):
        num_emails = 50
        
    def generate_scan_progress():
        accounts = load_data(ACCOUNTS_FILE)
        account_info = accounts.get(email)
        
        if not account_info:
            yield f"data: {json.dumps({'error': 'Account not configured.'})}\n\n"
            return

        password_or_creds = account_info.get('credentials') if account_info.get('provider') == 'gmail' else account_info.get('password')

        try:
            client = get_email_client(
                account_info['provider'],
                email,
                password_or_creds,
                account_info.get('imap_server')
            )
            
            status, message = client.connect()
            if status != "OK":
                yield f"data: {json.dumps({'error': f'Connection failed: {message}'})}\n\n"
                return

            scan_results_data = load_data(RESULTS_FILE)
            last_uid = scan_results_data.get(email, {}).get('last_uid')
            
            # The client's scan_emails method is now a generator
            for item in client.scan_emails(num_emails, last_uid, since_date):
                # Ensure item is a dictionary before processing
                if not isinstance(item, dict):
                    continue

                if item.get('status') == 'progress':
                    # This is a progress update
                    yield f"data: {json.dumps(item)}\n\n"
                elif item.get('status') == 'complete':
                    # This is the final result
                    links = item.get('links')
                    if not isinstance(links, dict):
                        links = {} # Ensure links is a dict
                    
                    new_last_uid = item.get('last_uid')

                    # --- Merge with existing results instead of overwriting ---
                    existing_results = scan_results_data.get(email, {})
                    existing_links = existing_results.get('links', {})
                    scan_history = existing_results.get('scan_history', [])

                    for domain, new_links_list in links.items():
                        if domain not in existing_links:
                            existing_links[domain] = []
                        
                        # Use a set for efficient lookup of existing hrefs
                        domain_hrefs = {link['href'] for link in existing_links[domain]}
                        
                        for link_data in new_links_list:
                            if link_data['href'] not in domain_hrefs:
                                existing_links[domain].append(link_data)
                                domain_hrefs.add(link_data['href'])
                    
                    # --- Update Scan History ---
                    scan_description = f"{num_emails} recent emails" if not since_date else f"emails since {since_date}"
                    
                    # Find date range of the new links
                    all_dates = [datetime.datetime.fromisoformat(link['date']) for domain_links in links.values() for link in domain_links if link.get('date')]
                    date_range_str = ""
                    if all_dates:
                        min_date = min(all_dates).strftime('%Y-%m-%d')
                        max_date = max(all_dates).strftime('%Y-%m-%d')
                        date_range_str = f"covering emails from {min_date} to {max_date}"

                    scan_history.append({
                        "scan_date": datetime.datetime.utcnow().isoformat(),
                        "scan_type": "date" if since_date else "number",
                        "scan_parameter": since_date or num_emails,
                        "description": f"Scanned {scan_description}",
                        "date_range": date_range_str,
                        "new_links_found": sum(len(v) for v in links.values())
                    })
                    
                    scan_results_data[email] = {
                        "scan_history": scan_history,
                        "last_uid": new_last_uid if isinstance(new_last_uid, str) else (new_last_uid.decode('utf-8') if new_last_uid else last_uid),
                        "links": existing_links # Save the merged links
                    }
                    save_data(RESULTS_FILE, scan_results_data)
                    
                    final_data = {
                        "status": "complete", 
                        "message": "Scan complete.", 
                        "links": existing_links,
                        "scan_history": scan_history
                    }
                    yield f"data: {json.dumps(final_data)}\n\n"
            
            client.disconnect()

        except Exception as e:
            # It's important to log the full exception for debugging
            logging.error(f"An exception occurred during scan stream: {e}", exc_info=True)
            yield f"data: {json.dumps({'error': f'An unexpected server error occurred: {e}'})}\n\n"

    return Response(generate_scan_progress(), mimetype='text/event-stream')

def run():
    # Clean up old files if they exist
    if os.path.exists('credentials.json'):
        os.remove('credentials.json')
    app.run(host='0.0.0.0', port=5001, debug=True)

import os
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
IMAP_SERVER = os.getenv("IMAP_SERVER")

# --- Debugging ---
DEBUG = True
DEBUG_EMAIL_DIR = 'debug_emails'

# --- General Configuration ---
DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ('true', '1', 't')
SECRET_KEY = os.getenv("SECRET_KEY", "a-secure-secret-key-for-sessions")


# --- Email Scanning Configuration ---
# Number of emails to fetch per scan
SCAN_PAGE_SIZE = 100 


# --- Google OAuth Configuration ---
# You must create a project in Google Cloud Console, enable the Gmail API,
# and download the client_secret.json file.
# https://developers.google.com/gmail/api/quickstart/python
GOOGLE_CLIENT_SECRET_FILE = 'client_secret.json'
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
GOOGLE_REDIRECT_URI = 'http://localhost:5001/oauth2callback'


# Auto Mail Unsubscriber

**Auto Mail Unsubscriber** is a web-based application designed to help users easily find and manage email subscription links. It scans specified email accounts, extracts all "unsubscribe" links, and presents them in a clean, organized interface, allowing users to efficiently manage their email subscriptions from a single dashboard.

The application currently supports both standard IMAP-based email providers (using email/password) and secure, modern authentication with Gmail via OAuth 2.0.

## Current Features

*   **Multi-Account Management**: Add and manage multiple email accounts.
*   **Provider Support**:
    *   **Gmail**: Securely connect using Google's OAuth 2.0 protocol. The application never sees or stores your Google password.
    *   **Other (IMAP)**: Connect to any email provider that supports IMAP with a username and password.
*   **Email Scanning**: Initiates a scan of your inbox to find emails containing unsubscribe links.
*   **Link Extraction**: Intelligently parses HTML emails to find and extract all potential unsubscribe links.
*   **Organized Link Display**: Presents the found links grouped by the sender's domain for easy management.
*   **Secure Credential Storage**: Account details (IMAP passwords or OAuth tokens) are stored locally in a `accounts.json` file.
*   **Web-Based Interface**: A clean, tab-based single-page application built with Flask and vanilla JavaScript for managing accounts and viewing results.

## How It Works

The application is composed of a Python Flask backend and a JavaScript-powered frontend.

1.  **Backend (Flask)**:
    *   Serves the main web page (`index.html`).
    *   Provides a RESTful API for all frontend operations (adding/deleting accounts, starting scans, fetching results).
    *   Handles the OAuth 2.0 flow for Google authentication, including the redirect and token exchange.
    *   Manages a local JSON file (`accounts.json`) for storing account credentials securely.
    *   Contains the core email processing logic in `email_client.py`.

2.  **Email Client**:
    *   **IMAPProvider**: Connects to traditional IMAP servers using `imaplib`, searches for emails, and fetches their content.
    *   **GmailProvider**: Uses the official Google API Python Client to connect via OAuth 2.0. It leverages the Gmail API to list messages and retrieve content, which is more secure and robust than IMAP for Gmail.
    *   **Link Finder**: A utility that uses `BeautifulSoup` to parse the HTML content of emails and identify `<a>` tags that are likely unsubscribe links based on their text content (e.g., "unsubscribe", "abmelden", "manage subscriptions").

3.  **Frontend (JavaScript)**:
    *   Dynamically creates tabs for each added account.
    *   Provides forms for adding new accounts, with conditional UI for selecting Gmail (OAuth) or other IMAP providers (password).
    *   Initiates API calls to the backend to trigger scans and display the results.
    *   Manages the user interface for displaying unsubscribe links.

## Project Structure

```
AutoMailUnsubscriber/
├── app/
│   ├── __init__.py
│   ├── email_client.py     # Core logic for connecting to email servers and scanning emails.
│   ├── link_finder.py      # Utility for finding unsubscribe links in HTML.
│   ├── web_server.py       # Flask web server, API endpoints, and OAuth handling.
│   ├── static/
│   │   └── style.css       # CSS for the frontend.
│   └── templates/
│       └── index.html      # The main HTML file for the single-page app.
├── config.py               # Configuration settings (currently minimal).
├── requirements.txt        # Python dependencies.
├── run.py                  # Entry point to start the Flask server.
├── client_secret.json      # (User-provided) Google OAuth credentials.
└── accounts.json           # (Generated) Stores user account info.
```

## Setup and Run

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
2.  **Configure Google OAuth**:
    *   Follow the official Google Cloud documentation to create a project, enable the Gmail API, and create an OAuth 2.0 Client ID for a "Web application".
    *   Set the authorized redirect URI to `http://localhost:5001/oauth2callback`.
    *   Download the credentials and save the file as `client_secret.json` in the project's root directory.
3.  **Run the Application**:
    ```bash
    python3 run.py
    ```
4.  **Access the App**:
    *   Open a web browser and navigate to `http://localhost:5001`.


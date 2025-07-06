# unsubmy.email

unsubmy.email is a simple web application that scans your email inbox for unsubscribe links from newsletters and mailing lists and presents them in a clean, easy-to-manage interface.

## Features

- **Multiple Account Support**: Connect and manage multiple email accounts (Gmail, Outlook, and any other IMAP provider).
- **Secure Authentication**: Uses OAuth2 for Gmail, meaning the application never sees or stores your Google password.
- **Unified Dashboard**: View all unsubscribe links from all your accounts in one place.
- **Smart Scanning**: Scans can be limited to a specific number of recent emails or a date range.
- **Real-time Progress**: A live-updating progress bar shows you the status of your scan.
- **History Tracking**: Keeps a log of your past scans and which links you've clicked.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.10+
- pip

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/unsubmy.email.git
    cd unsubmy.email
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Set up Google OAuth:**
    - Go to the [Google Cloud Console](https://console.cloud.google.com/).
    - Create a new project.
    - Go to "APIs & Services" > "Credentials".
    - Create an "OAuth client ID".
    - Select "Web application".
    - Under "Authorized redirect URIs", add `http://localhost:5001/oauth2callback`.
    - Download the JSON credentials file and rename it to `client_secret.json` in the root of the project directory.
    - Enable the Gmail API for your project.

4. **Run the application:**
    ```bash
    python3 run.py
    ```
    The app will be available at `http://localhost:5001`.


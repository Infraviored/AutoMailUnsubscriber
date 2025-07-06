# Auto Mail Unsubscriber

A simple tool to scan your email inbox and find unsubscribe links from newsletters and other subscription-based emails.

## Features

- Scans a specified number of recent emails.
- Uses an extensive list of English and German keywords to identify unsubscribe links.
- Groups found links by sender domain.
- Provides a simple web interface to start the scan and view the results.

## Setup and Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/AutoMailUnsubscriber.git
    cd AutoMailUnsubscriber
    ```

2.  **Install dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3.  **Configure your email credentials:**
    Create a file named `.env` in the project root by copying the template:
    ```bash
    cp .env.template .env
    ```
    Now, open the `.env` file and add your email account details. Do not add quotes around the values.
    ```
    EMAIL_ADDRESS=your_email@example.com
    EMAIL_PASSWORD=your_password
    IMAP_SERVER=imap.example.com
    ```
    For example, for GMX, `IMAP_SERVER` would be `imap.gmx.com`.

4.  **Run the application:**
    ```bash
    python run.py
    ```

5.  **Open your browser:**
    Navigate to `http://127.0.0.1:5000` to access the web interface. Enter the number of emails you want to scan and click "Scan Emails".

## How it works

The script connects to your email account via IMAP, fetches the most recent emails, and parses the HTML content to find links that are likely for unsubscribing. It looks for keywords like "unsubscribe", "abbestellen", "opt-out", etc., in the text of and around the links.

The results are then displayed in a web interface, grouped by the sender's domain name, making it easy to go through them and unsubscribe from unwanted emails.


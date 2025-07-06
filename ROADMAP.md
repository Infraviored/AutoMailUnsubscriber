# Project Roadmap: From Prototype to Production

This document outlines the necessary steps to evolve the Auto Mail Unsubscriber from a functional prototype into a secure, user-friendly, and deployable web application.

---

### Phase 1: Frontend Enhancements & User Experience

The first priority is to improve the user-facing experience, making the application more interactive and professional.

1.  **Implement Real-Time Scan Progress Bar**:
    *   **Goal**: The user should see live feedback during an email scan directly in the browser, rather than just in the console.
    *   **Technical Plan**:
        *   **Backend**: Modify the `/scan` endpoint in `web_server.py` to become a streaming endpoint (using Flask's streaming capabilities with `yield`).
        *   As the `email_client` scans emails one by one, the backend will `yield` progress updates as JSON objects (e.g., `{"progress": 10, "total": 100, "message": "Scanning email 10 of 100..."}`).
        *   **Frontend**: Modify the `handleScan` function in `index.html`. Instead of a standard `fetch`, use the `fetch` API in a way that can read a response stream.
        *   As progress events are received, update the "Scan Now" button's style and text. The button's background will fill horizontally based on the percentage, and its text will update to show "Scanning... (10/100)".

2.  **Create a Professional Landing Page**:
    *   **Goal**: New visitors should be greeted with an informative and trustworthy landing page before they log in or manage accounts.
    *   **Technical Plan**:
        *   Create a new route `/` in `web_server.py` that renders a new `landing.html` template.
        *   The existing account management interface will be moved to a new route, like `/dashboard`.
        *   The `landing.html` page will contain:
            *   A clear explanation of what the application does.
            *   Strong assurances about privacy and security (e.g., "We never store your emails").
            *   A "Get Started" or "Login" button that directs users to the login/account page.

---

### Phase 2: Security & Privacy Overhaul

To be a public-facing application, we must prioritize user data security and privacy.

1.  **Remove Debug Email Storage**:
    *   **Goal**: Stop saving the content of user emails to the local filesystem. This was a debug feature and is a major privacy risk.
    *   **Technical Plan**:
        *   In `app/email_client.py`, completely remove the code block that saves email HTML content to the `debug_emails` directory.
        *   Remove the `DEBUG_EMAIL_DIR` configuration from `config.py`.

2.  **Implement Data Persistence Options**:
    *   **Goal**: Give users control over whether their unsubscribe links are stored persistently or are session-only.
    *   **Technical Plan**:
        *   **UI**: In the account settings/dashboard, add a toggle switch: "Keep my links saved for next time".
        *   **Backend**:
            *   When the user initiates a scan, the frontend will send the state of this toggle.
            *   If persistence is disabled, all scan results (links, etc.) will be stored in the Flask `session` object, which is temporary and cookie-based.
            *   If persistence is enabled, the results will be saved to the `scan_results.json` file as it is now, but associated with the user's primary account ID.

---

### Phase 3: Multi-User Account System

The current system manages email accounts but doesn't have a concept of a "primary user" who owns those accounts. We need to implement a proper user authentication system.

1.  **Introduce User Registration & Login**:
    *   **Goal**: Users should be able to create a primary account for the application itself using an email and password. This primary account will then contain their linked email accounts for scanning.
    *   **Technical Plan**:
        *   **Database**: Replace the `accounts.json` and `scan_results.json` files with a proper database (e.g., SQLite for simplicity, or PostgreSQL for production). We'll need a `users` table (id, primary_email, password_hash) and a `linked_accounts` table (id, user_id, email_address, provider, credentials).
        *   **Authentication**:
            *   Create `/register` and `/login` endpoints.
            *   When a user registers, hash their password using a strong library like `Werkzeug.security`. **Never store plain text passwords.**
            *   Use Flask-Login or a similar session management library to handle user login state.
        *   **Account Linking**: Once logged in, the user can add scanning accounts (Gmail, IMAP). These will be stored in the `linked_accounts` table, associated with their primary `user_id`. The OAuth flow will remain largely the same, but the credentials will be stored in the database instead of a JSON file.

---

### Phase 4: Deployment

Prepare the application to be deployed to a public domain.

1.  **Configuration for Production**:
    *   Use a production-ready WSGI server (like Gunicorn or uWSGI) instead of the Flask development server.
    *   Update `config.py` to use environment variables for all sensitive information (e.g., `SECRET_KEY`, database URI).
    *   Disable debug mode in Flask.

2.  **Domain and HTTPS**:
    *   Acquire a domain name.
    *   Configure the production server to use HTTPS with an SSL certificate (e.g., from Let's Encrypt).
    *   Update the Google OAuth redirect URI in the Cloud Console to use the new `https://your-domain.com/oauth2callback` URI. 
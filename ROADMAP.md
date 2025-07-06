# Project Roadmap: From Prototype to Production (v2)

This document provides a detailed, technical blueprint for evolving the Auto Mail Unsubscriber from a functional local prototype into a secure, user-friendly, and production-ready web application. It includes architectural decisions, implementation details, and deployment strategies.

**Current Status**: Phase 1.1 is complete. The core application is functional with a robust, streaming UI for scanning. We are now beginning Phase 1.2 and a fast-track of Phase 3.

---

### **Phase 1: Core Frontend Enhancements & User Experience**

The immediate priority is to elevate the user-facing experience from a simple tool to an interactive and trustworthy application.

#### **1.1: Implement Real-Time Streaming Progress Bar & Enhanced UX - ✅ COMPLETE**

*   **Objective**: Provide users with immediate, granular feedback during the email scanning process, enhancing user engagement and transparency. The "Scan Now" button will transform into a dynamic progress bar.
*   **Status**: Implemented. The frontend now uses `EventSource` to listen to a streaming response from the Flask backend. The UI provides detailed progress and a rich summary of scan history and results.

#### **1.2: Create a Professional Landing Page & Application Structure**

*   **Objective**: Establish a clear separation between the public-facing marketing/information page and the functional application dashboard. This is critical for user trust and for the Google verification process.
*   **Technical Architecture**:
    *   **Routing**:
        *   A new `landing.html` template will be created. The `/` route in `web_server.py` will now render this template.
        *   The existing application logic in `index.html` will be moved into a new `dashboard.html` template.
        *   A new `/dashboard` route will be created, protected to ensure only logged-in users can access it (this protection will be implemented in Phase 3). Initially, it will be publicly accessible.
    *   **Landing Page Content (`landing.html`)**:
        *   This will be a static page with a professional design.
        *   It will clearly articulate the app's value proposition.
        *   It will feature a prominent "Get Started" or "Login with Google" button that links to the `/login` or `/dashboard` route.
        *   **Crucially for verification**, it will include footer links to "Privacy Policy" and "Terms of Service" pages (to be created in Phase 2).

---

### **Phase 2: Security, Privacy & Google Verification Preparedness**

This phase focuses on hardening the application, ensuring user data is handled with extreme care, and preparing all necessary documentation for the Google OAuth verification process.

#### **2.1: Fortify Security and Privacy Policies**

*   **Objective**: Eliminate security risks from debug features and implement transparent data handling practices.
*   **Technical Implementation**:
    *   **Remove Debug File I/O**: The code block in `app/email_client.py` responsible for writing email contents to the `debug_emails` directory will be completely removed. The `DEBUG_EMAIL_DIR` variable in `config.py` will also be deleted. This is a non-negotiable step for production.
    *   **Create `privacy_policy.html` and `terms_of_service.html`**:
        *   New templates will be created in the `templates` directory.
        *   New routes (`/privacy` and `/terms`) will be added to `web_server.py` to serve these pages.
        *   **Privacy Policy Content**: This document will be written in clear, simple language and will explicitly state:
            *   Confirmation that the app uses the Google Gmail API to read email data.
            *   The exact scope being requested (`gmail.readonly`).
            *   The reason for data access: "to automatically identify and extract hypertext links that are associated with email unsubscriptions."
            *   A firm declaration that email body content is processed ephemerally and **never stored** on the server.
            *   A list of the data that **is** stored (e.g., the extracted URL, sender's domain, date of email) and for what purpose (to display to the user).
            *   Details on how a user can permanently delete their account and all associated data.

#### **2.2: Prepare for Google OAuth Verification**

*   **Objective**: Systematically prepare all assets and documentation required by Google's Trust & Safety team to ensure a smooth verification process for the `gmail.readonly` scope.
*   **Checklist & Plan**:
    *   **Verified Domain Ownership**: The production domain must be verified through the Google Search Console. The Google account used for verification must be an owner of the Google Cloud project.
    *   **OAuth Consent Screen Configuration**:
        *   The Application Name, Logo, and Support Email must be professional and accurately represent the application.
        *   Links to the newly created Privacy Policy and Terms of Service homepages must be added.
    *   **Demonstration Video**: A short (1-2 minute) screen recording will be prepared. It must clearly show:
        1.  The user starting on the application's homepage (`https://your-domain.com`).
        2.  The entire OAuth 2.0 sign-in flow.
        3.  The OAuth consent screen, clearly showing the correct `client_id` in the URL.
        4.  The core functionality of the app after login (e.g., initiating a scan and seeing results appear).
    *   **Written Justification**: A concise justification for why the sensitive `gmail.readonly` scope is necessary for the app's core functionality will be prepared.

---

### **Phase 3: Multi-User Architecture & Data Persistence**

This phase transitions the application from a single-user tool to a true multi-tenant SaaS application.

#### **3.1: Database Integration**

*   **Objective**: Replace the fragile JSON file storage with a robust, scalable relational database.
*   **Technical Implementation**:
    *   **Technology Choice**: We will use `Flask-SQLAlchemy` as the ORM for seamless integration. The initial database will be SQLite for ease of development, with a clear path to switch to PostgreSQL for production.
    *   **Data Models (`models.py`)**: A new `app/models.py` file will be created with the following SQLAlchemy models:
        *   `User(db.Model)`:
            *   `id` (Integer, Primary Key)
            *   `primary_email` (String, Unique, Not Null)
            *   `password_hash` (String, Not Null)
            *   `linked_accounts` (Relationship to `LinkedAccount`)
        *   `LinkedAccount(db.Model)`:
            *   `id` (Integer, Primary Key)
            *   `user_id` (Integer, Foreign Key to `User.id`)
            *   `email_address` (String, Not Null)
            *   `provider` (String, e.g., 'gmail', 'other')
            *   `credentials_json` (Text, Nullable, Encrypted): To store OAuth tokens or IMAP passwords.
        *   `UnsubscribeLink(db.Model)`:
            *   `id` (Integer, Primary Key)
            *   `linked_account_id` (Integer, Foreign Key to `LinkedAccount.id`)
            *   `sender_domain` (String)
            *   `unsubscribe_url` (String, Unique)
            *   `email_subject` (String)
            *   `email_date` (DateTime)
    *   **Credential Encryption**: All sensitive credentials in `LinkedAccount.credentials_json` will be encrypted at rest using the `cryptography` library before being stored in the database.

#### **3.2: User Authentication System**

*   **Objective**: Implement a secure registration, login, and session management system.
*   **Technical Implementation**:
    *   **Library**: `Flask-Login` will be integrated to manage user sessions.
    *   **Password Hashing**: The `werkzeug.security` library will be used to generate secure password hashes (`generate_password_hash`) and verify them (`check_password_hash`).
    *   **Routes**:
        *   `/register` (GET, POST): A form for new users. On POST, it will validate the data, hash the password, and create a new `User` record.
        *   `/login` (GET, POST): A form to authenticate users. On POST, it will check credentials and use `login_user()` from Flask-Login.
        *   `/logout`: Will clear the session using `logout_user()`.
    *   **Route Protection**: The `@login_required` decorator from Flask-Login will be applied to all routes that require an authenticated user (e.g., `/dashboard`, `/scan`).

---

### **Phase 4: Deployment & Production Readiness**

This final phase covers the steps to deploy the application to a live server.

*   **Objective**: Deploy the application on a public domain, configured for security, reliability, and performance.
*   **Deployment Plan**:
    *   **WSGI Server**: Use **Gunicorn** as the production WSGI server to run the Flask application. It will be configured with multiple worker processes.
    *   **Reverse Proxy**: Use **Nginx** as a reverse proxy in front of Gunicorn. Nginx will handle incoming HTTP/HTTPS requests, serve static files directly (for performance), and forward dynamic requests to the Gunicorn workers.
    *   **HTTPS**: **Certbot** will be used to obtain and automatically renew a free SSL/TLS certificate from Let's Encrypt, enabling HTTPS for the domain.
    *   **Environment Variables**: All configuration variables (`SECRET_KEY`, `DATABASE_URI`, OAuth client secrets for production) will be managed through environment variables, not hardcoded in `config.py`.
    *   **Database**: For production, the application will be configured to connect to a managed PostgreSQL database instance.
    *   **Redirect URI Update**: The final step after deployment will be to go back to the Google Cloud Console and add the new, final production URL (`https-your-domain-com/oauth2callback`) to the list of authorized redirect URIs. 
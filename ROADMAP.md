# unsubmy.email Roadmap

This document outlines the planned features and improvements for **unsubmy.email**. The roadmap is divided into several phases, focusing on moving from a functional prototype to a robust, user-friendly, and secure application.

## Phase 1: Core Functionality & Usability (In Progress)

This phase focuses on building a solid foundation and a usable interface.

-   [x] **1.1: Basic Email Scanning**
    -   [x] Connect to IMAP servers.
    -   [x] Connect to Gmail via OAuth2.
    -   [x] Scan for and extract unsubscribe links.
    -   [x] Basic web interface to display results.
    -   [x] Store account credentials securely on the server.

-   [x] **1.2: Professional Landing & User System**
    -   [x] Create a professional, welcoming landing page for new users (`landing.html`).
    -   [x] Implement a full user account system (Login/Registration).
    -   [x] Move the core application to a protected dashboard (`dashboard.html`).
    -   [x] Migrate all data storage (linked accounts, scan results) from JSON files to a proper database (SQLite).
    -   [x] Associate all data with the logged-in user.

-   [ ] **1.3: Real-time Progress & Feedback**
    -   [x] Implement a real-time progress bar during email scans using server-sent events (SSE).
    -   [ ] Add more detailed status updates (e.g., "Scanning folder X", "Found Y links").
    -   [ ] Provide clearer error messages on the frontend if a scan fails.

-   [ ] **1.4: Enhanced Unsubscribe Tracking**
    -   [ ] Add a mechanism to mark links as "clicked" or "unsubscribed".
    -   [ ] Persist the "clicked" state in the database.
    -   [ ] Visually distinguish clicked links in the UI (e.g., grayed out, strikethrough).
    -   [ ] Add an option to hide unsubscribed-from domains from future scan results.

## Phase 2: Security & Production Readiness

This phase is about making the application secure, stable, and ready for deployment.

-   [ ] **2.1: Security Hardening**
    -   [ ] Encrypt all sensitive credentials stored in the database (e.g., IMAP passwords, OAuth refresh tokens) using a dedicated library like `cryptography`. **(High Priority)**
    -   [ ] Implement CSRF (Cross-Site Request Forgery) protection on all forms and API endpoints.
    -   [ ] Review and set appropriate CORS (Cross-Origin Resource Sharing) policies if the frontend and backend are ever separated.
    -   [ ] Add rate-limiting to API endpoints to prevent abuse.

-   [ ] **2.2: Configuration & Deployment**
    -   [ ] Move all hardcoded settings (like client secrets, database URI) into a configuration file or environment variables.
    -   [ ] Create a `Dockerfile` and `docker-compose.yml` for easy, containerized deployment.
    -   [ ] Write a deployment guide for a production environment (e.g., using Gunicorn and Nginx).

-   [ ] **2.3: Comprehensive Testing**
    -   [ ] Add unit tests for the email client logic (`email_client.py`).
    -   [ ] Add unit tests for the backend API endpoints (`web_server.py`).
    -   [ ] Implement integration tests that simulate a full user flow (login -> add account -> scan -> view results).

## Phase 3: Advanced Features & User Experience

This phase focuses on adding value and improving the overall user experience.

-   [ ] **3.1: Outlook / Microsoft 365 OAuth Support**
    -   [ ] Implement the OAuth2 flow for Microsoft accounts.
    -   [ ] Create an `OutlookProvider` in `email_client.py` that uses the Microsoft Graph API.

-   [ ] **3.2: Automated & Scheduled Scanning**
    -   [ ] Add an option for users to enable automatic background scanning on a schedule (e.g., once a week).
    -   [ ] This will likely require a background job processor like Celery or APScheduler.

-   [ ] **3.3: "One-Click" Unsubscribe (Ambitious)**
    -   [ ] Research the `List-Unsubscribe` email header, which often provides a `mailto:` or HTTP endpoint for direct, automated unsubscribing.
    -   [ ] Implement functionality to attempt an automated unsubscribe action on behalf of the user, where possible. This is a significant feature and requires careful security and UX considerations.

-   [ ] **3.4: UI/UX Polish**
    -   [ ] Add pagination or infinite scrolling for scan results with a large number of links.
    -   [ ] Implement a "select all" feature for domains.
    -   [ ] Improve the mobile responsiveness of the dashboard. 
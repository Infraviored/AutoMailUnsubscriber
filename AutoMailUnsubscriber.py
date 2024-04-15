import imaplib
import email
from tqdm import tqdm
import webbrowser
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import json

def load_and_update_logins():
    # Path to the login.json file
    login_file_path = "login.json"
    # Check if login.json exists
    try:
        with open(login_file_path, "r") as file:
            logins = json.load(file)
    except FileNotFoundError:
        logins = []

    # Ask the user which emails to process
    emails_to_process = []
    for login in logins:
        email = login["EMAIL"]
        process = input(f'Process "{email}"? (Y/N) ').strip().lower()
        if process == 'y':
            emails_to_process.append(login)

    # Ask if the user wants to add a new email
    add_new = input("Add new mail? (Y/N) ").strip().lower()
    if add_new == 'y':
        new_email = input("Enter new email: ").strip()
        new_password = input("Enter password for new email: ").strip()
        new_login = {"EMAIL": new_email, "PASSWORD": new_password}
        # Ask if the new login should be saved
        save_login = input("Save this email and password for future use? (Y/N) ").strip().lower()
        if save_login == 'y':
            logins.append(new_login)
            # Update the login.json file
            with open(login_file_path, "w") as file:
                json.dump(logins, file, indent=4)
        else:
            # Temporarily use the new login without saving
            print("This email will be used for this session only.")
        emails_to_process.append(new_login)

    return emails_to_process



def initialize_gmx_connection(EMAIL_ADDRESS, PASSWORD):
    # Connect to the GMX IMAP server
    imap_server = "imap.gmx.com"
    imap_port = 993
    mail = imaplib.IMAP4_SSL(imap_server, imap_port)

    # Login with your GMX credentials
    mail.login(EMAIL_ADDRESS, PASSWORD)

    mailbox = "INBOX"
    mail.select(mailbox)

    return mail



def find_unsubscribe_urls(email_body):
    # List of words similar to "unsubscribe"
    unsub_words_english = ["unsubscribe", "newsletter", "opt-out", "cancel", "subscription", "remove", "quit", "terminate", "end", "withdraw", "stop"]
    unsub_words_german = ["abbestellen", "Newsletter", "kündigen", "abmelden", "beenden", "Abonnement", "stoppen", "entfernen", "austragen", "löschen", "aufhören", "melde"]
    unsubscribe_words = unsub_words_english + unsub_words_german

    # Initialize BeautifulSoup
    soup = BeautifulSoup(email_body, 'html.parser')
    valid_unsubscribe_urls = []

    # Convert the entire email body into a list of text chunks and links
    text_and_links = []
    for elem in soup.recursiveChildGenerator():
        if isinstance(elem, str):
            text_and_links.append(('text', elem))
        elif elem.name == 'a' and elem.has_attr('href'):
            text_and_links.append(('link', elem['href']))

    # Search for text containing any unsubscribe words and measure the distance to the nearest link
    for i, (type, value) in enumerate(text_and_links):
        if type == 'text' and any(word.lower() in value.lower() for word in unsubscribe_words):
            # Initialize distance to a large number
            distance, closest_link = len(email_body), None
            # Check distance to all links and find the closest
            for j, (inner_type, inner_value) in enumerate(text_and_links):
                if inner_type == 'link':
                    current_distance = abs(i - j)
                    if current_distance < distance:
                        distance = current_distance
                        closest_link = inner_value

            # Check and append the closest link with its distance if valid
            if closest_link and not any(ext in closest_link.lower() for ext in ['.pdf', '.jpg', '.png', '.zip']):
                valid_unsubscribe_urls.append((closest_link, closest_link.lower(), distance))

    # Deduplicate the URLs based on the link itself
    seen = set()
    valid_unsubscribe_urls = [(a, b, c) for a, b, c in valid_unsubscribe_urls if not (b in seen or seen.add(b))]
    
    return valid_unsubscribe_urls

def process_emails(mail, num_messages):
    email_bodies = []  # Initialize the list to store email bodies
    unsubscribe_urls = []  # Initialize the list to store unsubscribe URLs
    # Search for all emails in the mailbox and get the message IDs
    status, messages = mail.search(None, "ALL")
    message_ids = messages[0].split()

    # Sort the message IDs in reverse order to process the most recent emails first
    message_ids = message_ids[::-1]

    # Process specified number of messages with tqdm progress bar
    for message_id in tqdm(message_ids[:num_messages], desc="Processing emails", unit="email"):
        status, msg_data = mail.fetch(message_id, "(RFC822)")
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)

        # Initialize email body
        body = ""

        # Check if the email is multipart (contains both plain text and HTML)
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Check for plain text email body
                if "text/plain" in content_type and "attachment" not in content_disposition:
                    body += part.get_payload(decode=True).decode(errors="ignore")
                # Check for HTML email body
                elif "text/html" in content_type and "attachment" not in content_disposition:
                    body += part.get_payload(decode=True).decode(errors="ignore")
        else:
            # For non-multipart emails, get the email body
            body = msg.get_payload(decode=True).decode(errors="ignore")

        email_bodies.append(body)

        # Find and process unsubscribe URLs
        unsubscribe_urls_in_email = find_unsubscribe_urls(body)
        unsubscribe_urls.extend(unsubscribe_urls_in_email)

    return email_bodies, unsubscribe_urls
def extract_domain(url):
    """
    Extracts the main domain from a URL, stripping away subdomains.
    """
    netloc = urlparse(url).netloc
    # Split the netloc by dots and keep the last two parts for most domains
    # Adjust if your URLs might have different TLDs requiring different handling (e.g., co.uk)
    parts = netloc.split('.')
    if len(parts) > 2 and not parts[-2].isdigit():  # Check if the domain is not an IP address
        # Simple heuristic to handle common second-level TLDs like co.uk, com.au, etc.
        if parts[-2] in ['co', 'com', 'org', 'net'] and len(parts[-1]) == 2:
            main_domain = '.'.join(parts[-3:])
        else:
            main_domain = '.'.join(parts[-2:])
    else:
        main_domain = netloc
    return main_domain

def format_html_output(unsubscribe_urls, max_links_per_domain=3):
    # Group the URLs by their respective domains and keep unique URLs per domain, along with their distances
    grouped_urls = {}
    for original_url, lowercase_url, distance in unsubscribe_urls:
        if any(ext in lowercase_url for ext in ['.pdf', '.jpg', '.png', '.zip']):
            continue
        
        domain = extract_domain(lowercase_url)  # Use the new extract_domain function here
        if domain not in grouped_urls:
            grouped_urls[domain] = []
        # Append both the original URL and its distance for sorting later
        grouped_urls[domain].append((original_url, distance))

    # Create the HTML output with embedded CSS styles
    html_output = """
    <html>
        <head>
            <title>Unsubscribe URLs by Domain</title>
            <style>
                body {
                    background-color: #303030;
                    color: #D0D0D0;
                    font-family: Arial, sans-serif;
                    font-size: 14px;
                }
                h1, h2 {
                    color: #FFFFFF;
                }
                ul {
                    list-style-type: none;
                    padding: 0;
                    margin: 0;
                }
                li {
                    margin-bottom: 10px;
                    background-color: #444;
                    padding: 10px;
                    border-radius: 5px;
                }
                a {
                    color: #FFFFFF; 
                    text-decoration: none;
                }
                a:visited {
                    color: #A1CB66;
                }
                a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <h1>Unsubscribe URLs by Domain</h1>
    """

    for domain, urls_with_distances in grouped_urls.items():
        domain_count = len(urls_with_distances)
        html_output += f"<h2>{domain} (Count: {domain_count})</h2><ul>"

        # Sort URLs by distance and limit to max_links_per_domain
        for url, distance in sorted(urls_with_distances, key=lambda x: x[1])[:max_links_per_domain]:
            clean_url = url.split('"', 1)[0]
            if clean_url.startswith("http"):
                html_output += f'<li><a href="{clean_url}" target="_blank">{clean_url}</a> (Distance: {distance})</li>'
            else:
                html_output += f"<li>{clean_url} (Distance: {distance})</li>"

        html_output += "</ul>"

    html_output += """
        </body>
    </html>
    """

    return html_output

if __name__ == "__main__":
    selected_emails = load_and_update_logins()

    for i, login_info in enumerate(selected_emails):
        email_address = login_info["EMAIL"]
        password = login_info["PASSWORD"]
        print(f"Processing {email_address}...")

        mail_connection = initialize_gmx_connection(email_address, password)

        # Prompt the user for the number of emails to process
        num_messages_to_process = int(input("Enter the number of emails to process: "))

        # Process the emails and find unsubscribe URLs
        _, unsubscribe_urls = process_emails(mail_connection, num_messages_to_process)

        # Generate the formatted HTML output
        html_output = format_html_output(unsubscribe_urls)

        # Save the HTML output to a file named after the email address to avoid overwriting
        output_filename = f"unsubscribe_urls_{email_address.split('@')[0]}.html"
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(html_output)

        # Open the HTML file in the default web browser
        webbrowser.open(output_filename)

        # Close mail connection
        mail_connection.logout()

        # Prompt to proceed to the next email
        if i < len(selected_emails) - 1:
            input(f"Please close the browser if open and press Enter to proceed to the next email {selected_emails[i + 1]['EMAIL']}...")
        else:
            print("Finished processing all selected emails.")
# AutoMailUnsubscriber

Tired of sifting through countless emails just to find those elusive unsubscribe links? Unsubscribe Helper is here to streamline the process, making your digital decluttering a breeze.

## How It Works

Unsubscribe Helper dives into your email inbox, using a keen eye to scan for potential trigger words like "unsubscribe" or "newsletter." It's not just looking at random; it hones in on the closest links within each email, usually right where the unsubscribe link lurks.

But it doesn't stop there. Unsubscribe Helper elegantly organizes these links by domain, allowing you to swiftly review and decide which subscriptions to cut from your digital life. It's like having a personal assistant dedicated to clearing your inbox clutter.

### Features

- **Smart Detection**: Iterates through your emails, focusing on ones with potential trigger words indicating subscription information.
- **Link Extraction**: Finds and extracts the nearest links within the email body, likely pointing you directly to unsubscribe pages.
- **Organized Overview**: Compiles the links in an easy-to-navigate list, sorted by domain, for efficient review and action.
- **Safety First**: Your emails are only processed in memory (RAM), never stored or logged, ensuring your privacy and security.
- **Simple Offline Review**: Generates a single, offline HTML file containing all found links. You decide when and which links to follow, directly from your browser.

## Is This Safe?

Absolutely. Your email content is processed in memory and never written to disk, except for the final HTML file containing unsubscribe links - and even that's done locally on your computer. The program itself doesn't interact with any servers (aside from your email provider to fetch emails), nor does it store any of your credentials or email contents beyond its runtime. You're in control every step of the way.

## Getting Started

Getting started with Unsubscribe Helper is straightforward. Follow these steps to declutter your inbox:

### Setup

1. **Clone the Repository**: Begin by cloning this repository to your local machine.
   ```
   git clone https://github.com/Infraviored/AutoMailUnsubscriber.git
   ```
2. **Install Dependencies**: Navigate into the cloned directory and install the required Python packages.
   ```
   pip install beautifulsoup4 tqdm
   ```
3. **Launch the Program**: Start the program by running the Python script.
   ```
   python AutoMailUnsubscriber.py
   ```

### Processing Your Emails

1. **Email Selection**: Upon launch, the program will ask you to select which email accounts to process. If it's your first time, you'll have the option to add a new email account.
2. **Number of Emails**: For each selected account, you will then enter the number of recent emails you wish to scan for unsubscribe links.
3. **Add More Accounts**: After processing, you'll have the option to add more email accounts or to proceed with the current selections.

### Reviewing Unsubscribe Links

1. **Open the HTML File**: Once processing is complete, the program generates an HTML file (`unsubscribe_urls_<email>.html`) for each processed email account.
2. **Review Links**: Open the generated HTML file in your preferred web browser. You'll see a list of unsubscribe links organized by domain, along with the distance metric indicating how closely related the link is to the unsubscribe trigger words.
3. **Take Action**: Click through the links to visit the unsubscribe pages directly from your browser and manage your subscriptions as needed.

By following these steps, you can quickly and efficiently review and act on unsubscribe links across multiple email accounts, helping you maintain a cleaner, more manageable inbox.

---

Embark on your journey to a cleaner inbox today with Unsubscribe Helper!


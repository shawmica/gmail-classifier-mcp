from mcp.server.fastmcp import FastMCP
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import os
import base64
import re

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify"
]

mcp = FastMCP("gmail-classifier")


def gmail_service():
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json",
                SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def get_header(headers, name):
    for h in headers:
        if h["name"].lower() == name.lower():
            return h["value"]
    return ""


def extract_body(payload):
    body = ""

    if "parts" in payload:
        for part in payload["parts"]:
            if part.get("mimeType") == "text/plain":
                data = part["body"].get("data")
                if data:
                    body += base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
    else:
        data = payload.get("body", {}).get("data")
        if data:
            body += base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

    return body


def classify_text(subject, body):
    text = f"{subject} {body}".lower()

    if any(word in text for word in ["password", "security alert", "login", "recovered", "verification"]):
        return "Security"
    elif any(word in text for word in ["invoice", "payment", "bank", "receipt", "transaction"]):
        return "Finance"
    elif any(word in text for word in ["meeting", "deadline", "project", "assignment", "task"]):
        return "Work"
    elif any(word in text for word in ["discount", "offer", "sale", "deal", "promo", "unlock"]):
        return "Promotions"
    elif any(word in text for word in ["course", "learn", "enroll", "certificate", "training"]):
        return "Education"
    elif any(word in text for word in ["urgent", "immediately", "action required"]):
        return "Important"
    else:
        return "General"


def detect_phishing_text(subject, body, sender):
    text = f"{subject} {body} {sender}".lower()
    score = 0
    reasons = []

    risky_words = ["urgent", "verify now", "password", "login", "bank", "suspended", "click here"]

    for word in risky_words:
        if word in text:
            score += 1
            reasons.append(f"Contains risky word: {word}")

    links = re.findall(r"https?://\S+", body)

    if len(links) > 3:
        score += 1
        reasons.append("Contains many links")

    if "security" in text or "account" in text:
        score += 1
        reasons.append("Account/security related email")

    if score >= 3:
        risk = "High"
    elif score == 2:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }


@mcp.tool()
def read_latest_emails(count: int = 10) -> list:
    """Read latest Gmail emails."""

    service = gmail_service()

    results = service.users().messages().list(
        userId="me",
        maxResults=count
    ).execute()

    messages = results.get("messages", [])
    emails = []

    for msg in messages:
        email = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        headers = email["payload"]["headers"]
        subject = get_header(headers, "Subject")
        sender = get_header(headers, "From")
        date = get_header(headers, "Date")
        body = extract_body(email["payload"])

        emails.append({
            "id": msg["id"],
            "from": sender,
            "subject": subject,
            "date": date,
            "snippet": email.get("snippet", ""),
            "category": classify_text(subject, body)
        })

    return emails


@mcp.tool()
def classify_email(subject: str, body: str) -> str:
    """Classify a single email by subject and body."""
    return classify_text(subject, body)


@mcp.tool()
def classify_latest_emails(count: int = 10) -> list:
    """Read and classify latest Gmail emails."""

    emails = read_latest_emails(count)

    return [
        {
            "subject": email["subject"],
            "from": email["from"],
            "category": email["category"],
            "snippet": email["snippet"]
        }
        for email in emails
    ]


@mcp.tool()
def summarize_latest_emails(count: int = 10) -> dict:
    """Summarize latest Gmail inbox categories."""

    emails = read_latest_emails(count)

    summary = {}

    for email in emails:
        category = email["category"]
        summary[category] = summary.get(category, 0) + 1

    return {
        "total_emails": len(emails),
        "category_summary": summary,
        "emails": emails
    }


@mcp.tool()
def detect_spam_or_phishing(count: int = 10) -> list:
    """Detect possible spam or phishing emails."""

    service = gmail_service()

    results = service.users().messages().list(
        userId="me",
        maxResults=count
    ).execute()

    messages = results.get("messages", [])
    output = []

    for msg in messages:
        email = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        headers = email["payload"]["headers"]
        subject = get_header(headers, "Subject")
        sender = get_header(headers, "From")
        body = extract_body(email["payload"])

        phishing_result = detect_phishing_text(subject, body, sender)

        output.append({
            "id": msg["id"],
            "from": sender,
            "subject": subject,
            "risk": phishing_result["risk"],
            "score": phishing_result["score"],
            "reasons": phishing_result["reasons"]
        })

    return output


@mcp.tool()
def create_gmail_label(label_name: str) -> str:
    """Create a Gmail label."""

    service = gmail_service()

    label_body = {
        "name": label_name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show"
    }

    try:
        service.users().labels().create(
            userId="me",
            body=label_body
        ).execute()

        return f"Label created: {label_name}"

    except Exception as e:
        return f"Label may already exist or failed: {str(e)}"


@mcp.tool()
def label_email(message_id: str, label_name: str) -> str:
    """Apply a Gmail label to an email by message ID."""

    service = gmail_service()

    labels = service.users().labels().list(userId="me").execute().get("labels", [])

    label_id = None

    for label in labels:
        if label["name"].lower() == label_name.lower():
            label_id = label["id"]
            break

    if not label_id:
        new_label = service.users().labels().create(
            userId="me",
            body={
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
        ).execute()

        label_id = new_label["id"]

    service.users().messages().modify(
        userId="me",
        id=message_id,
        body={
            "addLabelIds": [label_id]
        }
    ).execute()

    return f"Email labeled as {label_name}"


@mcp.tool()
def auto_label_latest_emails(count: int = 10) -> list:
    """Automatically classify and label latest Gmail emails."""

    emails = read_latest_emails(count)
    results = []

    for email in emails:
        label_result = label_email(email["id"], email["category"])

        results.append({
            "subject": email["subject"],
            "category": email["category"],
            "result": label_result
        })

    return results


@mcp.tool()
def classify_unread_emails(count: int = 10) -> list:
    """Classify unread Gmail emails only."""

    service = gmail_service()

    results = service.users().messages().list(
        userId="me",
        labelIds=["UNREAD"],
        maxResults=count
    ).execute()

    messages = results.get("messages", [])
    output = []

    for msg in messages:
        email = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        headers = email["payload"]["headers"]
        subject = get_header(headers, "Subject")
        sender = get_header(headers, "From")
        body = extract_body(email["payload"])
        category = classify_text(subject, body)

        output.append({
            "id": msg["id"],
            "from": sender,
            "subject": subject,
            "category": category,
            "snippet": email.get("snippet", "")
        })

    return output


@mcp.tool()
def auto_label_unread_emails(count: int = 10) -> list:
    """Classify unread Gmail emails and automatically apply labels."""

    unread_emails = classify_unread_emails(count)
    results = []

    for email in unread_emails:
        label_result = label_email(email["id"], email["category"])

        results.append({
            "subject": email["subject"],
            "from": email["from"],
            "category": email["category"],
            "label_result": label_result
        })

    return results
if __name__ == "__main__":
    print("Starting Gmail login test...")
    gmail_service()
    print("Gmail login successful. token.json created.")
    mcp.run()
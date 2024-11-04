import smtplib
import dns.resolver
import csv
from concurrent.futures import ThreadPoolExecutor
import functools
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from typing import List
import io

app = FastAPI()

# DNS cache to store resolved domains
dns_cache = {}

# Cached DNS lookup to avoid redundant queries
@functools.lru_cache(maxsize=100)
def cached_dns_lookup(domain):
    if domain not in dns_cache:
        dns_cache[domain] = dns.resolver.resolve(domain, 'MX')
    return dns_cache[domain]

# SMTP check for email existence
def smtp_check(email):
    domain = email.split('@')[1]
    try:
        mx_record = cached_dns_lookup(domain)
        mx_host = str(mx_record[0].exchange)
        server = smtplib.SMTP(timeout=10)  # Set a reasonable timeout
        server.set_debuglevel(0)  # Disable SMTP debug output
        server.connect(mx_host)
        server.helo(server.local_hostname)
        server.mail('sender@example.com')
        code, message = server.rcpt(email)
        server.quit()

        # Return True only if the server responds with 250 (OK)
        return code == 250
    except smtplib.SMTPServerDisconnected:
        print(f"Server disconnected: {domain}")
        return False
    except smtplib.SMTPConnectError:
        print(f"SMTP connection error: {domain}")
        return False
    except smtplib.SMTPRecipientsRefused:
        print(f"Recipient refused: {email}")
        return False
    except Exception as e:
        print(f"General SMTP error with {email}: {e}")
        return False

# Function to validate email addresses
def validate_email(email):
    deliverable = smtp_check(email)

    return {
        "Mail Address": email,
        "Deliverable": "Yes" if deliverable else "No"
    }

# Function to handle a list of emails with threading
def bulk_email_validation(email_list):
    results = []

    def validate_and_append(email):
        result = validate_email(email)
        results.append(result)

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(validate_and_append, email_list)

    return results

# Function to read emails from a CSV file
def read_emails_from_file(file):
    emails = []
    file_content = io.StringIO(file.decode('utf-8'))
    reader = csv.reader(file_content)
    for row in reader:
        emails.extend(row)
    return emails

# API endpoint to validate emails
@app.post("/validate-emails/")
async def validate_emails(email_list: str = Form(None), file: UploadFile = File(None)):
    # Check if both email_list and file are provided
    if email_list and file:
        raise HTTPException(status_code=400, detail="Provide either email list or CSV file, not both.")

    # If neither is provided
    if not email_list and not file:
        raise HTTPException(status_code=400, detail="No input provided. Please provide either a list of emails or a CSV file.")

    # Handle CSV file input
    if file:
        email_list = read_emails_from_file(await file.read())

    # Handle comma-separated email input
    elif email_list:
        email_list = [email.strip() for email in email_list.split(",")]

    # Validate emails
    results = bulk_email_validation(email_list)

    return {"validation_results": results}

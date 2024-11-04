import re
import csv
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from typing import List
import io

app = FastAPI()

# Syntax validation using regex
def is_valid_syntax(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

# Function to validate email addresses
def validate_email(email):
    syntax_valid = is_valid_syntax(email)
    
    return {
        "Mail Address": email,
        "Syntax Validation": "Valid" if syntax_valid else "Invalid"
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

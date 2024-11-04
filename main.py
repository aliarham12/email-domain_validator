import re
import csv
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from typing import List
import io
import dns.resolver
import functools
import smtplib
import whois

app = FastAPI()

# -----------------------------------------------------------------------------Syntax validation using regex----------------------------------------------------------------
def is_valid_syntax(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

# Function to validate email addresses
def Syntax_validate_email(email):
    syntax_valid = is_valid_syntax(email)
    
    if syntax_valid:
        return{"success":True,
               "message": "valid!",
                "data":[{
                    "mail_address": email,
                    "syntax_validation": "valid"
                }]}
    else:
         return{"success":False,
               "message": "invalid!",
                "data":[{
                    "mail_address": email,
                    "syntax_validation": "invalid"
                }]}

    # return {
    #     "mail_address": email,
    #     "syntax_validation": "Valid" if syntax_valid else "Invalid"
    # }

# Function to handle a list of emails with threading
def Syntax_bulk_email_validation(email_list):
    results = []

    def Syntax_validate_and_append(email):
        result = Syntax_validate_email(email)
        results.append(result)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(Syntax_validate_and_append, email_list)

    return results

# Function to read emails from a CSV file
def Syntax_read_emails_from_file(file):
    emails = []
    file_content = io.StringIO(file.decode('utf-8'))
    reader = csv.reader(file_content)
    for row in reader:
        emails.extend(row)
    return emails

# API endpoint to validate emails
@app.post("/syntax_validate-emails/")
async def Syntax_validate_emails(email_list: str = Form(None), file: UploadFile = File(None)):
    # Check if both email_list and file are provided
    if email_list and file:
        raise HTTPException(status_code=400, detail="provide either email list or CSV file, not both.")
    
    # If neither is provided
    if not email_list and not file:
        raise HTTPException(status_code=400, detail="no input provided. Please provide either a list of emails or a CSV file.")

    # Handle CSV file input
    if file:
        email_list = Syntax_read_emails_from_file(await file.read())
    
    # Handle comma-separated email input
    elif email_list:
        email_list = [email.strip() for email in email_list.split(",")]

    # Validate emails
    results = Syntax_bulk_email_validation(email_list)
    
    return results


# ---------------------------------------------------------DNS cache to store resolved domains------------------------------------------------
# dns_cache = {}

# # Cached DNS lookup to avoid redundant queries
# @functools.lru_cache(maxsize=100)
# def deliverability_cached_dns_lookup(domain):
#     if domain not in dns_cache:
#         dns_cache[domain] = dns.resolver.resolve(domain, 'MX')
#     return dns_cache[domain]

# # SMTP check for email existence
# def deliverability_smtp_check(email):
#     domain = email.split('@')[1]
    
#     # Skip SMTP check for known problematic domains
#     known_problematic_domains = ["outlook.com", "gmail.com", "yahoo.com"]
#     if domain in known_problematic_domains:
#         return None  # Skip the check, or return "Unknown"

#     try:
#         mx_record = deliverability_cached_dns_lookup(domain)
#         mx_host = str(mx_record[0].exchange)
#         server = smtplib.SMTP(timeout=10)  # Set a reasonable timeout
#         server.set_debuglevel(0)  # Disable SMTP debug output
#         server.connect(mx_host)
#         server.helo(server.local_hostname)
#         server.mail('sender@example.com')
#         code, message = server.rcpt(email)
#         server.quit()

#         # Return True only if the server responds with 250 (OK)
#         return code == 250
#     except smtplib.SMTPServerDisconnected:
#         print(f"Server disconnected: {domain}")
#         return False
#     except smtplib.SMTPConnectError:
#         print(f"SMTP connection error: {domain}")
#         return False
#     except smtplib.SMTPRecipientsRefused:
#         print(f"Recipient refused: {email}")
#         return False
#     except Exception as e:
#         print(f"General SMTP error with {email}: {e}")
#         return False


# # Function to validate email addresses
# def deliverability_validate_email(email):
#     deliverable = deliverability_smtp_check(email)

#     return {
#         "Mail Address": email,
#         # "Deliverable": "Yes" if deliverable else ("Unknown" if deliverable is None else "No")
#         "Deliverable": "Yes" if deliverable else "No"
#     }


# # Function to handle a list of emails with threading
# def deliverability_bulk_email_validation(email_list):
#     results = []

#     def deliverability_validate_and_append(email):
#         result = deliverability_validate_email(email)
#         results.append(result)

#     with ThreadPoolExecutor(max_workers=10) as executor:
#         executor.map(deliverability_validate_and_append, email_list)

#     return results

# # Function to read emails from a CSV file
# def deliverability_read_emails_from_file(file):
#     emails = []
#     file_content = io.StringIO(file.decode('utf-8'))
#     reader = csv.reader(file_content)
#     for row in reader:
#         emails.extend(row)
#     return emails

# # API endpoint to validate emails
# @app.post("/deliverability_validate-emails/")
# async def deliverability_validate_emails(email_list: str = Form(None), file: UploadFile = File(None)):
#     # Check if both email_list and file are provided
#     if email_list and file:
#         raise HTTPException(status_code=400, detail="Provide either email list or CSV file, not both.")

#     # If neither is provided
#     if not email_list and not file:
#         raise HTTPException(status_code=400, detail="No input provided. Please provide either a list of emails or a CSV file.")

#     # Handle CSV file input
#     if file:
#         email_list = deliverability_read_emails_from_file(await file.read())

#     # Handle comma-separated email input
#     elif email_list:
#         email_list = [email.strip() for email in email_list.split(",")]

#     # Validate emails
#     results = deliverability_bulk_email_validation(email_list)

#     return {"validation_results": results}

dns_cache = {}

# Cached DNS lookup to avoid redundant queries
@functools.lru_cache(maxsize=100)
def deliverability_cached_dns_lookup(domain):
    if domain not in dns_cache:
        dns_cache[domain] = dns.resolver.resolve(domain, 'MX')
    return dns_cache[domain]

# SMTP check for email existence
def deliverability_smtp_check(email):
    domain = email.split('@')[1]
    try:
        mx_record = deliverability_cached_dns_lookup(domain)
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
def deliverability_validate_email(email):
    deliverable = deliverability_smtp_check(email)


    if deliverable:
        return{"success":True,
               "message": "valid",
                "data":[{
                    "mail_address": email,
                    "deliverable": "yes"
                }]}
    else:
         return{"success":False,
               "message": "invalid",
                "data":[{
                    "mail_address": email,
                    "deliverable": "no"
                }]}
    # return {
    #     "Mail Address": email,
    #     "Deliverable": "Yes" if deliverable else "No"
    # }

# Function to handle a list of emails with threading
def deliverability_bulk_email_validation(email_list):
    results = []

    def deliverability_validate_and_append(email):
        result = deliverability_validate_email(email)
        results.append(result)

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(deliverability_validate_and_append, email_list)

    return results

# Function to read emails from a CSV file
def deliverability_read_emails_from_file(file):
    emails = []
    file_content = io.StringIO(file.decode('utf-8'))
    reader = csv.reader(file_content)
    for row in reader:
        emails.extend(row)
    return emails

# API endpoint to validate emails
@app.post("/deliverability_validate-emails/")
async def deliverability_validate_emails(email_list: str = Form(None), file: UploadFile = File(None)):
    # Check if both email_list and file are provided
    if email_list and file:
        raise HTTPException(status_code=400, detail="provide either email list or CSV file, not both.")

    # If neither is provided
    if not email_list and not file:
        raise HTTPException(status_code=400, detail="no input provided. Please provide either a list of emails or a CSV file.")

    # Handle CSV file input
    if file:
        email_list = deliverability_read_emails_from_file(await file.read())

    # Handle comma-separated email input
    elif email_list:
        email_list = [email.strip() for email in email_list.split(",")]

    # Validate emails
    results = deliverability_bulk_email_validation(email_list)

    return results


# --------------------------------------------------------Function to fetch DNS records (A, MX, TXT, CNAME)---------------------------------------------------------------
def get_dns_records(domain):
    records = {}
    try:
        # A record
        a_record = dns.resolver.resolve(domain, 'A')
        records['A'] = [str(rdata) for rdata in a_record]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        records['A'] = 'N/A'

    try:
        # MX record
        mx_record = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [str(rdata.exchange) for rdata in mx_record]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        records['MX'] = 'N/A'

    try:
        # TXT record
        txt_record = dns.resolver.resolve(domain, 'TXT')
        records['TXT'] = [str(rdata) for rdata in txt_record]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        records['TXT'] = 'N/A'

    try:
        # CNAME record
        cname_record = dns.resolver.resolve(domain, 'CNAME')
        records['CNAME'] = [str(rdata.target) for rdata in cname_record]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        records['CNAME'] = 'N/A'
    
    return records

# Function to perform WHOIS lookup
def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return {
            'registrant': whois_info.get('registrant_name', 'N/A'),
            'registrar': whois_info.get('registrar', 'N/A'),
            'creation Date': whois_info.get('creation_date', 'N/A'),
            'expiration Date': whois_info.get('expiration_date', 'N/A'),
            'status': whois_info.get('status', 'N/A')
        }
    except Exception as e:
        return f"whois lookup failed: {e}"

# Function to validate domain (DNS records + WHOIS info)
def dns_validate_domain(domain):
    try:
        dns_records = get_dns_records(domain)
        whois_info = get_whois_info(domain)
        
        # If both A record and WHOIS failed or are not available, consider the domain invalid
        if dns_records['A'] == 'N/A':
            return {
                "success": False,
                "message": "Invalid domain!",
                "data": [{
                    "domain": domain,
                    "dns_records": dns_records,
                    "whois_info": "N/A"
                }]
            }
        
        return {
            "success": True,
            "message": "Valid domain!",
            "data": [{
                "domain": domain,
                "dns_records": dns_records,
                "whois_info": whois_info
            }]
        }
    
    except Exception as e:
        # Catch-all exception handler for any unexpected issues
        return {
            "success": False,
            "message": f"Invalid domain due to error: {str(e)}",
            "data": [{
                "domain": domain,
                "dns_records": "N/A",
                "whois_info": "N/A"
            }]
        }

# Function to handle a list of domains with threading
def dns_bulk_domain_validation(domain_list):
    results = []

    def dns_validate_and_append(domain):
        result = dns_validate_domain(domain)
        results.append(result)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(dns_validate_and_append, domain_list)

    return results

# Function to read domains from a CSV file
def dns_read_domains_from_file(file):
    domains = []
    file_content = io.StringIO(file.decode('utf-8'))
    reader = csv.reader(file_content)
    for row in reader:
        domains.extend(row)
    return domains

# API endpoint to validate domains
@app.post("/validate-domains/")
async def dns_validate_domains(domain_list: str = Form(None), file: UploadFile = File(None)):
    # Check if both domain_list and file are provided
    if domain_list and file:
        raise HTTPException(status_code=400, detail="provide either domain list or CSV file, not both.")

    # If neither is provided
    if not domain_list and not file:
        raise HTTPException(status_code=400, detail="no input provided. Please provide either a list of domains or a CSV file.")

    # Handle CSV file input
    if file:
        domain_list = dns_read_domains_from_file(await file.read())

    # Handle comma-separated domain input
    elif domain_list:
        domain_list = [domain.strip() for domain in domain_list.split(",")]

    # Validate domains
    results = dns_bulk_domain_validation(domain_list)

    return results



# @app.get("/")
# async def root():
#     return {"message": "Main FastAPI app is running. Check /syntax, /deliverability, or /dns for endpoints."}


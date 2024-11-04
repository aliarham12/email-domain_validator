import re
import smtplib
import dns.resolver
import csv
from concurrent.futures import ThreadPoolExecutor
import functools

# DNS cache to store resolved domains
dns_cache = {}

# Syntax validation using regex
def is_valid_syntax(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

# Cached DNS lookup to avoid redundant queries
@functools.lru_cache(maxsize=100)
def cached_dns_lookup(domain):
    if domain not in dns_cache:
        dns_cache[domain] = dns.resolver.resolve(domain, 'MX')
    return dns_cache[domain]

# DNS validation by checking MX records
def check_dns(email):
    domain = email.split('@')[1]
    try:
        records = cached_dns_lookup(domain)
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return False

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
        # If the server disconnects prematurely
        print(f"Server disconnected: {domain}")
        return False
    except smtplib.SMTPConnectError:
        # If there's an issue connecting to the SMTP server
        print(f"SMTP connection error: {domain}")
        return False
    except smtplib.SMTPRecipientsRefused:
        # If the recipient is refused
        print(f"Recipient refused: {email}")
        return False
    except Exception as e:
        # Handle any other exceptions
        print(f"General SMTP error with {email}: {e}")
        return False

# Function to validate email addresses
def validate_email(email):
    syntax_valid = is_valid_syntax(email)
    if syntax_valid:
        dns_valid = check_dns(email)
        if dns_valid:
            deliverable = smtp_check(email)
        else:
            deliverable = False
    else:
        dns_valid = False
        deliverable = False
    
    return {
        "Syntax Validation": "Valid" if syntax_valid else "Invalid",
        "DNS Record Validation": "Success" if dns_valid else "Failed",
        "Deliverable": "Yes" if deliverable else "No"
    }

# Function to handle a list of emails with threading
def bulk_email_validation(email_list):
    results = []

    # Thread-safe list append
    def validate_and_append(email):
        result = validate_email(email)
        result["Mail Address"] = email
        results.append(result)
    
    # Using ThreadPoolExecutor to run tasks in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:  # Adjust number of workers as needed
        executor.map(validate_and_append, email_list)

    return results

# Function to read emails from CSV
def read_emails_from_file(filename):
    emails = []
    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            emails.extend(row)
    return emails

# Main function to handle inputs
def main():
    input_emails = input("Enter email(s) separated by commas or provide a CSV file path: ")
    
    if input_emails.endswith(".csv"):
        email_list = read_emails_from_file(input_emails)
    else:
        email_list = [email.strip() for email in input_emails.split(",")]
    
    results = bulk_email_validation(email_list)
    
    print("\nValidation Results")
    print("{:<30} {:<20} {:<20} {:<20}".format("Mail Address", "Syntax Validation", "DNS Record Validation", "Deliverable"))
    for result in results:
        print("{:<30} {:<20} {:<20} {:<20}".format(result["Mail Address"], result["Syntax Validation"], result["DNS Record Validation"], result["Deliverable"]))

if __name__ == "__main__":
    main()

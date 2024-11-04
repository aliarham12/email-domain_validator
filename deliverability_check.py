import smtplib
import dns.resolver
import csv
from concurrent.futures import ThreadPoolExecutor
import functools

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
    print("{:<30} {:<20}".format("Mail Address", "Deliverable"))
    for result in results:
        print("{:<30} {:<20} ".format(result["Mail Address"], result["Deliverable"]))

if __name__ == "__main__":
    main()

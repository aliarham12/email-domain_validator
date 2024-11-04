import dns.resolver
import whois
import csv
from concurrent.futures import ThreadPoolExecutor

# Function to fetch DNS records (A, MX, TXT, CNAME)
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
            'Registrant': whois_info.get('registrant_name', 'N/A'),
            'Registrar': whois_info.get('registrar', 'N/A'),
            'Creation Date': whois_info.get('creation_date', 'N/A'),
            'Expiration Date': whois_info.get('expiration_date', 'N/A'),
            'Status': whois_info.get('status', 'N/A')
        }
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# Function to validate domain (DNS records + WHOIS info)
def validate_domain(domain):
    dns_records = get_dns_records(domain)
    whois_info = get_whois_info(domain)

    return {
        "Domain": domain,
        "DNS Records": dns_records,
        "WHOIS Info": whois_info
    }

# Function to handle a list of domains with threading
def bulk_domain_validation(domain_list):
    results = []

    def validate_and_append(domain):
        result = validate_domain(domain)
        results.append(result)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(validate_and_append, domain_list)

    return results

# Function to read domains from CSV
def read_domains_from_file(filename):
    domains = []
    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            domains.extend(row)
    return domains

# Main function to handle inputs
def main():
    input_domains = input("Enter domain(s) separated by commas or provide a CSV file path: ")
    
    if input_domains.endswith(".csv"):
        domain_list = read_domains_from_file(input_domains)
    else:
        domain_list = [domain.strip() for domain in input_domains.split(",")]
    
    results = bulk_domain_validation(domain_list)
    
    print("\nValidation Results")
    for result in results:
        print(f"\nDomain: {result['Domain']}")
        print("DNS Records:", result['DNS Records'])
        print("WHOIS Info:", result['WHOIS Info'])

if __name__ == "__main__":
    main()

# import dns.resolver
# import csv
# from concurrent.futures import ThreadPoolExecutor
# import functools

# # DNS cache to store resolved domains
# dns_cache = {}

# # Cached DNS lookup to avoid redundant queries
# @functools.lru_cache(maxsize=100)
# def cached_dns_lookup(domain):
#     if domain not in dns_cache:
#         dns_cache[domain] = dns.resolver.resolve(domain, 'MX')
#     return dns_cache[domain]

# # DNS validation by checking MX records
# def check_dns(email):
#     domain = email.split('@')[1]
#     try:
#         records = cached_dns_lookup(domain)
#         return True
#     except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
#         return False

# # Function to validate email addresses
# def validate_email(email):
#     dns_valid = check_dns(email)
    
#     return {
#         "Mail Address": email,
#         "DNS Record Validation": "Success" if dns_valid else "Failed"
#     }

# # Function to handle a list of emails with threading
# def bulk_email_validation(email_list):
#     results = []

#     def validate_and_append(email):
#         result = validate_email(email)
#         results.append(result)
    
#     with ThreadPoolExecutor(max_workers=10) as executor:
#         executor.map(validate_and_append, email_list)

#     return results

# # Function to read emails from CSV
# def read_emails_from_file(filename):
#     emails = []
#     with open(filename, newline='') as csvfile:
#         reader = csv.reader(csvfile)
#         for row in reader:
#             emails.extend(row)
#     return emails

# # Main function to handle inputs
# def main():
#     input_emails = input("Enter email(s) separated by commas or provide a CSV file path: ")
    
#     if input_emails.endswith(".csv"):
#         email_list = read_emails_from_file(input_emails)
#     else:
#         email_list = [email.strip() for email in input_emails.split(",")]
    
#     results = bulk_email_validation(email_list)
    
#     print("\nValidation Results")
#     print("{:<30} {:<20}".format("Mail Address", "DNS Record Validation"))
#     for result in results:
#         print("{:<30} {:<20}".format(result["Mail Address"], result["DNS Record Validation"]))

# if __name__ == "__main__":
#     main()



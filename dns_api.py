import dns.resolver
import whois
import csv
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from typing import List
import io

app = FastAPI()

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

# Function to read domains from a CSV file
def read_domains_from_file(file):
    domains = []
    file_content = io.StringIO(file.decode('utf-8'))
    reader = csv.reader(file_content)
    for row in reader:
        domains.extend(row)
    return domains

# API endpoint to validate domains
@app.post("/validate-domains/")
async def validate_domains(domain_list: str = Form(None), file: UploadFile = File(None)):
    # Check if both domain_list and file are provided
    if domain_list and file:
        raise HTTPException(status_code=400, detail="Provide either domain list or CSV file, not both.")

    # If neither is provided
    if not domain_list and not file:
        raise HTTPException(status_code=400, detail="No input provided. Please provide either a list of domains or a CSV file.")

    # Handle CSV file input
    if file:
        domain_list = read_domains_from_file(await file.read())

    # Handle comma-separated domain input
    elif domain_list:
        domain_list = [domain.strip() for domain in domain_list.split(",")]

    # Validate domains
    results = bulk_domain_validation(domain_list)

    return {"validation_results": results}

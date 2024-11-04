import re
import csv
from concurrent.futures import ThreadPoolExecutor

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
    print("{:<30} {:<20}".format("Mail Address", "Syntax Validation"))
    for result in results:
        print("{:<30} {:<20}".format(result["Mail Address"], result["Syntax Validation"]))

if __name__ == "__main__":
    main()

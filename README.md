How it works:
Syntax Validation: Validates if the email format is correct using regex.
DNS Validation: Uses the dnspython library to check if the domain has valid MX records.
Deliverability Check (SMTP Check): Uses the smtplib to connect to the mail server and check if the email exists.
Instructions:
Input: You can either enter a comma-separated list of emails or specify a CSV file containing emails.
Output: The script will display results for each email, showing whether the email is valid based on syntax, DNS validation, and deliverability.

1. Make sure to install the required libraries:

    ```bash
    pip install dnspython
    ```

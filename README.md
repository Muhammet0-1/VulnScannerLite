# 🛡️ VulnScannerLite

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)

**VulnScannerLite**, web uygulamalarındaki yaygın güvenlik açıklarını (XSS, SQL Injection) tespit etmek için geliştirilmiş, nesne yönelimli (OOP) mimariye sahip hafif bir güvenlik aracıdır.

## 🚀 Özellikler

* **Akıllı Form Analizi:** Sayfadaki tüm formları (`input`, `textarea`, `select`) otomatik algılar ve ayrıştırır.
* **WAF Bypass (Basic):** Gerçek bir tarayıcı gibi davranmak için `User-Agent` rotasyonu kullanır.
* **Session Management:** `requests.Session` yapısı ile daha hızlı ve kararlı bağlantı sağlar.
* **Payload Injection:** XSS ve SQLi için optimize edilmiş payload listeleri kullanır.
* **Detaylı Loglama:** Hem konsola renkli çıktı verir hem de `scan_results.txt` dosyasına kayıt tutar.

## 🛠️ Kurulum

```bash
# Projeyi klonlayın
git clone [https://github.com/Muhammet0-1/VulnScannerLite.git](https://github.com/Muhammet0-1/VulnScannerLite.git)

# Klasöre girin
cd VulnScannerLite

# Gerekli kütüphaneleri yükleyin
pip install requests beautifulsoup4

💻 Kullanım
Bash

python scanner.py

Program sizden hedef URL'yi isteyecektir. Örnek: http://testphp.vulnweb.com
⚠️ Yasal Uyarı

Bu araç sadece eğitim ve yetkili güvenlik testleri (Pentest) için geliştirilmiştir. İzniniz olmayan sistemlerde kullanmak yasa dışıdır. Geliştirici, kötüye kullanımdan sorumlu değildir.

# 🔍 Simple Vulnerability Scanner (XSS, SQLi, LFI)

Bu Python scripti, temel güvenlik açıklarını tespit edebilen bir tarayıcıdır. CV'ye eklenebilecek bir proje olarak geliştirildi.

## ✨ Özellikler

- 📎 Form bazlı **XSS Tespiti**
- 🔍 GET ve Form tabanlı **SQL Injection (SQLi) Taraması**
- 📂 Parametre bazlı **Local File Inclusion (LFI) Taraması**
- 📝 Otomatik zaman damgalı **rapor dosyası oluşturma** (`scan_results.txt`)
- 🎯 Kullanıcı dostu menülü yapı

## 🚀 Kullanım

1. Gerekli modülleri yükle:
```bash
pip install requests beautifulsoup4

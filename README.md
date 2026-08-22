# VulnScannerLite

[![CI](https://github.com/Muhammet0-1/VulnScannerLite/actions/workflows/ci.yml/badge.svg)](https://github.com/Muhammet0-1/VulnScannerLite/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10--3.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

VulnScannerLite, açıkça yetkilendirilmiş tek bir HTTP(S) URL'si için sınırlı ve kanıta dayalı güvenlik duruşu
denetimi yapan bir komut satırı aracıdır. Varsayılan çalışma pasiftir: bir sayfayı `GET` ile alır, yanıt
başlıklarını, çerez niteliklerini ve form metadata'sını inceler. Form göndermez, payload çalıştırmaz ve açık
istismar ettiğini iddia etmez.

> Yalnızca sahibi olduğunuz veya yazılı test izni aldığınız sistemlerde kullanın. Araç kullanımı üçüncü taraf
> sistemleri test etme yetkisi vermez.

## Neden yeniden tasarlandı?

İlk prototip XSS ve SQL injection payload'ları gönderiyor, formları otomatik olarak submit ediyor ve tarayıcı
User-Agent değerleriyle "WAF bypass" iddiasında bulunuyordu. Bunlar küçük bir denetim aracı için gereksiz risk,
yanlış pozitif ve kapsam aşımı oluşturuyordu. Sürüm 1.0 bu davranışları kaldırır ve dürüst bir posture-audit
modeli kullanır.

## Güvenlik modeli

- Loopback, RFC1918 ve IPv6 ULA adresleri varsayılan olarak kullanılabilir; global hedefler ayrıca
  `--allow-public-target` ister.
- DNS bir kez çözülür. Onaylanan adres kümesi raporlanır ve bağlantı seçilen IP'ye sabitlenir.
- `HTTP_PROXY`, `HTTPS_PROXY` ve benzeri ortam proxy'leri kullanılmaz.
- HTTPS sertifikası ve SNI, kullanıcının verdiği özgün alan adıyla doğrulanır.
- Yalnızca aynı origin yönlendirmeleri izlenir; yönlendirme sayısı ve gövde boyutu sınırlıdır.
- Formlar yalnızca parse edilir; hiçbir form gönderilmez.
- Kimlik doğrulama, cookie jar, crawling, parola denemesi, SQLi/XSS payload'ı ve evasion özelliği yoktur.

## Kurulum

```bash
git clone https://github.com/Muhammet0-1/VulnScannerLite.git
cd VulnScannerLite
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Çalışma zamanı yalnızca Python standart kütüphanesini kullanır.

## Kullanım

Yerel geliştirme sunucusunu pasif denetlemek:

```bash
vulnscanner-lite \
  --url http://127.0.0.1:8000/ \
  --acknowledge-authorization
```

Yetkilendirilmiş global bir hedef için:

```bash
vulnscanner-lite \
  --url https://authorized.example/ \
  --acknowledge-authorization \
  --allow-public-target \
  --format json
```

İsteğe bağlı reflection kontrolü yalnızca rastgele, etkisiz bir metin token'ı ekleyen ikinci bir `GET` isteği
gönderir:

```bash
vulnscanner-lite \
  --url http://127.0.0.1:8000/search \
  --acknowledge-authorization \
  --active-reflection
```

Token'ın yanıtta görülmesi yalnızca reflection gözlemidir; **XSS kanıtı değildir**. Araç script etiketi,
SQL sözdizimi veya başka bir saldırı payload'ı göndermez.

Önemli seçenekler:

| Seçenek | Davranış |
| --- | --- |
| `--timeout 5` | DNS çözümlemesinden sonraki HTTP işlemi için 0.1-30 saniye mutlak sınır |
| `--max-body-bytes 1048576` | En fazla 5 MiB olacak yanıt gövdesi sınırı |
| `--max-redirects 3` | En fazla 5 aynı-origin yönlendirme |
| `--format text\|json\|jsonl` | İnsan veya makine tarafından okunabilir çıktı |
| `--fail-on low\|medium` | Eşik karşılanırsa çıkış kodu `3` |

Tam yardım:

```bash
vulnscanner-lite --help
```

Eski `scanner.py` dosyası yalnızca yeni CLI'a yönlendiren uyumluluk katmanıdır:

```bash
python scanner.py --help
```

## Denetimler

- HTTP/TLS kullanımı ve HSTS
- CSP, framing, MIME sniffing, Referrer-Policy ve Permissions-Policy
- CORS wildcard gözlemi ve gereksiz teknoloji başlıkları
- `Secure`, `HttpOnly` ve `SameSite` çerez nitelikleri
- Şifre alanlarının HTTP veya GET formunda bulunması
- Geçersiz ve cross-origin form action değerleri
- İsteğe bağlı, etkisiz query reflection canary'si

Bu kontroller bağlamdan bağımsız gözlemlerdir. Eksik bir başlık her zaman açık değildir; var olan bir başlık da
uygulamanın güvenli olduğunu garanti etmez.

## Çıkış kodları

| Kod | Anlam |
| --- | --- |
| `0` | Denetim tamamlandı ve seçili eşik aşılmadı |
| `1` | Çözümleme, bağlantı, TLS veya raporlama hatası |
| `2` | CLI/kullanıcı girdisi hatası |
| `3` | `--fail-on` eşiği karşılandı |
| `130` | Kullanıcı kesintisi |

## Sınırlamalar

Araç tek origin ve tek sayfa düzeyinde çalışır. JavaScript çalıştırmaz; DOM tabanlı sorunları, oturum gerektiren
akışları, API yetkilendirmesini veya iş mantığı açıklarını doğrulamaz. Sıkıştırılmış gövdeleri açmaz. İlk güvenli
ve deterministik IP'yi kullanır; diğer çözümlenen adresleri rapora dahil eder. Sonuçlar manuel inceleme ve hedefe
özgü risk değerlendirmesi gerektirir.

## Geliştirme

```bash
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
mypy
pytest
python -m build
```

Testler sahte resolver ve transport kullanır; gerçek DNS veya HTTP bağlantısı kurmaz.

## Güvenlik ve lisans

Güvenlik bildirimleri için [SECURITY.md](SECURITY.md), katkı süreci için
[CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın. Proje [MIT Lisansı](LICENSE) ile sunulur.

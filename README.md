# SecureScoreLens — 3.2.3-preview.1

**Read-only Microsoft 365 Secure Score assessment and offline Turkish reporting.**
A synthetic demo and source-backed remediation catalogue are included; this preview does not change tenant settings.

Microsoft 365 Secure Score verisini Türkçe, çevrimdışı açılan HTML rapora dönüştürür. Microsoft puanı/durumları ile aracın etki önceliklendirme modeli ayrı kavramlardır. **Önizleme sürümüdür; üretim veya tüm içerik için doğruluk garantisi değildir.**

## Windows 11 hızlı başlangıç

1. ZIP'i **Tümünü ayıkla** ile tamamen çıkarın. GitHub'a yüklemek için ZIP'i değil içindeki dosyaları kullanın.
2. Windows PowerShell **5.1** veya üstü gerekir. `BASLAT.cmd` Windows'un `powershell.exe` uygulamasını çağırır; **PowerShell 7 zorunlu değildir**. PowerShell 7 ile `pwsh` komutu alternatif olabilir; bu sürümde Windows üzerinde çalıştırılarak doğrulanmadı.
3. **Python 3.8+** ve standart kütüphane yeterlidir; pip/npm paket kurulumu gerekmez. Güncel, desteklenen Python 3 sürümü tercih edin. `python --version` ile denetleyin. Başlatıcı `python`, `python3`, `py` arar. Python bulunmazsa modül kullanıcı kapsamındaki Python 3.12 için `winget` kurulumu dener; bu Windows davranışı burada çalıştırılmadı. Elle kurup terminali yeniden açmak daha öngörülebilirdir.
4. Önce ağ/tenant oturumu olmadan sentetik raporu deneyin; PowerShell terminalini çıkarılan depo kökünde açın:

```powershell
.\BASLAT.cmd -Demo
.\BASLAT.cmd -SelfTest
```

Gerçek değerlendirme için:

```powershell
.\BASLAT.cmd
# İsteğe bağlı hedef ve çıktı klasörü; gerçek değerleri yalnız yerel terminalde girin:
.\BASLAT.cmd -TenantId '<tenant-id>' -OutputFolder '.\Raporlar'
```

Normal çalıştırmada tarayıcıda Microsoft oturum açma/izin ekranı açılır; internet ve loopback callback erişimi gerekir. Yerel yönetici olarak terminal açmak gerekmez. Başlatıcı paket dosyalarındaki indirme engelini kaldırmayı dener ve süreç için ExecutionPolicy Bypass kullanır; kurumsal güvenlik ilkelerini aşmayın, önce kaynakları inceleyin. Kalıcı modül kurulumu **gerekmez**; `Istege-Bagli-Kalici-Kurulum.ps1` yalnız isteğe bağlıdır.

Çıktılar varsayılan `Raporlar/` altındadır. **Rapor, ham JSON, CSV/XLSX, log ve tenant bilgileri hassastır; GitHub'a yüklemeyin.** `.gitignore` bir veri kaybı önleme sistemi değildir; önceden izlenen dosyaları temizlemez.

Sadece hazır sentetik arayüzü görmek için `SecureScoreLens-Secenekler-TR-ONIZLEME.html` dosyasını yerel tarayıcıda açın. Demo puanları gerçek müşteri ölçümü değildir. Bu dosya onaylı önizlemeyle byte-identical tutulmuştur; GitHub yayın sürümü dosyanın içine sonradan yazılmamıştır.

## Microsoft API izinleri ve roller

- `SecurityEvents.Read.All`: Secure Score için gerekli salt-okunur Graph izni.
- `Organization.Read.All`: kurum adı/alan adı için isteğe bağlı veriye erişim. **Mevcut etkileşimli akış iki izni birlikte ister**; bu yayın izin istemini veya kimlik doğrulamayı değiştirmez.
- Mevcut akış authorization code + PKCE S256, loopback callback ve state kontrolü kullanır; token süreç belleğindedir. Microsoft'un kamuya açık first-party istemci kimliği bir sır değildir ve korunmuştur. Token içeren ekran/diagnostic paylaşmayın. `-AppOnly` mevcut ileri kullanım yoludur; varsayılan hızlı başlangıç değildir ve burada doğrulanmadı.
- Yönetici onayı tenant politikasına göre gerekebilir. **İzin/onay verme yetkisi ile günlük veri okuma rolü farklıdır.** Onayı kuruluşun yetkili yöneticisi versin; günlük okuma için uygun en az ayrıcalıklı rolü (ör. ilgili hizmetin Security Reader yetkisi) yöneticinizle doğrulayın. Rutin çalıştırmayı Global Administrator hesabıyla yapmayı önermiyoruz. Rol, lisans ve veri kapsamı API sonucunu etkileyebilir; yalnız izin verilmiş olması tüm verilere erişimi garanti etmez.
- Yeni hunting izni, portal scraping, yazma API'si, otomatik düzeltme veya deployment eklenmedi.

## Güncel içerik kapsamı

| Kapsam | Sayı / sınır |
|---|---|
| Envanter | 460 kontrol; tamamı tenant'ta geçerli veya içerik olarak doğrulanmış demek değildir |
| Cihaz ayrıntılı seçenekleri | **120/184 kontrol, 134 seçenek** |
| Önceki kabul edilen seçenekler | **33 kontrol / 41 seçenek** nesneleri korunur |
| Cihaz incelemesi bekleyenler | **64**; seçenek olmadığı anlamına gelmez |
| Türkçe How-to | 275 açıklamalı yönerge + 184 cihaz yönlendirmesi + 1 kaynak adımı yok |
| Etki çevirileri | 460 kaynak-hash bağlı kayıt |
| Canlı portal/tenant doğrulaması | **0** |

Kaynak/başlık/kategori/hash bağı kontrol edilir. Kaynak eşleşmesi, teknik korumanın uygulanmış veya puan kazanılmış olduğunun kanıtı değildir. Kamuya açık Microsoft Learn yönergeleri portalın tüm Remediation options listesinin birebir dökümü değildir. Güncel kaynak defteri: [docs/README.md](docs/README.md), [coverage.json](docs/coverage.json). Manuel baskı/PDF sayfa kırılmaları, Windows oturumu ve gerçek tenant uçtan uca testi yapılmadı.

## Geliştirme ve tekrar çalıştırılabilir testler

Depo kökünde, temiz çıkarılan ZIP üzerinde:

```sh
python Modul/assets/secure_score_assessment.py --self-test
python -m unittest discover -s tests -v
node --check tests/generated.js
node --check tests/browser-check.js
```

Node yalnız JavaScript doğrulaması ve isteğe bağlı tarayıcı testi içindir; uygulamayı çalıştırmak için gerekmez. Unit suite 31 test, motor self-test'i 51 denetim içerir. `tests/generated.js`, unit test tarafından motordan yeniden üretilir. Browser testi mevcut Chromium/CDP ve Node'un yerleşik `fetch`/`WebSocket` desteğini gerektirir (Node 22+); talimatlar [CONTRIBUTING.md](CONTRIBUTING.md). CI yalnız bu offline testleri çalıştırır; token, tenant, ağ API'si veya deployment kullanmaz. Taze yerel sonuçlar: [PUBLICATION-CHECKS.md](PUBLICATION-CHECKS.md).

## Yayın ve lisans

GitHub yükleme adımları: [GITHUB-YUKLEME.md](GITHUB-YUKLEME.md). Etiket: `v3.2.3-preview.1`; GitHub Release **pre-release** işaretlenmelidir. Mantıksal sürüm `3.2.3-preview.1`; PowerShell manifesti `ModuleVersion=3.2.3`, PowerShellGet'in alfanümerik prerelease etiketi `preview1` kullanır. Galeriye otomatik yayın yoktur.

Onaylı `v3.2.2-Secenekler-TR-ONIZLEME` kaynağı esas alınmıştır; özgün v3.2.2 baseline değiştirilmedi. Kaynak SHA-256 ve dosya bütünlüğü [SOURCE-PROVENANCE.json](SOURCE-PROVENANCE.json), [SHA256SUMS.txt](SHA256SUMS.txt) içindedir. Son dosya kendisini hash'lemez.

Mevcut [LICENSE](LICENSE) aynen korunmuştur; yeni lisans veya ek hak sahipliği iddiası eklenmedi. [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), [release-notes.md](release-notes.md).

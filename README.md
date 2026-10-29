# SecureScoreLens

**Microsoft 365 Secure Score'u, müşteriye sunulabilir bir güvenlik değerlendirme raporuna dönüştürür.**

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)](https://learn.microsoft.com/powershell/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB)](https://www.python.org/)
[![Salt okunur](https://img.shields.io/badge/eri%C5%9Fim-salt%20okunur-00A14B)](#güvenlik)
[![Lisans: MIT](https://img.shields.io/badge/lisans-MIT-blue)](LICENSE)

Tenant'ınıza salt-okunur bağlanır, API'nin erişilebilir Secure Score puanlarını ve iyileştirme profillerini okur; sonucu **tek dosyalık, çevrimdışı açılan, Türkçe** bir HTML rapora dönüştürür. Tenant ayarlarını değiştirmez. Varsayılan etkileşimli akışta parola yalnız Microsoft ekranına girilir; erişim token'ı süreç belleğinde tutulur, kalıcı olarak kaydedilmez.

**3.2.3** Sentetik demo ve kaynak bağlantılı iyileştirme kataloğu içerir; üretim, tüm içerik, teknik koruma veya Secure Score kazanımı için doğruluk garantisi değildir. Microsoft puanları/durumları ile aracın etki önceliklendirme modeli ayrı kavramlardır.

<img width="1280" height="637" alt="banner" src="https://github.com/user-attachments/assets/629bfac4-7a38-451f-b6f9-c412577e50ce" />

---

## Bu araç ne işe yarar?

Microsoft Secure Score portalı size bir puan ve uzun bir öneri listesi verir. Bu listeyi müşteriye sunulabilir bir belgeye çevirmek, çoğu zaman elle yapılan bir danışmanlık işidir. SecureScoreLens bu raporlama ve önceliklendirme işini kolaylaştırır; uzman incelemesinin veya tenant üzerinde doğrulamanın yerine geçmez.

| Portalın verdiği | SecureScoreLens'in ürettiği |
|---|---|
| Puan ve öneri listesi | Yönetici özeti, risk duruşu, öncelik sıralı yol haritası |
| Öneri ve kaynak yönergeleri | Mevcut içerik kapsamına göre Türkçe açıklama, etki analizi, ortam bağımlılığı ve doğrulama rehberi; eksik içerik için açık sınırlar |
| Microsoft'un puan ve sıralama alanları | Microsoft sınıflandırmasından ayrı, formülü raporda açıklanan **etki önceliklendirme modeli** |
| Anlık ölçümler | Yeterli anlık görüntü varsa puan değişimine ilişkin kapsam ve ilerleme analizi |
| Canlı portal | Çevrimdışı açılan tek dosya ve tarayıcı yazdırma akışıyla **PDF çıktısı** |
| Standart sunum | **Kendi logonuz, renginiz ve kapak sayfanız** |

---

## Amacı

Secure Score önerilerini teknik bir kontrol listesi seviyesinden çıkarıp **yönetilebilir, önceliklendirilebilir ve aksiyon alınabilir** bir güvenlik iyileştirme yol haritasına dönüştürmek.

Üç tasarım ilkesi üzerine kuruludur:

1. **Doğruluk her şeyden önce gelir.** Microsoft'un tenant ölçümündeki mevcut puanı ve maksimum puanı korunur; gösterilen yüzde bu değerlerin oranından hesaplanır. Microsoft'un maksimum puanı araç tarafından lisans varsayımıyla yeniden yazılmaz. Anlık görüntüde bulunmayan bir kontrol tek başına lisans yokluğu kanıtı değildir. Veri yoksa uydurulmaz; bilgi/kapsam sınırı belirtilir.
2. **Salt okunur değerlendirme.** Değerlendirme verisi Microsoft Graph'tan `GET` ile okunur. Kimlik doğrulamanın token uç noktasına yaptığı `POST`, tenant ayarı değiştirmek değildir. Araç otomatik düzeltme veya deployment yapmaz.
3. **Yöntem açıklanır.** Risk seviyeleri Microsoft'un sınıflandırması değildir; aracın etki önceliklendirme modeliyle hesaplanır ve **formülü raporun içinde yazar.** Puan projeksiyonları ve yol haritası kazanımları uygulama veya sonuç garantisi değildir.

---

## Nasıl çalıştırılır?

### Gereksinimler

| Gereksinim | Not |
|---|---|
| Windows / PowerShell | Windows 11 hızlı başlangıcı hedeflenir. Windows PowerShell **5.1 veya üstü** gerekir. `BASLAT.cmd`, Windows'un `powershell.exe` uygulamasını çağırır; **PowerShell 7 zorunlu değildir**. `pwsh` alternatif olabilir, ancak bu sürüm Windows üzerinde çalıştırılarak doğrulanmadı. |
| Python 3.8+ | Standart kütüphane yeterlidir; pip/npm paketi gerekmez. Güncel, desteklenen Python 3 sürümü tercih edin. Başlatıcı/modül `python`, `python3`, `py` arar. Bulamazsa kullanıcı kapsamında Python 3.12 için `winget` kurulumu dener; başarı garantisi yoktur. |
| Hesap ve onay | Secure Score verisini okumaya yetkili hesap gerekir. Yönetici onayı tenant politikasına bağlıdır; onay verme yetkisi ile günlük veri okuma rolü farklıdır. Ayrıntılar [Microsoft API izinleri ve roller](#microsoft-api-izinleri-ve-roller) bölümündedir. |
| İnternet ve callback | Gerçek değerlendirme için Microsoft oturum açma/izin ekranına, Graph'a ve yerel loopback callback'e erişim gerekir. Sentetik demo tenant oturumu gerektirmez. |

`python --version` ile Python'u kontrol edin. Python'u önceden elle kurup terminali yeniden açmak daha öngörülebilirdir. Uygulamayı çalıştırmak için Node gerekmez.

Varsayılan etkileşimli yol Microsoft'un kamuya açık first-party istemci kimliğini kullanır; bu yol için ayrıca tenant uygulama kaydı veya yönetilecek bir client secret gerekmez. Bu kimlik bir sır değildir. `-AppOnly` mevcut ileri kullanım yoludur; varsayılan hızlı başlangıç değildir ve burada doğrulanmadı.

### Kalıcı modül kurulumu gerektirmeyen yol (önerilen)

1. [Releases](../../releases) sayfasından **`v3.2.3` önizleme** paketini indirin.
2. ZIP'e sağ tıklayın → **Tümünü ayıkla**. ZIP'in içinden doğrudan çalıştırmayın. GitHub'a yükleyecekseniz ZIP'i değil, ayıklanan depo dosyalarını kullanın; bkz. [GITHUB-YUKLEME.md](GITHUB-YUKLEME.md).
3. Önce PowerShell terminalini ayıklanan depo kökünde açıp ağ/tenant oturumu olmadan sentetik raporu ve motor denetimlerini deneyin:

```powershell
.\BASLAT.cmd -Demo
.\BASLAT.cmd -SelfTest
```

Gerçek değerlendirme için `BASLAT.cmd` dosyasına çift tıklayın veya:

```powershell
.\BASLAT.cmd
# Gerçek değerleri yalnız yerel terminalinizde girin:
.\BASLAT.cmd -TenantId '<tenant-id>' -OutputFolder '.\Raporlar'
```

Normal çalıştırmada tarayıcıda Microsoft oturum açma/izin ekranı açılır. Yerel yönetici olarak terminal açmak gerekmez; `PSModulePath` değiştirilmez ve kalıcı modül kurulumu gerekmez. **Bu, hiçbir şey kurulamayacağı anlamına gelmez:** Python yoksa otomatik `winget` kurulum denemesi yapılabilir. Başlatıcı paket dosyalarının indirme engelini kaldırmayı dener ve süreç için ExecutionPolicy Bypass kullanır. Kurumsal güvenlik ilkelerini aşmayın; önce kaynakları inceleyin. Windows başlatıcı/oturum açma ve otomatik Python kurulumu bu yayın çalışmasında yürütülmedi.

Başlatıcı çıktıları varsayılan **`Raporlar/`** altına yazar. Klasörü kaldırmadan önce raporları ve hassas verileri kuruluşunuzun saklama politikasına göre yönetin; isteğe bağlı kalıcı kurulum yaptıysanız onun kaldırma yolunu da kullanın.

Sadece hazır sentetik arayüzü görmek için [SecureScoreLens-Secenekler-TR-ONIZLEME.html](SecureScoreLens-Secenekler-TR-ONIZLEME.html) dosyasını indirip yerel tarayıcıda açın. Demo puanları ve atamalar gerçek müşteri ölçümü değildir. Paketlenen HTML onaylı önizlemeyle **byte-identical** tutulmuştur; GitHub yayın sürümü dosyanın içine sonradan yazılmamıştır.

### PowerShell modülü olarak

Depo kökünden:

```powershell
Import-Module .\Modul\SecureScoreLens.psd1 -Force
Invoke-SecureScoreLens -Demo
# Gerçek değerlendirme:
Invoke-SecureScoreLens
```

Modül doğrudan çağrıldığında varsayılan çıktı klasörü geçerli dizindeki **`SecureScoreReport/`** olur; başlatıcının `Raporlar/` varsayılanından farklıdır. Komutu kalıcı kullanılabilir yapmak için depo kökündeki `Istege-Bagli-Kalici-Kurulum.ps1` isteğe bağlıdır; kullanıcı profiline kurar, yönetici gerektirmez ve `-Kaldir` ile geri alınır.

### Sık kullanılan parametreler

Markalama parametreleri modül komutuna verilir; `BASLAT.cmd` sarmalayıcısı bunların tamamını sunmaz:

```powershell
Import-Module .\Modul\SecureScoreLens.psd1 -Force

# Tenant'a bağlanmadan markalı sentetik demo
Invoke-SecureScoreLens -Demo -Provider 'Firmanız' -Logo 'C:\marka\logo.png' `
    -BrandColor '#0070C0' -Customer 'SYNTHETIC DEMO' -Path '.\Raporlar'

# Gerçek tenant, markalı rapor; değerleri yalnız yerel terminalinizde girin
Invoke-SecureScoreLens -TenantId '<tenant-id>' -Provider 'Firmanız' `
    -Customer 'Müşteri A.Ş.' -Path '.\Raporlar'

# Analiz motorunun kendi doğrulama denetimleri
Invoke-SecureScoreLens -SelfTest
```

| Parametre | Ne yapar |
|---|---|
| `-Customer` | Kapakta ve başlıkta görünen kurum adı |
| `-Provider` | Kapakta, başlıkta ve alt bilgide hazırlayan hizmet sağlayıcı |
| `-Logo` | Kapağa/başlığa gömülen logo (png/jpg/gif/svg/webp, en fazla 2 MB) |
| `-BrandColor` | Kapak ve vurgu rengi (`#RRGGBB`); **risk renklerini değiştirmez** |
| `-Path` | Modülün rapor klasörü; başlatıcıda karşılığı `-OutputFolder` |
| `-TenantId` | Hedef tenant; verilmezse oturum açılan tenant |
| `-HistoryDays` | Geçmiş ölçüm isteğinin boyutu; varsayılan 30 |
| `-Demo` / `-SelfTest` | Sentetik veriyle rapor / motor denetimleri |
| `-SkipPythonInstall` | Modül çağrısında otomatik Python kurulum denemesini atlar; Python yine gereklidir |
| `-AppOnly` / `-ClientId` | İleri uygulama kimliği akışı; ayrı yapılandırma ve izin değerlendirmesi gerektirir, burada doğrulanmadı |

> `Invoke-SecureScoreAssessment` eski komut adıdır ve takma ad olarak korunur.

---

## Rapor içeriği

Üretilen HTML **tek dosyadır**, görüntüleme için dış kaynak çağırmaz ve çevrimdışı açılır. Kaynak/portal bağlantılarını takip etmek internet gerektirir. Beş bölümden oluşur:

### 1 · Genel Bakış

Secure Score kartı, yönetici özeti, puan projeksiyonu, kategori dağılımı, etki derecesi kartları, işlem durumu dağılımı ve mevcut geçmiş verisine göre puan trendi. Renkler ve etki/risk yorumları aracın modelidir; Microsoft'un puanı ile karıştırılmamalıdır.

### 2 · Tüm İyileştirme İşlemleri

API ve tenant ölçümlerinden oluşan kapsamdaki maddeler; arama, durum/etki/kategori filtreleri ve sıralama. Satır genişletildiğinde mevcut Microsoft kaynak yönergeleri, tehdit türleri, portal bağlantısı ve içerik kapsamına göre Türkçe açıklamalar görülür. **Sorumlu kişi ve hedef tarih atanabilir**; satırda rozet gösterilir, geçmiş tarih vurgulanır. Bunlar rapor içi takip alanlarıdır; tenant'ta görev veya ayar oluşturmaz. CSV dışa aktarımı ve PDF/yazdırma seçimi rapordaki kriterlerle kullanılır.

Her kontrol için eksiksiz, bağımsız doğrulanmış yapılandırma veya kanıt adımı bulunduğu varsayılmamalıdır. Cihaz yönlendirmeleri ile ayrıntılı seçeneklerin kapsamı [Güncel içerik kapsamı](#güncel-içerik-kapsamı) bölümünde ayrıdır.

### 3 · 30/60/90 Gün Yol Haritası

Açık maddeler etki önceliğine göre üç faza dağıtılır. Her faz için işlem sayısı ve puan kazanım projeksiyonu gösterilir. Plan; kuruluşun lisans, ürün, değişiklik yönetimi ve teknik bağımlılık incelemesinin yerine geçmez. **Her kontrolün uygulanmasıyla öngörülen puanın mutlaka kazanılacağı garanti edilmez.**

### 4 · İlerleme ve Kapsam

Tenant'ın mevcut ölçüm anlık görüntülerini karşılaştırarak puan değişiminin görünen bileşenlerini açıklar: iyileşen/gerileyen kontroller ve ölçüm kapsamına giren/çıkan maddeler. Yüzde düşerken ham puanın artması, maksimum puanın/kapsamın büyümesiyle ilişkili olabilir; sonuç veri üzerinden okunmalıdır. Tek anlık görüntüden değişim nedeni veya lisans durumu kesinleştirilemez.

### 5 · Bulgu Raporu

Açık maddeler için danışmanlık raporu biçiminde bulgu kartları:

| Alan | Kaynak / sınır |
|---|---|
| Bulgu adı, etkilenen kaynak, kategori | Microsoft Graph'ta mevcut alanlar |
| Açıklama, Etkisi | İçerik paketi; kaynak bağlılığı teknik uygulama doğrulaması değildir |
| Risk seviyesi | Aracın etki önceliklendirme modeli |
| İyileştirme → Yapılandırma | Mevcut Microsoft yönergesi veya kaynak yönlendirmesi |
| İyileştirme → Ortam bağımlılığı, Doğrulama | İçerik paketi kapsamı ölçüsünde; her kontrol için eksiksiz veya tenant'ta denenmiş kanıt adımı garantisi yoktur |
| Ek bilgi | Microsoft belge bağlantısı |
| Secure Score kaydı | Mevcut öncelik, puan, kazanım projeksiyonu ve tehdit alanları |

Başta yönetici özeti, raporun amacı ve renk kodlu risk duruşu tablosu yer alır. **PDF olarak indir** düğmesi bu bölümü tarayıcının yazdırma/PDF akışına yönlendirir. Fiziksel baskı, manuel PDF sayfa kırılmaları ve tüm tarayıcı etkileşimleri bu sürüm için taze olarak doğrulanmadı.

---

## Kimler için, ne katkı sağlar?

### Yönetilen hizmet sağlayıcılar ve danışmanlıklar

Değerlendirme raporu hazırlama yükünü azaltır. Logo, renk ve kapak müşteriye veya hizmet sağlayıcıya göre değiştirilebilir. Sorumlu/termin alanları raporu bir **takip aracına** çevirir; müşteri tesliminden önce içerik, veri kapsamı ve PDF çıktısı gözden geçirilmelidir.

### Kurum içi güvenlik ekipleri

Puan ve kapsam değişimlerini incelemeyi, hangi ürün/kontrol grubuna odaklanılacağını tartışmayı ve 30/60/90 günlük plan hazırlamayı kolaylaştırır. Düşük maliyetli kazanımların gerçekten ek bütçe/lisans gerektirip gerektirmediği ortamda ayrıca doğrulanır.

### CISO ve yöneticiler

Teknik liste yerine yönetici özeti, risk duruşu ve aşamalı plan sunar. Microsoft ölçümleri, sentetik demo değerleri ve aracın model/projeksiyonları birbirinden ayrılmalıdır; her rapor sayısı doğrudan tenant ölçümü değildir.

### Denetim ve uyum ekipleri

Kaynak bağlantıları ve mevcut doğrulama rehberleri kanıt toplama planını destekler. **Her bulgu için eksiksiz doğrulama kanıtı sunulduğu iddia edilmez.** Rapor çevrimdışı arşivlenebilir; kontrolün uygulanmış olduğunun veya mevzuat uyumunun kanıtı ayrıca toplanmalıdır.

---

## Güvenlik

- **Salt okunur veri erişimi.** Değerlendirme Graph çağrıları `GET` kullanır; kimlik doğrulamada Microsoft token uç noktasına `POST` yapılır. Tenant ayarı değiştiren yazma API'si, yeni hunting izni, portal scraping, otomatik düzeltme veya deployment eklenmedi.
- **Etkileşimli kimlik doğrulama.** Authorization Code + PKCE S256, loopback callback ve `state` kontrolü kullanılır. Parola araca girilmez; token süreç belleğindedir, kalıcı token kaydı yapılmaz. Bu, bellekten tüm izlerin silindiğine dair adli güvence değildir. Token içeren ekran/diagnostic paylaşmayın.
- **Her etkileşimli çalıştırmada yeniden onay akışı.** Microsoft izin ekranı açılır; sessiz token yeniden kullanımına dayanan bir hızlı başlangıç değildir. İstenen izinler onay öncesi gösterilir.
- **Yerel sertleştirme.** Callback dinleyicisi loopback'e bağlanır; state kontrolü, sınırlı okuma ve sabit hata mesajı eşlemeleri vardır. Raporun dış bağlantıları `http(s)` şemasıyla sınırlandırılır. Bunlar kapsamlı güvenlik denetimi veya açık bulunmadığı garantisi değildir.
- **Hassas çıktı.** Rapor, ham JSON, CSV/XLSX, log, tenant bilgileri ve gerçek müşteri atamaları hassastır; **GitHub'a yüklemeyin**. Token'ın kaydedilmemesi, raporların hassas olmadığı anlamına gelmez. `.gitignore` bir veri kaybı önleme sistemi değildir; içeriği temizlemez ve önceden izlenen dosyaları kaldırmaz.

Güvenlik açığı bildirimi için [SECURITY.md](SECURITY.md).

### Microsoft API izinleri ve roller

| İzin | Amaç ve mevcut davranış |
|---|---|
| `SecurityEvents.Read.All` | Secure Score için gerekli salt-okunur Graph izni |
| `Organization.Read.All` | Kurum adı/alan adı verisi için işlevsel olarak isteğe bağlıdır; **mevcut etkileşimli akış iki izni birlikte ister** |

Bu yayın izin istemini veya kimlik doğrulamayı değiştirmez. Yönetici onayı tenant politikasına göre gerekebilir. **Onay verme yetkisi ile günlük veri okuma rolü farklıdır:** onayı kuruluşun yetkili yöneticisi versin; rutin okumada ilgili hizmet için uygun en az ayrıcalıklı rolü (örneğin uygun Security Reader yetkisi) yöneticinizle doğrulayın. Global Reader'ın her tenant/veri kapsamı için yeterli olduğu varsayılmaz; rutin çalıştırmayı Global Administrator hesabıyla yapmayı önermiyoruz. Rol, lisans ve veri kapsamı API sonucunu etkiler; yalnız izin verilmesi bütün verilere erişimi garanti etmez.

---

## Doğruluk ve sınırlar

- Microsoft'un `/security/secureScores` ölçümündeki mevcut ve maksimum puanları korunur; yüzde bunların oranından hesaplanır. Araç kendi lisans yorumuyla paydayı daraltmaz.
- Tenant anlık görüntüsünde yer almayan kontrol, **otomatik olarak lisans yok veya uygulanamaz** demek değildir. Ölçülen kapsam ile global katalog farklı olabilir; eksiklik rol, lisans, hizmet veya API veri kapsamıyla ilişkili olabilir. Bu araç tenant lisans denetimi yapmış sayılmaz.
- **Risk seviyeleri Microsoft'a ait değildir.** `maxScore`, `rank`, `threats` ve `tier` alanlarını kullanan etki modelinin formülü raporda açıklanır. Öncelik, yapılandırmanın doğruluğu veya koruma kanıtı değildir.
- Kaynak/ID/başlık/kategori/hash bağı kontrol edilir. Kaynak eşleşmesi, teknik korumanın uygulanmış veya puan kazanılmış olduğunun kanıtı değildir. Kamuya açık Microsoft Learn yönergeleri, portalın tüm **Remediation options** listesinin birebir dökümü değildir.
- Microsoft Graph'ın `complianceInformation` alanına ilişkin [kaynak belgesi](https://learn.microsoft.com/graph/api/resources/securescorecontrolprofile) mevcut uygulama sınırını belirtir; araç bu alandan **CIS/NIST/ISO eşlemesi iddia etmez**.
- Secure Score bir güvenlik duruşu özetidir; **ihlal olasılığının mutlak ölçüsü değildir**. Eksik içerik, örnek veri ve test sınırları değerlendirmede dikkate alınmalıdır.

### Güncel içerik kapsamı

| Kapsam | Sayı / sınır |
|---|---|
| Envanter | **460 kontrol**; tamamı tenant'ta geçerli veya içerik olarak bağımsız doğrulanmış demek değildir |
| Cihaz ayrıntılı seçenekleri | **120/184 kontrol, 134 seçenek** |
| Önceki kabul edilen seçenekler | **33 kontrol / 41 seçenek** nesneleri yapısal olarak korunur |
| Cihaz incelemesi bekleyenler | **64**; seçenek olmadığı anlamına gelmez |
| Türkçe How-to | **275** açıklamalı yönerge + **184** cihaz yönlendirmesi + **1** kaynak adımı yok |
| Etki çevirileri | **460** kaynak-hash bağlı kayıt |
| Canlı portal / gerçek tenant içerik doğrulaması | **0** |

Kaynak defteri ve kapsam ayrıntıları: [docs/README.md](docs/README.md), [docs/coverage.json](docs/coverage.json). İçerik kapsamı ile tenant'ta uygulama/kanıt doğrulaması ayrı tutulmalıdır.

---

## Depo yapısı

Aşağıdaki yollar **3.2.3** paketinin depo köküne göredir:

```text
SecureScoreLens/
├─ BASLAT.cmd                         Windows hızlı başlangıç
├─ BASLAT.ps1                         PowerShell başlatıcısı
├─ Istege-Bagli-Kalici-Kurulum.ps1     İsteğe bağlı kurulum/kaldırma
├─ Modul/
│  ├─ SecureScoreLens.psd1             PowerShell manifesti
│  ├─ SecureScoreLens.psm1             PowerShell modülü
│  └─ assets/
│     ├─ secure_score_assessment.py    Analiz/HTML motoru (Python stdlib)
│     ├─ secure_score_tr.json          Türkçe içerik paketi
│     └─ remediation_options_tr.json   Ayrıntılı seçenekler
├─ SecureScoreLens-Secenekler-TR-ONIZLEME.html
├─ docs/                              Kaynak ve kapsam defterleri
├─ tests/                             Offline testler ve sentetik fixture'lar
├─ .github/workflows/ci.yml            Offline CI
├─ PUBLICATION-CHECKS.md
├─ SOURCE-PROVENANCE.json
└─ SHA256SUMS.txt
```

Eski `src/`, `module/SecureScoreLens/` ve `launcher/` örnekleri bu paketin çalıştırma yolları değildir; motor **`Modul/assets/`**, başlatıcılar **depo kökü** altındadır.

### Geliştirme ve tekrar çalıştırılabilir testler

Temiz ayıklanan ZIP'in depo kökünde:

```sh
python Modul/assets/secure_score_assessment.py --self-test
python -m unittest discover -s tests -v
node --check tests/generated.js
node --check tests/browser-check.js
```

Motor self-test'i **51**, unit suite **31** denetim/test içerir. Paketlemenin [PUBLICATION-CHECKS.md](PUBLICATION-CHECKS.md) kaydındaki **2026-10-28 önceki çalıştırmada 82/82 geçti**; iki JavaScript sözdizimi kontrolü de geçti ve 82 toplamına eklenmedi. Bu README birleştirmesi sırasında yeni uygulama, browser, Windows veya tenant testi çalıştırıldığı iddia edilmez.

`tests/generated.js`, unit test tarafından motordan yeniden üretilir. Node yalnız JavaScript doğrulaması ve isteğe bağlı tarayıcı testi içindir. Browser testi mevcut Chromium/CDP ve yerleşik `fetch`/`WebSocket` destekli Node **22+** gerektirir; talimatlar [CONTRIBUTING.md](CONTRIBUTING.md) içindedir. Yayın kontrolündeki taze Chromium denemesi ortam engeli nedeniyle çalışmadı; tarihsel browser sonuçları bu sürümün taze başarısı olarak sunulmaz.

CI yalnız bu offline motor/unit/sözdizimi kontrollerini çalıştırır; token, tenant, ağ API'si veya deployment kullanmaz. Windows 11 başlatıcı/login, PowerShell 5.1/7, gerçek Graph izin/rol davranışı, canlı portal, manuel tarayıcı etkileşimi ve baskı/PDF sayfalaması burada doğrulanmadı. Bilinen sınırlar için [PUBLICATION-CHECKS.md](PUBLICATION-CHECKS.md) ve [CHANGES.md](CHANGES.md).

---

## Katkı

Katkılar memnuniyetle karşılanır — özellikle kaynaklı içerik doğruluğu düzeltmeleri ve eksik cihaz seçeneklerinin incelenmesi. Kapsamı ve kanıt sınırlarını açıkça belirtin; gerçek tenant çıktısı, token veya müşteri verisi eklemeyin. Süreç ve test talimatları için [CONTRIBUTING.md](CONTRIBUTING.md).

## Yayın, bütünlük ve kaynak geçmişi

- GitHub yükleme adımları: [GITHUB-YUKLEME.md](GITHUB-YUKLEME.md). Etiket **`v3.2.3`** olmalı; GitHub Release **pre-release** işaretlenmelidir. Bu README düzenlemesi GitHub'a push, upload veya yayın yapmaz.
- Mantıksal sürüm **`3.2.3`**; PowerShell manifestinde **`ModuleVersion=3.2.3`**, PowerShellGet için alfanümerik prerelease etiketi **`preview1`** kullanılır. Galeriye otomatik yayın yoktur.
- Onaylı **`v3.2.2-Secenekler-TR-ONIZLEME`** kaynağı esas alınmıştır; özgün v3.2.2 baseline değiştirilmedi. Kaynak SHA-256 ve korunma bilgisi [SOURCE-PROVENANCE.json](SOURCE-PROVENANCE.json), paket dosyalarının bütünlük listesi [SHA256SUMS.txt](SHA256SUMS.txt) içindedir. Checksum dosyası kendisini hash'lemez.
- Bu belge paket dışındaki birleştirilmiş README teslimidir; mevcut ZIP, kod veya paket checksum'ları değiştirilmedi. Belgeyi depoda `README.md` yerine koyarsanız, o değişiklik için checksum listesini ve yayın kontrollerini ayrıca güncelleyin; eski checksum'un yeni belgeyi doğruladığını varsaymayın.
- Yayın ayrıntıları: [CHANGELOG.md](CHANGELOG.md), [release-notes.md](release-notes.md), [PUBLICATION-CHECKS.md](PUBLICATION-CHECKS.md). Göreli belge bağlantıları ayıklanan depo kökünde kullanılmak üzere yazılmıştır.

## Lisans

Paketin mevcut **[MIT LICENSE](LICENSE)** dosyası ve mevcut hak sahipliği bildirimi aynen korunur; yeni lisans veya ek hak sahipliği iddiası eklenmez. Microsoft, Microsoft 365, Microsoft Entra ID, Microsoft Defender ve Microsoft Purview, Microsoft Corporation'ın ticari markalarıdır. Bu proje Microsoft ile bağlantılı değildir ve Microsoft tarafından onaylanmamıştır.

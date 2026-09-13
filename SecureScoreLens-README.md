# SecureScoreLens

**Microsoft 365 Secure Score'u, müşteriye sunulabilir bir güvenlik değerlendirme raporuna dönüştürür.**

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)](https://learn.microsoft.com/powershell/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB)](https://www.python.org/)
[![Salt okunur](https://img.shields.io/badge/eri%C5%9Fim-salt%20okunur-00A14B)](#güvenlik)
[![Lisans: MIT](https://img.shields.io/badge/lisans-MIT-blue)](LICENSE)

Tenant'ınıza salt-okunur bağlanır, Secure Score puanını ve kapsamdaki **tüm** iyileştirme
işlemlerini okur, sonucu **tek dosyalık, çevrimdışı çalışan, Türkçe** bir HTML rapora
dönüştürür. Tenant üzerinde hiçbir değişiklik yapmaz, hiçbir kimlik bilgisi saklamaz.

---

## Bu araç ne işe yarar?

Microsoft Secure Score portalı size bir puan ve uzun bir öneri listesi verir. Bu listeyi
bir müşteriye sunulabilir belgeye çevirmek, bugün elle yapılan bir danışmanlık işidir.
SecureScoreLens tam olarak o işi otomatikleştirir.

| Portalın verdiği | SecureScoreLens'in ürettiği |
|---|---|
| Puan ve öneri listesi | Yönetici özeti, risk duruşu, öncelik sıralı yol haritası |
| Her öneri için kısa adım metni | Açıklama, etki analizi, ortam bağımlılığı, **doğrulama adımı** |
| Sıralama var, önem derecesi yok | Formülü raporda açıklanan **etki önceliklendirme modeli** |
| Anlık görünüm | **Puanın neden değiştiği** — kapsam ve ilerleme analizi |
| Canlı portal | Çevrimdışı açılan tek dosya, **PDF olarak indirilebilir** |
| Microsoft markası | **Kendi logonuz, renginiz ve kapak sayfanız** |

---

## Amacı

Secure Score önerilerini teknik bir kontrol listesi seviyesinden çıkarıp **yönetilebilir,
önceliklendirilebilir ve aksiyon alınabilir** bir güvenlik iyileştirme yol haritasına
dönüştürmek.

Üç tasarım ilkesi üzerine kuruludur:

1. **Doğruluk her şeyden önce gelir.** Puan, maksimum puan ve yüzde doğrudan tenant'ın
   kendi ölçümünden alınır — yeniden hesaplanmaz. Lisans kapsamı dışındaki kontroller
   paydaya dahil edilmez. Veri yoksa uydurulmaz, "bilgi yok" yazılır.
2. **Salt okunur.** Tüm Microsoft Graph çağrıları `GET`'tir. Araç tenant'ta hiçbir
   şeyi değiştiremez — bu bir ayar değil, koddaki bir sınırdır.
3. **Yöntem açıklanır.** Risk seviyeleri Microsoft'un sınıflandırması değildir; bizim
   modelimizle hesaplanır ve **formülü raporun içinde yazar.**

---

## Nasıl çalıştırılır?

### Gereksinimler

| Gereksinim | Not |
|---|---|
| Windows 10/11 | PowerShell 5.1 — Windows'ta yerleşiktir |
| Python 3.8+ | Yoksa betik `winget` ile tek seferlik kurar |
| Hesap | Secure Score okuyabilen bir hesap. İlk çalıştırmadaki uygulama onayını yetkili biri vermelidir; sonrasında **Global Reader yeterlidir** |
| İnternet | Microsoft Graph ve onay ekranı için |

**Tenant'ta uygulama kaydı açmanıza gerek yoktur.** Microsoft'un kendi first-party
Graph PowerShell istemci kimliği kullanılır; yönetilecek bir secret yoktur.

### Kurulum gerektirmeyen yol (önerilen)

1. [Releases](../../releases) sayfasından son sürüm ZIP dosyasını indirin.
2. ZIP'e sağ tıklayın → **Tümünü ayıkla**.
   *(ZIP'in içinden doğrudan çalıştırmayın; Windows dosyaları geçici bir klasöre açar.)*
3. Ayıklanan klasördeki **`BASLAT.cmd`** dosyasına çift tıklayın.

Bu kadar. Sisteme hiçbir şey kurulmaz, `PSModulePath` değişmez, yönetici yetkisi
istenmez. Silmek için klasörü silmek yeterlidir.

### PowerShell modülü olarak

```powershell
# Depoyu klonlayın veya ZIP'i ayıklayın, sonra:
Import-Module .\module\SecureScoreLens\SecureScoreLens.psd1 -Force
Invoke-SecureScoreLens
```

Komutu her oturumda kullanılabilir yapmak için `launcher\Istege-Bagli-Kalici-Kurulum.ps1`
betiğini çalıştırın (kullanıcı profiline kopyalar, yönetici gerektirmez, `-Kaldir` ile geri alınır).

### Sık kullanılan parametreler

```powershell
# Gerçek tenant, markalı rapor
Invoke-SecureScoreLens -Provider "Firmanız" -Logo "C:\marka\logo.png" `
                       -BrandColor "#0070C0" -Customer "Müşteri A.Ş."

# Tenant'a bağlanmadan örnek veriyle deneme
Invoke-SecureScoreLens -Demo

# Analiz motorunun kendi doğrulama testleri
Invoke-SecureScoreLens -SelfTest
```

| Parametre | Ne yapar |
|---|---|
| `-Customer` | Kapakta ve başlıkta görünen kurum adı |
| `-Provider` | "Hazırlayan" olarak kapakta, başlıkta ve alt bilgide |
| `-Logo` | Kapağa ve başlığa gömülür (png/jpg/gif/svg/webp, ≤2 MB) |
| `-BrandColor` | Kapak ve vurgu rengi (`#RRGGBB`). **Risk renklerini değiştirmez** |
| `-Path` | Rapor klasörü |
| `-Demo` / `-SelfTest` | Örnek veriyle çalıştır / motor testlerini çalıştır |

> `Invoke-SecureScoreAssessment` eski komut adıdır ve takma ad olarak çalışmaya devam eder.

---

## Rapor içeriği

Üretilen HTML **tek dosyadır**, dış kaynak çağırmaz ve çevrimdışı açılır. Beş bölümden oluşur:

### 1 · Genel Bakış
Secure Score kartı (risk seviyesine göre renklenir), yönetici özeti, puan projeksiyonu,
kategori dağılımı, etki derecesi kartları, işlem durumu dağılımı ve puan trendi.

### 2 · Tüm İyileştirme İşlemleri
Kapsamdaki her maddenin durumu. Arama, durum/etki/kategori filtreleri, sıralama.
Her satır genişletilerek Microsoft'un yapılandırma adımları, tehdit türleri ve portal
bağlantısı görülür. **Sorumlu kişi ve hedef tarih atanabilir** — girilen bilgiler
satırda rozet olarak görünür, tarihi geçmişse kırmızıya döner. CSV ve PDF dışa aktarımı
seçilebilir kriterlerle çalışır.

### 3 · 30/60/90 Gün Yol Haritası
Açık maddeler etki önceliğine göre üç faza dağıtılır. Her faz için kazanılabilir puan
ve işlem sayısı gösterilir.

### 4 · İlerleme ve Kapsam
Tenant'ın kendi ölçüm anlık görüntülerini karşılaştırarak **puanın neden değiştiğini**
açıklar: iyileşen ve gerileyen kontroller, ölçüm kapsamına giren veya çıkan maddeler.
Yüzde düşerken ham puanın artması genellikle kapsamın genişlemesindendir; bu bölüm
bunu açıkça yazar.

### 5 · Bulgu Raporu
Açık her madde için ayrı bir **bulgu kartı** — danışmanlık raporu biçiminde:

| Alan | Kaynak |
|---|---|
| Bulgu adı, etkilenen kaynak, kategori | Microsoft Graph |
| Açıklama, Etkisi | İçerik paketi |
| Risk seviyesi | Etki önceliklendirme modeli |
| İyileştirme → Yapılandırma | Microsoft'un kendi yönergesi |
| İyileştirme → Ortam bağımlılığı, **Doğrulama** | İçerik paketi |
| Ek bilgi | Microsoft belge bağlantısı |
| Secure Score kaydı | Öncelik sırası, puan, kazanç, tehdit türleri |

Bölümün başında yönetici özeti, raporun amacı ve renk kodlu risk duruşu tablosu yer alır.
**PDF olarak indir** düğmesi yalnızca bu bölümü basar.

---

## Kimler için, ne katkı sağlar?

### Yönetilen hizmet sağlayıcılar ve danışmanlıklar
Elle yazılan değerlendirme raporunun yerini alır. Logo, renk ve kapak sayfası müşteriye
veya hizmet sağlayıcıya göre değiştirilebilir; aynı araç her müşteri için kendi
kimliğiyle çalışır. Sorumlu/termin alanları raporu bir **takip aracına** çevirir.

### Kurum içi güvenlik ekipleri
Puanın neden değiştiğini açıklar, hangi ürüne odaklanılacağını söyler, ek bütçe
gerektirmeyen düşük maliyetli kazanımları ayırır. Yönetime sunulacak belge hazır gelir.

### CISO ve yöneticiler
Teknik liste yerine yönetici özeti, risk duruşu ve 30/60/90 günlük plan. Her sayı
tenant'ın kendi ölçümüne dayanır.

### Denetim ve uyum ekipleri
Her bulgunun **doğrulama adımı** vardır — "yapıldı" demek yerine nasıl kanıtlanacağı
yazar. Rapor çevrimdışı tek dosyadır, arşivlenebilir.

---

## Güvenlik

- **Salt okunur.** Tüm Graph çağrıları `GET`. Tek `POST`, Microsoft'un token uç noktasına.
- **Kimlik bilgisi saklanmaz.** Authorization Code + PKCE (S256). Parola araca hiç
  girilmez, yalnızca Microsoft'un kendi ekranına girilir. Token bellekte tutulur,
  diske yazılmaz, çalıştırma sonunda temizlenir.
- **Her çalıştırmada onay.** Sessiz yeniden kullanım yoktur; istenen izinler onay
  öncesi ekranda listelenir.
- **Minimum yetki.** Zorunlu: `SecurityEvents.Read.All`. Opsiyonel:
  `Organization.Read.All`. İkisi de `.Read.` — yazma yetkisi hiç istenmez.
- **Yerel sertleştirme.** Geri dönüş dinleyicisi yalnızca loopback'e bağlıdır, `state`
  doğrulanır, okuma sınırlıdır, hata mesajları sabit metinlerle eşlenir.
- **Rapor** dış kaynak çağırmaz; bağlantılar yalnızca `http(s)` şemasıyla sınırlıdır.

Güvenlik açığı bildirmek için [SECURITY.md](SECURITY.md) dosyasına bakın.

---

## Doğruluk ve sınırlar

- Puan, maksimum puan ve yüzde **doğrudan** `/security/secureScores` çıktısından alınır.
- Yalnızca tenant'ın kendi anlık görüntüsündeki kontroller sayılır. Microsoft'un global
  kataloğunda olup tenant'a uygulanmayan kontroller "kapsam dışı" olarak raporlanır ve
  hiçbir hesaba katılmaz. *(Microsoft portalı lisanstan bağımsız olarak tüm önerileri
  gösterir; bu araç tenant'ın gerçek kapsamını esas alır.)*
- **Risk seviyeleri Microsoft'a ait değildir.** `maxScore`, `rank`, `threats` ve `tier`
  alanlarından türetilir; formül raporun Yol Haritası bölümünde yazılıdır.
- Microsoft Graph'ın `complianceInformation` alanı
  [belgelerinde](https://learn.microsoft.com/graph/api/resources/securescorecontrolprofile)
  *"Uygulanmadı. Şu anda null döndürür."* olarak tanımlıdır — bu yüzden araç
  CIS/NIST/ISO eşlemesi **iddia etmez.**
- Secure Score bir güvenlik duruşu özetidir, **ihlal olasılığının mutlak ölçüsü değildir.**
  Bu uyarı raporun içinde de yer alır.

---

## Depo yapısı

```
SecureScoreLens/
├─ src/                        Analiz ve rapor motoru (Python, yalnızca stdlib)
│  ├─ secure_score_assessment.py
│  └─ secure_score_tr.json     Türkçe içerik paketi (120 kontrol)
├─ module/SecureScoreLens/     PowerShell modülü
│  ├─ SecureScoreLens.psd1
│  ├─ SecureScoreLens.psm1
│  └─ assets/                  Modüle gömülü motor ve içerik paketi
├─ launcher/                   Kurulum gerektirmeyen başlatıcılar
│  ├─ BASLAT.cmd               ← çift tıklanacak dosya
│  ├─ BASLAT.ps1
│  └─ Istege-Bagli-Kalici-Kurulum.ps1
└─ docs/                       Ek belgeler
```

Motorun 51 iç doğrulama testi vardır:

```bash
python3 src/secure_score_assessment.py --self-test
```

---

## Katkı

Katkılar memnuniyetle karşılanır — özellikle içerik paketindeki teknik doğruluk
düzeltmeleri. Ayrıntılar için [CONTRIBUTING.md](CONTRIBUTING.md).

## Lisans

[MIT](LICENSE). Microsoft, Microsoft 365, Microsoft Entra ID, Microsoft Defender ve
Microsoft Purview, Microsoft Corporation'ın ticari markalarıdır. Bu proje Microsoft ile
bağlantılı değildir ve Microsoft tarafından onaylanmamıştır.

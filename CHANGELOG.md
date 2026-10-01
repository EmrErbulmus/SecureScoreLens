# Değişiklik Günlüğü

Bu proje [Semantic Versioning](https://semver.org/lang/tr/) kullanır.

## [3.1.4] - 2026-09-13
### Eklendi
- **Bulgu Raporu** bölümü: açık her madde için ayrı bulgu kartı (açıklama, etki,
  ortam bağımlılığı, doğrulama), yönetici özeti, raporun amacı ve renk kodlu
  risk duruşu tablosu.
- Bulgu Raporu için **PDF çıktısı** — yalnızca ilgili bölümü basar.
- **İlerleme ve Kapsam** bölümü: puanın neden değiştiğini anlatan kapsam analizi.
- **Kurumsal marka uyarlaması**: logo, marka rengi, hazırlayan adı ve kapak sayfası.
- Açık maddelere **sorumlu ve hedef tarih** atama; CSV dışa aktarımı.
- Seçilebilir kriterlerle CSV/PDF dışa aktarma paneli.

### Değiştirildi
- Graph'ın ham servis kodları Microsoft'un güncel resmi ürün adlarına çevrildi
  (`AzureAD` → Microsoft Entra ID, `MDATP` → Microsoft Defender for Endpoint vb.).
- Yazı tipi Segoe UI Variable'a geçirildi; okunabilirlik ölçümleri güncellendi.
- Bulgu kartlarındaki ve işlem detaylarındaki Türkçe başlık satırı kaldırıldı.

### Düzeltildi
- PDF düğmesi sessizce çalışmıyordu: `print()` çağrısı tıklama akışından
  koparıldığı için tarayıcı tarafından engelleniyordu.
- CSV indirme çalışmıyordu: indirme bağlantısı sayfaya eklenmiyordu.
- Birincil alan adı, `isDefault` işaretli kayıt yoksa boş kalıyordu.
- İçerik denetimi sonrası dört teknik düzeltme (Defender Firewall giden trafik
  ifadesi, LDAP imzalama, Safe Links doğrulama lisansı, OneDrive GUID listesi).

## [2.0.0] - 2026-09-12
### Eklendi
- PowerShell modülü ve kurulum gerektirmeyen başlatıcı.
- Bölümlenmiş rapor tasarımı, 30/60/90 gün yol haritası, etki önceliklendirme modeli.
- 120 kontrol için Türkçe içerik paketi.

## [1.0.0] - 2026-09-11
- İlk sürüm: salt-okunur Secure Score analizi ve HTML rapor.
## [3.2.0] - 2026-10-01

- How-to paketi 460 mevcut profile genişletildi: 90 önceki çeviri, 185 Türkçe
  kaynak uyarlaması, 184 genel cihaz yönlendirmesi, 1 eksik Microsoft yönergesi uyarısı.
  Kontrol başlıkları İngilizce kalır; 120 Türkçe başlık yardımcı metni ayrı kapsamdır.
- Yeni SCID'ler için dar deterministik cihaz yönlendirmesi çevirisi; diğer yeni/değişen
  kaynak metinleri için açık eksik çeviri uyarısı ve etiketli özgün İngilizce referans.
- None/Unknown etki değerleri Türkçeleştirildi; çevrilmemiş etki açıklamaları gizlenmeden etiketlendi.
- 33/184 cihaz kontrolü (%17,93), 41 seçenek ve 30 Microsoft Learn kaynağı içeren
  kaynak incelemeli yerel katalog; 151 kontrolde ayrıntılı seçenek eksikliği açıkça gösterilir.
  scid_87 için GPO/güncel Intune Settings catalog/exact registry, ayrıca koşullu sensor
  teşhisi/onboarding ve Everyone ACL yönergeleri; canlı API/veri çekme veya yeni izin yok.
- İşlem How-to ve Bulgu Raporu aynı güvenli renderer'ı kullanır. Beyaz bulgu hücreleri,
  ekran ve print/PDF için belirgin ince kenarlıklar; #FFC000 duruş rengi korundu.
- Launcher ve isteğe bağlı installer, release Modul ve depo module dizilimlerini destekler.
- Offline motor/çeviri/güvenli HTML/asset/print regresyon testleri eklendi.
## [3.2.1] - 2026-10-01

- Özgün Microsoft İngilizce metin/etki kutuları HTML, PDF ve görünüm dışa
  aktarımlarından kaldırıldı; özgün metadata ve ham JSON denetim için korunur.
- Kaynak incelemeli bölüm başlığı İyileştirme Seçenekleri oldu. Bölüm yalnızca cihaz
  kategorisinde ID/başlık eşleşen ve gerçekten portal seçeneklerine yönlendiren
  kontrollerde gösterilir; native Secure Score yönergelerine eklenmez.
- Normal Türkçe öneriler korunur; gereksiz eksik GPO/Intune/registry açıklaması ve
  boş Kaynaklar listesi kaldırıldı. Eksik çeviri uyarısı artık gösterilmeyen İngilizce
  kaynağa atıf yapmaz; güncel Secure Score portalına yönlendirir.
- 33/184 cihaz kontrolü, 41 seçenek ve 151 eksik ayrıntılı yönerge kapsamı değişmedi.
- Skor hesabı, ince beyaz hücre kenarlıkları, renkler ve salt-okunur yetkiler değişmedi.
## [3.2.2] - 2026-10-01

- Tekrarlanan kart başı çeviri, kapsam, kaynak niteliği ve inceleme tarihi metinleri
  kaldırıldı; gerçek sınırlar Yöntem ve Kapsam notunda birleştirildi.
- Findings-only PDF'ye de dahil kısa uygulama-kapsam cümlesi bulgu girişine eklendi.
- İyileştirme Seçenekleri 16 px/800 normal harf düzeni ve mavi çizgi/hafif zeminle
  belirginleştirildi. Yapılandırma, bağımlılık ve doğrulama aynı renderer'da yapılandırıldı.
- Açıklama/etki paketi eksikliği için tekrar eden kart uyarısı kaldırıldı. Gerçek
  eksik yönergeler kısa portal yönlendirmesiyle; kaynak-yok durumu açık doğru metinle gösterilir.
- Maddeye özgü lisans/OS/iş kesintisi, güvenli hedefleme ve teknik doğrulama uyarıları
  korundu. Belge linkleri okunabilir etiketlerle tekilleştirildi; boş kaynak listesi yok.
- Özgün kaynak notes/applicability/date ve JSON audit alanları korundu; display
  özetleri yeni kaynak araştırması değildir. 33/184 kontrol ve 41 seçenek kapsamı değişmedi.
- Skor hesabı, salt-okunur yetkiler, #FFC000 ve beyaz hücre kenarlıkları korundu.

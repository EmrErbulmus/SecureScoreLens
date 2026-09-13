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

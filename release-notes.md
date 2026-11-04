# 3.2.3-preview.4 — aday, Windows doğrulaması bekliyor

- Yalnız özel çıktı yazıcısında reflection Invoke yerine türlenmiş Framework kurucusu / modern statik Create kullanılır; FileSecurity açıkça temel nesneye dönüştürülür.
- Korumalı kullanıcı+SYSTEM ACL, CreateNew ve exclusive paylaşım korunur; izin genişletilmez.
- Oturum açmadan sentetik dosya/ACL/üzerine yazma sınaması: `Diagnose-Output.ps1`.
- Arındırılmış aşama/tür/HResult/izinli parametre adı; ham mesaj veya yol yoktur.
- CreatePrivate ArgumentException için kesin kök neden Windows üzerinde doğrulanmadı; reflection PSObject bağlaması olasıdır. Windows PowerShell/ACL testi bu ortamda yapılmadı. Python testleri Windows kanıtı değildir.
- Python motoru ve tüm varlıklar preview.3 ile byte-identical kalır.

# 3.2.3-preview.3 — özel çıktı oluşturma hotfix

- Yalnız PowerShell Write-PrivateOutputText değişti. Write-only handle üzerinden sonradan SetAccessControl yerine korumalı DACL CreateNew sırasında sağlanır.
- .NET Framework: imzası açıkça seçilmiş FileStream(FileSecurity) kurucusu. Modern .NET: FileSystemAclExtensions.Create; API yoksa güvensiz fallback yok.
- Yalnız geçerli kullanıcı + SYSTEM, inheritance kapalı, FileShare.None ve CreateNew korunur. İçerik ACL kurulduktan sonra yazılır. Mevcut dosyanın üzerine yazılmaz.
- Hata tanısı: yalnız sabit aşama ve en iç exception türü. Müşteri yolu/içerik/token yok. Flush/close hataları da kapsanır.
- Python, Graph/auth akışı, başlatıcılar ve içerik varlıkları byte-identical. Motor sürüm etiketi bilinçli olarak preview.2 kalır.
- Windows runtime/ACL testi yapılmadı; kesin kullanıcı kök nedeni iddiası yok. Linux Python regresyonları Windows kanıtı değildir.
- Kaynak: SecureScoreLens-v3.2.3-preview.2.zip, SHA-256 254f0f63938ada3ab38bdde6e4956bcab8aee05b54c3e0ad82198566f51bd8a0.

## Önceki sürüm notları (değişmeden)

# 3.2.3-preview.2 — denetim düzeltmeleri

Kaynak yalnızca son onaylı GitHub preview.1 ZIP'idir (SHA-256 `739b53ce0bd046da13b735509a09f6ed9d2d6f5611f5fa88e7c6ff59ac3a5687`). 3.2.4 ortam/evidence taslakları dahil edilmedi. GitHub'a gönderim veya dağıtım yapılmadı.

## Düzeltilen / sınırlandırılan bulgular

| Bulgu | Durum | Kanıt / sınır |
|---|---|---|
| Kategori kazanılabilir puanı ve açık işlem sayısı | Düzeltildi | Yalnız OPEN_STATES; ignored/riskAccepted/thirdParty/alternate puan farkı ham metadata'da korunur, teknik tamamlandı sayılmaz |
| regression_days satır sayısı gibi kullanımı | Düzeltildi | Son ölçüme sabitlenmiş gerçek UTC gün aralığı; seyrek ve çoklu günlük ölçüm, sınır ve gelecek kayıt testleri |
| Kapsamdan çıkan kontrol tablosunun boş olması | Düzeltildi | Tarihsel ölçüm + profil başlığı/kategori/ürün, profil yoksa ID |
| Farklı saat dilimlerinde ters trend/grafik | Düzeltildi | UTC datetime sıralaması; metin, çizgi, ilerleme ve state-update sıralama |
| Sekiz içerik notu | 6 düzeltme, 2 güvenli bekletme | Ayrı reviewed_guidance_corrections.json; tam ID/başlık/kategori ve özgün ham HTML SHA bağlama |
| Citrix kilitleme süresi birimi | Güvenli bekletme | Birim/tenant doğrulanmadı; kör saniye-dakika değişikliği önerilmez; tam teknik çözüm iddiası yok |
| IntegratedApps/onay semantiği | Güvenli bekletme | Tenant/ilke kapsamı doğrulanmadan blanket tersine çevirme yok; tam teknik çözüm iddiası yok |
| HTTP redirect / bearer / pagination | Sertleştirildi | Sabit public graph.microsoft.com HTTPS443; otomatik yönlendirme reddi, tekrar eden nextLink reddi; mock transport testleri |
| Loopback callback / hata yansıtma / BSTR | Sertleştirildi | Kriptografik state, süre/başlık limitleri, sabit hata; Windows canlı doğrulaması yapılmadı |
| Çıktı erişimi | Sınırlandırıldı | Yeni dosyalarda özel izin isteği; ACL hatası veri yazmadan durur; mevcut klasör/üst paylaşım/yedek ACL değişmez; dosya sistemi izinleri uygulamıyorsa açık uyarı, gizlilik garantisi yok |
| Auth scope açıklaması | Düzeltildi | Organization.Read.All rapor amacı isteğe bağlı olsa da mevcut akış her oturumda ister; izin kapsamı değiştirilmedi |

## Korunan kapsam

Microsoft currentScore/maxScore ve risk paleti/layout korunur. Özgün İngilizce profil fixture'ı, çeviri ve seçenek varlıkları byte-identical hash korumasındadır. 460 profil; Türkçe 275 ayrıntılı +184 genel yönlendirme +1 kaynak adımı olmayan kayıt; impact460; seçenek120/184,134 alternatif ve kalan64 ayrıntılı inceleme korunur. **460 kontrolün hepsi teknik/portal doğrulandı demek değildir.** Önceki16 preview düzeltmesi testleri korunur. Yeni operasyon rehberi Microsoft profilini değiştirmez: güncel kaynak etiketi ve ayrı özgün Microsoft arşivi eylem/bulgu/CSV/JSON'da korunur. Safe hold teknik tamamlandı değildir.

Modül ModuleVersion3.2.3 / Prerelease preview2, engine/GitHub3.2.3-preview.2. DEMO yalnız sentetik katalogdur; müşteri/tenant PII içermez. Windows/gerçek tenant sign-in ve ACL testi yapılmadı; PowerShell parser pwsh ortamda yok. Bu bir güvenlik sertifikasyonu veya tüm denetim maddelerinin çözüldüğü iddiası değildir.


ZIP: SecureScoreLens-GitHub-v3.2.3-preview.2.zip; GitHub tag v3.2.3-preview.2. Remote push/deploy yok.

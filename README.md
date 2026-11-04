# SecureScoreLens 3.2.3-preview.2

Microsoft 365 Secure Score verisini salt okunur değerlendirerek Türkçe, çevrimdışı görüntülenebilen tek dosyalık HTML rapor ve CSV/JSON çıktıları üretir. Tenant ayarlarını değiştirmez. Bu paket son onaylı corrective preview.2 kodunun sade çalışma zamanı dağıtımıdır; yeni kod veya 3.2.4 taslakları içermez.

## Gereksinimler

Windows PowerShell 5.1+ ve Python 3.8+ gerekir; desteklenen güncel Python 3 önerilir. pip/npm bağımlılığı yoktur. `BASLAT.cmd` powershell.exe kullanır; PowerShell 7 zorunlu değildir. Gerçek değerlendirme Microsoft oturum açma, Graph erişimi ve yetkili hesap/onay gerektirir. Python bulunamazsa başlatıcı kullanıcı kapsamlı winget kurulumunu deneyebilir; önceden kurmak daha öngörülebilirdir. Başlatıcı indirme engelini kaldırmayı ve süreç kapsamında ExecutionPolicy Bypass kullanmayı dener; kuruluş ilkelerini aşmayın.

## Çalıştırma

1. `SecureScoreLens-v3.2.3-preview.2.zip` dosyasını tamamen ayıklayın. ZIP içinden çalıştırmayın.
2. Ayıklanan kök dizinde terminal açın. Önce sentetik demo ve motor denetimlerini çalıştırın:

```powershell
.\BASLAT.cmd -Demo
.\BASLAT.cmd -SelfTest
```

3. Gerçek değerlendirme için `BASLAT.cmd` dosyasına çift tıklayın veya terminalde ` .\BASLAT.cmd ` çalıştırın. Parolayı yalnız Microsoft ekranına girin. Varsayılan rapor dizini `Raporlar/` olur. Gerçek çıktılar hassas tenant bilgisi içerebilir; GitHub'a yüklemeyin.

### Modülü doğrudan kullanma

```powershell
Import-Module .\Modul\SecureScoreLens.psd1 -Force
Invoke-SecureScoreLens -Demo
Invoke-SecureScoreLens -SelfTest
# Gerçek değerlendirme:
Invoke-SecureScoreLens
```

Modül doğrudan çağrıldığında varsayılan çıktı dizini `SecureScoreReport/` olur. Kalıcı modül kurulumu gerekmez. `Istege-Bagli-Kalici-Kurulum.ps1` yalnız komutun kullanıcı profilinden bulunmasını isteyenler içindir; geri alma: ` .\Istege-Bagli-Kalici-Kurulum.ps1 -Kaldir `.

Python motorunun Windows başlatıcısından bağımsız çevrimdışı denemesi:

```text
python Modul/assets/secure_score_assessment.py --self-test
python Modul/assets/secure_score_assessment.py --demo --out Raporlar
```

## Mevcut özellikler ve bu paketin sınırı

Yönetici özeti, filtrelenebilir iyileştirme listesi, 30/60/90 yol haritası, geçmiş/kapsam analizi, bulgu raporu, rapor içi sorumlu/termin takibi, marka seçenekleri ve tarayıcıdan PDF/yazdırma mevcut özelliklerdir; bu sadeleştirmeyle yeni geliştirilmiş değildir. Microsoft currentScore/maxScore korunur; etki modeli ve puan projeksiyonları Microsoft puanı veya uygulama garantisi değildir.

460 katalog profili; 275 ayrıntılı Türkçe yönerge, 184 genel cihaz yönlendirmesi, 1 kaynak adımı olmayan kayıt; 460 etki metni bulunur. 184 cihaz kontrolünden 120'sinde 134 ayrıntılı seçenek vardır; 64'ü ayrıntılı inceleme bekler. Canlı portal doğrulaması 0'dır. Sekiz hedefli içerik kaydının altısı gözden geçirilmiş düzeltme, Citrix birimi ve IntegratedApps onay modeli ise güvenli bekletmedir; tümü çözülmüş sayılmaz.

Bu çalışma Windows/PowerShell canlı oturum açma, gerçek Graph/tenant, Windows ACL veya elle PDF sayfalamasını doğrulamaz. Yeni dosyalarda özel izin istenmesi, tüm depolama/yedek/paylaşım zincirinin özel olduğunu garanti etmez. Mevcut akış Organization.Read.All iznini her oturumda ister; bu izin pakette kaldırılmadı. [Sürüm notları](release-notes.md) ve [Güvenlik](SECURITY.md) sınırlarını okuyun.

## Paket bütünlüğü ve kaynak

`Modul/` altındaki tüm dosyalar, iki başlatıcı ve isteğe bağlı kurucu son onaylı kaynak ZIP ile byte-identical korunmuştur. `reviewed_guidance_corrections.json`, `remediation_options_tr.json` ve `secure_score_tr.json` çalışma zamanı bağımlılıklarıdır; silmeyin. Geliştirici tests/docs/CI, fixture, araştırma ve örnek HTML bu dağıtımda yoktur. Motorun dahili SelfTest'i için tests klasörü gerekmez; geliştirici unittest paketi bu ZIP'e dahil değildir.

`SHA256SUMS.txt` kendisi hariç bu ZIP'teki tüm dosyaların SHA-256 değerlerini kapsar; ZIP'in kendi hash'i değildir. `SOURCE-PROVENANCE.json` doğrudan paket kaynağını ve önceki provenansı ayrı alanlarda korur. Tam kaynak ZIP'in hash'i bu sade ZIP'in hash'i olarak kullanılmamalıdır. [MIT lisansı](LICENSE) ve mevcut kaynak/kurum atıfları korunmuştur.

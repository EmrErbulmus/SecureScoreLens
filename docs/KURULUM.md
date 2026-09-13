# Kurulum ve Kullanım

## Yol 1 — Kurulum gerektirmeyen (önerilen)

Dağıtım için en uygun yoldur. Sisteme hiçbir şey kurulmaz.

1. [Releases](../../../releases) sayfasından son sürüm ZIP'ini indirin.
2. ZIP'e sağ tıklayın → **Tümünü ayıkla**.
3. Ayıklanan klasördeki **`BASLAT.cmd`** dosyasına çift tıklayın.

Betik sırasıyla şunları yapar:
- Paket bütünlüğünü ve PowerShell sürümünü kontrol eder
- İndirilen dosyaların Windows "bloke" işaretini kaldırır
- Modülü **tam yol** ile yükler (sistemde kayıtlı olması gerekmez)
- Tarayıcıda Microsoft'un izin ekranını açar
- Raporu klasörün altındaki `Raporlar` klasörüne yazar ve açar
- İşlem başarılıysa pencereyi kendiliğinden kapatır

## Yol 2 — Depodan çalıştırma

```powershell
git clone https://github.com/<kullanici>/SecureScoreLens.git
cd SecureScoreLens
Import-Module .\module\SecureScoreLens\SecureScoreLens.psd1 -Force
Invoke-SecureScoreLens
```

## Yol 3 — Kullanıcı profiline kurma (isteğe bağlı)

Komutu her PowerShell penceresinde kullanılabilir yapar. Yönetici gerektirmez.

```powershell
.\launcher\Istege-Bagli-Kalici-Kurulum.ps1
Invoke-SecureScoreLens
```

Kaldırmak için: `.\launcher\Istege-Bagli-Kalici-Kurulum.ps1 -Kaldir`

---

## Yetkilendirme

İlk çalıştırmada tarayıcıda Microsoft'un onay ekranı açılır ve iki izin istenir:

| İzin | Durum | Ne için |
|---|---|---|
| `SecurityEvents.Read.All` | Zorunlu | Secure Score ve iyileştirme işlemleri |
| `Organization.Read.All` | Opsiyonel | Kurum adı ve birincil alan adı |

İkisi de salt okunurdur. **Onayı tenant'ta yetkili bir hesap vermelidir**; onay
verildikten sonra sonraki çalıştırmalarda Global Reader yeterlidir.

Tenant'ta uygulama kaydı açmanıza gerek yoktur — Microsoft'un kendi first-party
Graph PowerShell istemci kimliği kullanılır.

---

## Sık karşılaşılan sorunlar

**`Import-Module : ... was not loaded because no valid module file was found`**
Modül sisteme kurulmadığı için isimle bulunamıyor. `Import-Module` yazmayın;
doğrudan `BASLAT.cmd` dosyasını çalıştırın veya tam manifest yolunu verin.

**`Modul dosyalari bulunamadi`**
ZIP tam ayıklanmamış. ZIP'in içinden çalıştırmak yerine önce **Tümünü ayıkla**
deyin.

**`... cannot be loaded because running scripts is disabled`**
`.ps1` dosyasına doğrudan sağ tıklamışsınız. `BASLAT.cmd` kullanın — yürütme
ilkesini yalnızca kendi süreci için atlar, makine ayarınızı değiştirmez.

**`Python 3.8+ bulunamadi`**
`winget` kurumsal politikayla kapalıysa Python'u elle kurun:
`winget install -e --id Python.Python.3.12` veya python.org üzerinden.

**PDF'te renkler basılmıyor**
Yazdırma penceresinde **"Arka plan grafikleri"** seçeneğini açın. Tarayıcının kendi
üst/alt bilgisini kaldırmak için **"Üstbilgi ve altbilgi"** seçeneğini kapatın.

**Rapor boş veya puan gelmiyor**
Hesabın Secure Score okuma yetkisi olmayabilir veya tenant'ta henüz ölçüm
oluşmamıştır. `-Demo` ile örnek veri üzerinde aracın çalıştığını doğrulayın.

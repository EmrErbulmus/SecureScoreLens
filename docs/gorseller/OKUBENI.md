# Ekran görüntüleri

README'deki galeri bu klasördeki altı dosyayı bekler. Dosya adları birebir
aşağıdaki gibi olmalıdır — README bu adlarla bağlantı verir.

| Dosya | Ne gösterilecek |
|---|---|
| `01-genel-bakis.png` | **Genel Bakış** sekmesi — Secure Score kartı ve yönetici özeti görünecek şekilde, sayfanın en üstü |
| `02-islemler.png` | **Tüm İyileştirme İşlemleri** — araç çubuğu, filtre çipleri ve ilk birkaç satır. Bir satırı genişletip sorumlu/termin alanlarını göstermek daha iyi olur |
| `03-yol-haritasi.png` | **30/60/90 Gün Yol Haritası** — üç fazın görüldüğü kısım |
| `04-ilerleme.png` | **İlerleme ve Kapsam** — "Dönem bulgusu" kartı ve dört KPI kutusu |
| `05-bulgu-raporu.png` | **Bulgu Raporu** — risk duruşu tablosu ve altındaki ilk bulgu kartı |
| `06-kapak.png` | **Kapak sayfası** — raporu ilk açtığınızda çıkan ekran |

## Nasıl alınır

1. Bir raporu tarayıcıda açın. Markalı görünüm için logo ve renk vererek üretin:

   ```powershell
   Invoke-SecureScoreLens -Provider "KoçSistem" -Logo "C:\marka\logo.png" -BrandColor "#0070C0"
   ```

2. Tarayıcıyı **tam ekran** yapın (`F11`) ve yakınlaştırmayı **%100**'e getirin
   (`Ctrl+0`). Tutarlı genişlik, galerinin düzgün görünmesi için önemlidir.

3. Ekran görüntüsünü alın:
   - **Windows:** `Win + Shift + S` → alanı seçin
   - Tarayıcının kendi aracı da olur: `F12` → `Ctrl+Shift+P` → *"Capture screenshot"*

4. Dosyaları yukarıdaki adlarla bu klasöre kaydedin.

## Önemli: veri maskeleme

Ekran görüntüleri **herkese açık bir depoya** girecek. Almadan önce:

- **Kurum adını** `-Customer "Örnek A.Ş."` ile değiştirerek rapor üretin
- **Tenant kimliği ve birincil alan adı** kapakta ve başlıkta görünür — bunları
  görsel üzerinde bulanıklaştırın veya kırpın
- Sorumlu/termin alanlarına gerçek çalışan adı girmeyin
- Bulgu kartlarındaki içerik geneldir, sorun değildir; ama **puanınız ve açık
  madde sayınız** kurumunuzun güvenlik duruşunu ele verir. Bunu paylaşmak
  istemiyorsanız `-Demo` ile örnek veriden görüntü alın:

  ```powershell
  Invoke-SecureScoreLens -Demo -Customer "Örnek A.Ş." -Provider "KoçSistem"
  ```

  Demo modu tenant'a hiç bağlanmaz; sentetik veriyle aynı raporu üretir.
  **Depo görselleri için en güvenli yol budur.**

## Boyut

PNG, genişlik 1200–1600 piksel arası yeterlidir. Dosya başına 300 KB'ı aşmamaya
çalışın; GitHub'da README'nin açılma hızını etkiler.

## banner.svg — iki yerde kullanılır

Elle yazılmış SVG'dir; metnini veya renklerini doğrudan düzenleyebilirsiniz.
Projenin gerçek renk paletini kullanır (`#C00000`, `#F56A00`, `#FFD500`,
`#00A14B`, `#0070C0`).

### 1 · README başlığı
`README.md` dosyasının en üstünde yer alır. SVG olarak kullanılır — her ekran
çözünürlüğünde net görünür ve 4 KB'dır. Ek bir işlem gerekmez.

### 2 · Sosyal önizleme (bağlantı paylaşıldığında çıkan görsel)
GitHub bu alanda **SVG kabul etmez**; PNG, JPG veya GIF ister ve dosya 1 MB'ın
altında olmalıdır. Önerilen boyut **1280×640**.

Dönüştürmek için bu klasördeki **`banner-png-olustur.html`** dosyasını tarayıcıda
açın ve düğmeye basın. Dönüştürme tamamen tarayıcınızda yapılır; internet
bağlantısı veya üçüncü taraf bir servis gerekmez.

Ardından GitHub'da **Settings → General → Social preview** altına yükleyin.

> Not: SVG'deki yazılar sistem yazı tipleriyle çizilir. PNG'yi hangi makinede
> üretirseniz o makinenin yazı tipleri kullanılır — Windows'ta üretmek, banner'ın
> tasarlandığı Segoe UI görünümünü verir.

# Rapor İçeriği

Üretilen HTML tek dosyadır, dış kaynak çağırmaz, çevrimdışı açılır.

## Kapak sayfası
Logo, gizlilik etiketi, kurum adı, Secure Score yüzdesi ve risk rozeti, hazırlayan
bilgisi, tenant kimliği, birincil alan adı, kapsam ve içindekiler. Ekranda
geçilebilir; PDF'e yazdırırken her zaman birinci sayfa olarak basılır.

## 1 · Genel Bakış
- **Secure Score kartı** — risk seviyesine göre renklenir; puan, ilerleme çubuğu,
  kazanılabilir puan ve risk rozeti
- **Yönetici özeti** — en büyük fırsat, kritik maddeler, ilk 3 öncelik, hızlı
  kazanımlar, gerileyen maddeler, dönem trendi, ürün yoğunlaşması, uygulama eforu
  ve emsal karşılaştırması
- **Puan projeksiyonu** — kritik+yüksek kapatılırsa / hızlı kazanımlar uygulanırsa
  puanın nereye gideceği
- **Kategori dağılımı**, etki derecesi kartları (tıklanınca ilgili listeye gider),
  işlem durumu dağılımı, kategori tablosu, ilk 5 işlem ve puan trendi

## 2 · Tüm İyileştirme İşlemleri
Kapsamdaki her madde. Arama, durum/etki/kategori filtreleri ve sıralama. Satır
genişletilince Microsoft'un yapılandırma adımları, tehdit türleri, kullanıcı etkisi,
uygulama maliyeti ve portal bağlantısı görülür.

**Sorumlu ve termin atama:** açık maddelere sorumlu kişi/ekip, hedef tarih ve durum
notu girilebilir. Satırda rozet olarak görünür; tarihi geçmişse kırmızıya döner.
Kayıtlar tarayıcıda tutulur, rapor dosyası değişmez; her tenant ayrı saklanır.

**Dışa aktarma:** kapsam (filtrelenmiş / tümü) ve içerik (sorumlu-termin sütunları,
durum notu, uygulama adımları) seçilerek CSV veya PDF alınır.

## 3 · 30/60/90 Gün Yol Haritası
Açık maddeler etki önceliğine göre üç faza dağıtılır. Etki önceliklendirme modelinin
formülü bu bölümde açıkça yazar.

## 4 · İlerleme ve Kapsam
Tenant'ın en eski ve en yeni ölçümünü karşılaştırır: ham puan, tamamlanma oranı,
ölçülen kontrol sayısı ve ulaşılabilir puan değişimi. İyileşen, gerileyen, kapsama
giren ve kapsamdan çıkan kontroller tablo hâlinde listelenir.

Yüzde düşerken ham puanın artması genellikle kapsamın genişlemesindendir; bölüm
bunu açıkça yazar. En az iki farklı günün ölçümü gerekir.

## 5 · Bulgu Raporu
Açık her madde için danışmanlık biçiminde bir bulgu kartı. Bölüm başında yönetici
özeti, raporun amacı ve renk kodlu risk duruşu tablosu bulunur.

**PDF olarak indir** düğmesi yalnızca bu bölümü basar: yönetici özeti, risk duruşu
ve tüm bulgu kartları. Menü, başlık, alt bilgi ve diğer bölümler basılmaz.

---

## Etki önceliklendirme modeli

Microsoft Secure Score **önem derecesi yayımlamaz** — yalnızca bir sıralama verir.
Bu araç kendi modelini kullanır ve formülü raporda gösterir:

```
etki = maxScore × 0.9
     + (1 − rank / toplam) × 6
     + tehdit ağırlığı × 0.9
     + (gerilediyse 8)
     + (tier "Core" ise 2)
```

| Eşik | Seviye |
|---|---|
| ≥ 20 | Kritik |
| ≥ 15 | Yüksek |
| ≥ 10 | Orta |
| < 10 | Düşük |

Bu bir Microsoft sınıflandırması değildir. PTES raporlama standardı özel bir risk
modeline izin verir — **yeter ki raporda tanımlansın.** Bu araç tanımlar.

---

## Çıktı dosyaları

| Dosya | İçerik |
|---|---|
| `secure-score-dashboard-tr-*.html` | Ana rapor (tek dosya, çevrimdışı) |
| `secure-score-actions-*.csv` | Tüm işlemler, tablo hâlinde |
| `secure-score-assessment-*.json` | Analiz sonucu, makine okunur |
| `securescore-raw-*.json` | Graph'tan alınan ham veri |

Ham veri dosyası `--offline-input` ile yeniden analiz edilebilir; bu, tenant'a
tekrar bağlanmadan rapor tasarımını yenilemeyi sağlar.

# Güvenlik Politikası

## Güvenlik açığı bildirimi

Bir güvenlik açığı bulduysanız **herkese açık issue açmayın.**

Bildirimlerinizi depo sahibine özel olarak iletin (GitHub → Security → *Report a
vulnerability*, veya depo açıklamasındaki iletişim adresi). Bildiriminizde şunlar
yer alırsa değerlendirme hızlanır:

- Etkilenen dosya ve sürüm
- Yeniden üretme adımları
- Gözlenen ve beklenen davranış
- Varsa etkisi hakkındaki değerlendirmeniz

Makul bir sürede dönüş yapılır ve düzeltme yayımlanana kadar bildirim gizli tutulur.

## Aracın güvenlik tasarımı

Bu araç, çalıştığı tenant üzerinde **hiçbir değişiklik yapamaz.**

| Önlem | Uygulama |
|---|---|
| Salt okunur erişim | Tüm Microsoft Graph çağrıları `GET`. Tek `POST`, Microsoft'un token uç noktasına |
| İstenen yetkiler | `SecurityEvents.Read.All` (zorunlu), `Organization.Read.All` (opsiyonel). İkisi de salt okunur |
| Kimlik doğrulama | Authorization Code + PKCE (S256). Parola araca girilmez |
| Belirteç saklama | **Yok.** Bellekte tutulur, diske yazılmaz, çalıştırma sonunda temizlenir |
| Onay | Her çalıştırmada yeniden istenir; sessiz yeniden kullanım yoktur |
| Geri dönüş dinleyicisi | Yalnızca loopback'e bağlanır, `state` doğrulanır, okuma boyutu sınırlıdır |
| Hata mesajları | Sabit metinlerle eşlenir; dış girdi yansıtılmaz |
| Üretilen rapor | Tek dosya, dış kaynak çağırmaz, bağlantılar `http(s)` ile sınırlı |
| Logo gömme | Tür ve boyut (≤2 MB) doğrulanır |
| Marka rengi | Yalnızca literal hex kabul edilir; başka değer yok sayılır |

## Raporun içerdiği veri

Üretilen rapor **tenant'ınıza ait güvenlik yapılandırma bilgisi** taşır. Kurum içi
sınıflandırmanıza göre saklayın ve paylaşın. Depoya rapor dosyası eklemeyin —
`.gitignore` bunu engeller.

## Desteklenen sürümler

En son yayımlanan sürüm desteklenir. Güvenlik düzeltmeleri yeni bir yama sürümü
olarak yayımlanır.

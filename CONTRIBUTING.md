# Katkı Rehberi

Katkılar memnuniyetle karşılanır. En değerli katkı türü, içerik paketindeki
**teknik doğruluk düzeltmeleridir.**

## Önce bunu okuyun: doğruluk kuralı

Bu araçtan çıkan rapor kurumsal müşterilere sunulur. Bu yüzden tek bir kural
her şeyin önünde gelir:

> **Emin olmadığınız hiçbir teknik ayrıntıyı yazmayın.**
> Var olmayan bir Microsoft özelliği, yanlış bir lisans iddiası veya olmayan bir
> portal yolu, eksik bilgiden çok daha zararlıdır. Emin değilseniz, emin
> olduğunuz daha genel bir ifade kullanın.

## Katkı türleri

### 1. İçerik paketi düzeltmesi (`src/secure_score_tr.json`)

Her kontrol için dört alan bulunur:

| Alan | İçerik |
|---|---|
| `aciklama` | Kontrolün ne olduğu, kavramsal olarak. "Kontrol, ..." ile başlar |
| `etkisi` | Yapılmazsa ne olur: saldırı yolu ve iş sonucu |
| `bagimlilik` | Ön koşullar, neyin bozulabileceği, ilgili kontroller, lisans gereksinimi |
| `dogrulama` | Düzeltmenin işe yaradığı nasıl kanıtlanır — gözlemlenebilir bir kontrol |

Düzeltme gönderirken:
- Değişikliğin **neden** doğru olduğunu, mümkünse bir `learn.microsoft.com`
  bağlantısıyla açıklayın.
- Güncel resmi ürün adlarını kullanın: Microsoft Entra ID, Microsoft Defender for
  Endpoint / for Identity / for Office 365 / for Cloud Apps, Microsoft Purview
  Information Protection. Emekli adlar (Azure AD, MDATP, MCAS, Azure ATP) kabul edilmez.
- Microsoft arayüz öğelerinin adlarını Türkçe cümle içinde İngilizce bırakın —
  örn. "Conditional Access politikası". Bu bilinçli bir tercihtir.
- Alanlar düz metindir: HTML veya markdown kullanmayın.

### 2. Kod değişikliği

```bash
python3 src/secure_score_assessment.py --self-test
```

51 testin tamamı geçmelidir. Davranış değiştiren her katkı **kendi testini
getirmelidir** — özellikle:

- Doğruluk (puan, kapsam, sayım)
- Renk kontrastı ve okunabilirlik
- Güvenlik sınırları (salt okunurluk, şema kısıtları)

### 3. Hata bildirimi

Bir issue açarken şunları ekleyin: aracın sürümü, Windows ve PowerShell sürümü,
yaptığınız işlem, beklenen ve gözlenen sonuç. **Ekran görüntüsü veya günlük
paylaşırken tenant kimliği, alan adı ve kullanıcı adlarını maskeleyin.**

Güvenlik açıkları için issue açmayın — [SECURITY.md](SECURITY.md) dosyasına bakın.

## Değiştirmeyin

Aşağıdakiler bilinçli tasarım kararlarıdır; değiştiren bir katkı gerekçesiz kabul edilmez:

- **Salt okunurluk.** Yazma yapan hiçbir Graph çağrısı eklenmez.
- **Kimlik bilgisi saklanmaması.** Belirteç diske yazılmaz, önbelleğe alınmaz.
- **Puanın yeniden hesaplanmaması.** Headline puan tenant'ın ölçümünden gelir.
- **Marka renginin risk renklerini etkilememesi.** Kırmızı her zaman kritik demektir.
- **Uydurulmuş içerik olmaması.** Veri yoksa "bilgi yok" yazılır.

## Pull request

Küçük ve odaklı tutun. Açıklamada ne değiştiğini ve neden değiştiğini yazın.
Rapor çıktısını etkileyen değişikliklerde önce/sonra ekran görüntüsü ekleyin.

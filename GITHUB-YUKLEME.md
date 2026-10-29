# GitHub'a yükleme — kısa rehber

1. `SecureScoreLens-GitHub-v3.2.3-preview.1.zip` dosyasını **tamamen ayıklayın**. Kökünde README.md, BASLAT.cmd, Modul, tests, docs ve gizli `.github`, `.gitignore`, `.gitattributes` bulunur.
2. Kendi GitHub hesabınızda hedef depoyu açın/oluşturun. Public yapmadan önce LICENSE sahibini ve tüm dosyaları gözden geçirin. Bu işlem için kimlik bilginizi asistana vermeyin.
3. **Code > Add file > Upload files** seçin. ZIP dosyasını değil, ayıklanan kökün **içeriğini** (alt klasörlerle birlikte) yükleyin ve commit edin. `.github`, `.gitignore`, `.gitattributes` dosyalarının da gerçekten geldiğini doğrulayın; gerekirse Add file ile ayrıca ekleyin. Tüm içerik tek bir üst klasörün altına taşınmamalı.
4. GitHub tarayıcı upload'u `.github/workflows/ci.yml` dosyasını kabul etmezse, hesabınızın/deponuzun workflow oluşturma yetkisini kontrol edin; kaynağı değiştirmeden GitHub arayüzünden aynı yolu ekleyin. Güvenlik kısıtlarını aşmayın. Actions sekmesinde offline CI sonucunu kontrol edin.
5. **Releases > Draft a new release**: tag `v3.2.3-preview.1`, başlık `SecureScoreLens 3.2.3-preview.1`. `release-notes.md` içeriğini açıklamaya kopyalayın; **Set as a pre-release** seçin. ZIP'i burada release asset olarak ekleyebilirsiniz (Code upload'unun tersine burada ZIP uygundur).

## Mevcut eski depoya yükleme

Web upload eski dosyaları kendiliğinden silmez. Ayrı inceleme yaparak kullanılmayan eski `src/`, `module/`, `dist/`, `release/`, nested ZIP'ler, eski örnek/gerçek raporlar, raw tenant JSON/CSV/XLSX, log/screenshot/cache, eski banner bağlantıları ve eski workflow/README komutlarını **manuel olarak** değerlendirin. Bu adlar her depoda mevcut veya gereksiz kabul edilmez; önce karşılaştırın. Bu paket hiçbir uzak dosyayı silmez. Önceden hassas veri yayımlandıysa yalnız dosyayı silmek yeterli değildir; SECURITY.md sürecini izleyin.

GitHub push, repo oluşturma veya deployment bu hazırlıkta yapılmadı. Önce Windows'ta `BASLAT.cmd -Demo`, sonra kuruluşunuzun yetkili test süreciyle gerçek bağlantıyı doğrulayın. Gerçek müşteri raporlarını tekrar depoya yüklemeyin.

# Katkıda bulunma

Değişiklikleri küçük ve kaynak/kanıt sınırları açık tutun. Tenant puanlarını, auth kapsamını, paleti veya onaylı seçenekleri istenmeden değiştirmeyin. Kamuya açık Microsoft kaynaklarını URL ve kontrol ID'siyle belirtin; portalın bütün seçenekleri doğrulanmış gibi yazmayın.

Depo kökünde Python 3.8+ ile:

```sh
python Modul/assets/secure_score_assessment.py --self-test
python -m unittest discover -s tests -v
node --check tests/generated.js
node --check tests/browser-check.js
```

31 unit test; self-test ayrı 51 denetimdir. Yeni bağımlılık gerekmez. Node yalnız JS/test içindir. `tests/profile-metadata.json` Microsoft genel kontrol metadata'sıdır; tenant snapshot değildir. Diğer test skorları sentetiktir. JSON kaynak varlıkları ve test fixture'larını silmeyin.

## İsteğe bağlı mevcut tarayıcı testi

Kurulu Chromium ve Node 22+ gereklidir; bu paket tarayıcı indirmez. Kendi bilgisayarınızda depo kökünden ayrı bir terminalde Chromium'u **yalnız loopback** debug portuyla ve depoya ait özel test profiliyle çalıştırın (CHROME yolunu kendi kurulu tarayıcınıza göre belirleyin):

```sh
"$CHROME" --headless --remote-debugging-address=127.0.0.1 --remote-debugging-port=9331 --user-data-dir="$PWD/.browser-profile" about:blank
```

Diğer terminalde `node tests/browser-check.js` çalıştırın. Portu dış ağa açmayın; kişisel tarayıcı profilini kullanmayın. Windows'ta eşdeğer Chromium komut satırıyla başlatın. Browser script'i sentetik yerel HTML'yi açar; test PNG ve `browser-test-results.json` üretir. Bunlar gitignore kapsamındadır; yayın paketine katmayın. İşi bitirince yalnız başlattığınız test tarayıcısını kapatın. CI browser kurmaz/çalıştırmaz.

Güvenlik raporları için SECURITY.md. PR'larda gerçek müşteri/log/kimlik bilgisi içermeyen sentetik tekrar adımları verin. Test fingerprint dosyasını yalnız belgelenmiş, onaylı değişiklik için güncelleyin; hash eşitliği anlamsal güvenlik garantisi değildir.

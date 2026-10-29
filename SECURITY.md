# Güvenlik ve veri koruma

Bu önizleme salt-okunur değerlendirme içindir; güvenlik sertifikası, tenant doğrulaması veya sır içermediğine dair mutlak garanti değildir. Kaynağı inceleyin; yalnız yetkili olduğunuz tenant'ta kullanın.

- Token süreç belleğindedir; uygulama kimlik doğrulaması/izinleri bu paketle genişletilmedi. Kamuya açık Microsoft istemci kimliği sır değildir.
- Yerel rapor/ham JSON/CSV/XLSX, kullanıcı atamaları, kurum/alan adı, tenant kimliği, tarayıcı localStorage verisi ve ekran görüntüleri hassas olabilir. Yerel dosya ve tarayıcı profilini koruyun; paylaşımlı cihaz kullanmayın.
- `.gitignore` ve örnek sentetik dosyalar gerçek veriyi otomatik olarak anonimleştirmez. Commit ve GitHub upload öncesi içerik, dosya adları ve gömülü/base64 verileri yeniden inceleyin.
- Gerçek token, secret, sertifika özel anahtarı, `.env`, cache veya tenant çıktısını issue/PR içine koymayın. Sızıntı şüphesinde erişimi kesin, ilgili kimlik bilgisini iptal/rotate edin ve kuruluşunuzun sürecini izleyin. Git geçmişinden silmek tek başına iptal değildir.
- GitHub'da Security > Advisories > Report a vulnerability mevcut ve etkinse özel bildirim kullanın; değilse depo sahibinin kurumsal özel bildirim kanalını belirleyin. Hassas ayrıntıyla public issue açmayın. Bu pakette yeni bir e-posta adresi veya yanıt süresi taahhüdü tanımlanmaz.

Desteklenen inceleme hedefi bu preview paketidir. Windows login/tenant/API/gerçek printer doğrulanmadı; 460 envanter kaydının tüm içerikleri teknik olarak doğrulanmış değildir. Known limits: `release-notes.md`. Yayın öncesi kontroller heuristiktir, kapsamlı güvenlik denetimi değildir.

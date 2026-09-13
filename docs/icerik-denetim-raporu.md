# Teknik Doğruluk Denetim Raporu — `bulgu_icerik.json`

**Karar:** 52 kontrolün tamamı (4 alan × 52 = 208 metin bloğu) denetlendi; **1 düzeltilmesi gereken hata**, **3 doğrulanması gereken şüpheli ifade** bulundu. Lisans iddiaları, ürün adları ve kontrol/başlık eşleşmeleri genel olarak doğrudur.

---

## Hatalı — düzeltilmeli

### 1. `scid_2070` — Turn on Microsoft Defender Firewall (`etkisi`)

**Hatalı metin:**
> "Ayrıca giden trafiğin denetlenmemesi, zararlı yazılımın komuta kontrol sunucusuna bağlanmasını ve veri çıkarmasını kolaylaştırır."

**Sorun:** Cümle, Microsoft Defender Firewall'ın açılmasının giden (outbound) trafiği denetleyeceği izlenimini veriyor. Windows/Microsoft Defender Firewall'da varsayılan giden ilke **Allow**'dur; güvenlik duvarı etkinken de açıkça giden blok kuralı tanımlanmadıkça komuta-kontrol bağlantıları engellenmez. Kontrolün sağladığı asıl fayda gelen (inbound) bağlantıların varsayılan olarak engellenmesidir. Kurumsal müşteriye, etkinleştirme sonrası elde edilmeyecek bir koruma vaat edilmiş oluyor.

**Yerine konacak düzeltilmiş cümle:**
> "Güvenlik duvarı etkinleştirildiğinde gelen bağlantılar varsayılan olarak engellenir; giden trafik ise varsayılan ilkede serbest bırakıldığından, komuta kontrol bağlantılarının ve veri çıkarma girişimlerinin sınırlanması için ayrıca hedefli giden blok kurallarının tanımlanması gerekir."

---

## Şüpheli — doğrulanmalı

### 1. `scid_103` — Require LDAP client signing (`aciklama`)

**Metin:**
> "...LDAP client signing ayarının en az imza pazarlığı yapacak şekilde yapılandırılmasını öngörür. Amaç, kimlik doğrulama trafiğinin bütünlüğünü koruyarak imzasız ve açık metin bağlamaları engellemektir."

**Neden şüpheli:** Metnin kendi içinde tutarsızlık var. Önerilen değer "Negotiate signing" (imza pazarlığı) olduğunda imzasız bağlamalar reddedilmez; yalnızca imzalama pazarlık edilir. İmzasız bağlamaların fiilen reddedilmesi "Require signing" değeriyle olur, açık metin (simple bind) trafiğinin engellenmesi ise esas olarak LDAPS/kanal bağlama ve sunucu tarafı imzalama gereksinimiyle sağlanır. Hedeflenen değerin (Negotiate mi Require mı) netleştirilmesi ve "açık metin bağlamaları engeller" iddiasının buna göre yeniden ifade edilmesi önerilir.

### 2. `mdo_safelinksforOfficeApps` — Safe Links for Office Applications (`dogrulama`)

**Metin:**
> "...Explorer içinde ilgili URL tıklama kaydının oluştuğu doğrulanmalıdır."

**Neden şüpheli:** URL tıklama verisinin görüntülendiği Threat Explorer, Microsoft Defender for Office 365 **Plan 2** yeteneğidir; Safe Links ise Plan 1 ile de gelir. Plan 1 lisansına sahip bir müşteri bu doğrulama adımını uygulayamaz (Plan 1'de Real-time detections sınırlı kapsam sunar). Adımın "Plan 2 varsa Threat Explorer, aksi hâlde yeniden yazılmış safelinks.protection.outlook.com bağlantısının gözlenmesi" biçiminde koşullandırılması değerlendirilmelidir.

### 3. `spo_block_onedrive_sync_unmanaged_devices` — Block OneDrive sync from unmanaged devices (`aciklama`)

**Metin:**
> "Kısıtlama, eşitlemeye izin verilen etki alanlarının tanımlanmasıyla uygulanır."

**Neden şüpheli:** Ayar, DNS anlamında etki alanı adları değil, Active Directory etki alanlarının **GUID** değerleri ile yapılandırılır (Get-ADDomain ile elde edilir) ve yalnızca domain joined cihazları kapsar. `bagimlilik` alanı bunu doğru anlatıyor, ancak `aciklama` okuyucuda "etki alanı adı listesi" beklentisi yaratabilir; ifadenin GUID temelli olduğunun belirtilmesi önerilir.

---

## Temiz

Aşağıdaki alanlar tek tek karşılaştırıldı ve doğru bulundu:

**Lisans iddiaları (öncelik 1):** Conditional Access temelli kontrollerin Microsoft Entra ID Premium **P1** gerektirdiği (`AdminMFAV2`, `MFARegistrationV2`, `BlockLegacyAuthentication`, `aad_phishing_MFA_strength`, `aad_sign_in_freq_session_timeout`, `aad_limited_administrative_roles`); Identity Protection risk ilkelerinin **P2** gerektirdiği (`SigninRiskPolicy`, `UserRiskPolicy`); Privileged Identity Management'ın **P2** olduğu (`OneAdmin`, `RoleOverlap`); şirket içi AD için Entra Password Protection ve özel yasaklı parola listesinin **P1** olduğu (`aad_password_protection`, `aad_custom_banned_passwords`); sızdırılmış kimlik bilgisi tespiti için **P2** (`PasswordHashSync`); duyarlılık etiketleri **E3/E5**, otomatik etiketleme **E5** (`mip_sensitivitylabelspolicies`, `mip_autosensitivitylabelspolicies`); Customer Lockbox **E5/eşdeğer uyum lisansı** (`CustomerLockBoxEnabled`); genişletilmiş denetim saklaması **E5/uyum eklentisi** (`exo_mailboxaudit`); `exo_outlookaddins` ve `IntegratedApps` için "ek lisans gerekmez" ifadesi. Tümü doğru; yanlış SKU ataması bulunamadı.

**Ürün adları (öncelik 5):** Tüm metinlerde güncel adlandırma kullanılmış — Microsoft Entra ID, Microsoft Entra ID Protection, Microsoft Defender for Endpoint / for Office 365 / for Cloud Apps, Microsoft Purview Information Protection. "Azure AD", "Azure ATP", "Cloud App Security", "Azure Information Protection", "Office 365 ATP" gibi emekli adlar hiç geçmiyor.

**İçerik/kontrol eşleşmesi (öncelik 3):** 52 kaydın `aciklama` metni, `acik_maddeler.json` içindeki İngilizce `title` ve `remediation` ile karşılaştırıldı; konu kayması bulunmadı (ör. `mdo_spam_notifications_only_for_admins` doğru biçimde giden anti-spam bildirimlerini, `mdo_thresholdreachedaction` limit aşımında gönderim kısıtlamasını, `exo_individualsharing` organizasyon paylaşım ilkelerini anlatıyor).

**Doğrulama adımları (öncelik 4):** PowerShell ve portal adımları kontrol edildi ve uygulanabilir bulundu — `Get-OwaMailboxPolicy`/`AdditionalStorageProvidersAvailable`, `Get-OrganizationConfig`/`MailTipsAllTipsEnabled` ve `AuditDisabled`, `Get-SPOTenant`/`SharingDomainRestrictionMode = AllowList`, `Get-MpPreference`/`DisableEmailScanning = False`, `Get-NetFirewallProfile`, Entra sign-in logs'ta bloklayan Conditional Access ilkesinin Failure sonucu, EAC Roles > User roles altındaki My Custom Apps / My Marketplace Apps / My ReadWriteMailboxApps izinleri, SharePoint admin center Policies > Access control > Block access, Teams admin center meeting policy ayarları.

**Ürün yeteneği atıfları (öncelik 2):** Safe Links tıklama anında yeniden değerlendirme, Defender for Cloud Apps log collector'ın Docker üzerinde çalışması ve Cloud Discovery'yi beslemesi, MDE sensör/telemetri ve uzaktan müdahale yetenekleri, Customer Lockbox onaylayıcı rolü, admin consent workflow, kimlik avına dayanıklı MFA yöntemleri (FIDO2, Windows Hello for Business, sertifika tabanlı kimlik doğrulama) — tümü doğru ürüne ve mevcut özelliklere atfedilmiş; var olmayan bir özellik adı kullanılmamış.

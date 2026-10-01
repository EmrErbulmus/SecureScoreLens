# Remediation options v3.2 — kapsam ve kanıt

> v3.2.2 görünüm notu: aşağıdaki araştırma kapsamı değişmemiştir. Kaynak/başlık eşleşmeli
> gerçek cihaz portal yönlendirmeleri için bölüm adı İyileştirme Seçenekleri'dir.
> Normal Secure Score yönergelerinde ek eksik yöntem açıklaması gösterilmez. Özgün
> İngilizce metin/etki denetim JSON'unda kalır; HTML/PDF'de ek kutu olarak gösterilmez.
> Kartlarda genel kaynak/çeviri/tarih açıklamaları yerine yalnızca değişiklikle ilgili
> adımlar, maddi bağımlılıklar, teknik uyarılar ve doğrulama bilgisi yer alır. Kaynak
> kapsamı ve tenant ayarı doğrulaması yapılmadığı bir kez yöntem notunda açıklanır.
> Özgün notes/applicability/date alanları korunur; kısa display alanları yeni doğrulama değildir.

Doğrulama tarihi: **2026-10-01**. Kaynak ve kimlik doğrulaması yapılmıştır; tenant üzerinde uygulama, ilke dağıtımı veya cihaz değişikliği yapılmamıştır.

## Sonuç

- Ham kaynak: `/mnt/workspace/input/securescore-raw-20260911-161210.json`.
- Toplam **460** profil; Device kategorisinde **184** profil. Bu 184 profilin tamamında `choose remediation or exception options` içeren genel Recommendations yönlendirmesi bulunmaktadır.
- Yeni katalog: **33/184 kontrol (%17,93)**, **41 seçenek**. **151/184 kontrol (%82,07) eksiktir**.
- İçerik niteliği: **30 kontrol** ayar/ACL/bileşen/onboarding uygulama yoluna; **3 kontrol** (`scid_2000`, `scid_2001`, `scid_2002`) koşullu sensor teşhisi ve gerektiğinde onboarding yoluna sahiptir. Bu üç kayıt tek adımlı, garantili otomatik onarım değildir.
- Öncelikli `scid_87` için **3 seçenek**: exact GPO yolu ve Disabled, güncel Settings catalog yaklaşımı ve Disabled, exact registry yolu/tür/değer.
- **v3.1.4 baseline** çeviri paketi **120 giriş** içeriyordu; Device profilleriyle kesişim **30** girişti. Bu değerler başlangıç durumudur, v3.2 paketinin güncel kapsamı değildir.
- Uygulama ajanının bağımsız **v3.2 çeviri paketi genişletmesi**, güncel `src/secure_score_tr.json` üzerinde ayrıca okunarak doğrulandı: **460 profil ID**, **90 önceki non-generic çeviri**, **185 Turkish source-guidance adaptation**, **184 generic-device-redirect**, **1 source-unavailable uyarısı**. Başlık çevirisi **120** kontrolde kalır. Kaynak yönergesi uyarlamaları ve dar portal yönlendirmeleri ayrıntılı, kaynakları kontrol bazında incelenmiş canlı portal Remediation options değildir; bu ayrı katalogda doğrulanmış seçenek kapsamı yine **33/184** kontroldür.
- JSON'daki 33 anahtarın tamamı lowercase SCID'dir; bütün `title` değerleri ham profilin İngilizce exact title değeriyle birebir eşleşir. Açıklama/adımlar özgün Türkçedir; UI, product, policy ve cmdlet adları İngilizce korunur.

## Kanıt hiyerarşisi ve sınırlar

1. Ham JSON, kontrol kimliği ve exact title için esas kaynaktır; tenant'a özgü skor/cihaz sayısı bu içerikte çoğaltılmamıştır.
2. Kullanıcı ekranı `2026-10-01_13h41_58.png`, `scid_87` Remediation options içindeki GPO, eski Intune Administrative Templates ve registry seçeneklerini açıkça gösterir.
3. Microsoft Learn RemoteAssistance CSP, GPO/CSP adları ve registry eşlemesini doğrular. Registry **REG_DWORD=0** ayrıntısı kullanıcı ekranıyla da doğrudan desteklenir.
4. Güncel Intune Settings catalog belgesi, Windows ayarlarının CSP'lerden üretildiğini ve `Devices > Manage devices > Configuration > Create > New policy` yolunu açıklar. RemoteAssistance CSP ile birleştirilerek Settings catalog yöntemi önerilmiştir. **Tenant içindeki ayar adı/görünürlüğü canlı olarak doğrulanmamıştır**; katalogda arama ve Learn more ile exact CSP eşleşmesi koşulu vardır. Aynı ayar görünmezse benzer isimli başka bir ayara geçilmez.
5. `2026-10-01_13h34_37.png` ve `2026-10-01_13h34_52.png` sensor/data collection başlıklarıyla mevcut genel How-to eksikliğini gösterir; bu ekranlar sensor'e ait ayrıntılı portal seçenekleri göstermez.
6. `2026-10-01_13h41_44.png`, `Remove share write permission set to ‘Everyone’` exact title ve genel yönlendirmeyi gösterir; ayrıntılı portal ACL seçeneği göstermez. Yeni seçenek Windows SmbShare cmdlet belgelerine dayanır, portal metninin birebir aktarımı değildir.
7. `2026-10-01_13h35_20.png` Secure Score Implementation bölümünün ayrıntılı adımlar yerine Recommendations yönlendirmesi verdiğini doğrular.
8. Security Options belgelerinin bir bölümü 2017–2023 tarihli ve Previous versions alanına yönlenir. Açık policy adı, değer ve applicability kullanılmış; varsayılanların güncel tenant/OS ile aynı olduğu varsayılmamıştır. `scid_88` kaynağı yalnızca Windows 10 işaretler; daha yeni OS desteği pilotta doğrulanmalıdır.
9. `scid_72` için en sıkı `Refuse LM & NTLM` hedefi ve `scid_28` için 1–900 saniye aralığı ham öneriden gelir; Microsoft kaynak ayarın geçerli değerlerini ve etkisini açıklar, bu hedefleri tüm kurumlara koşulsuz gereklilik olarak sunmaz.
10. `scid_40` kaynağının Reference/Countermeasure bölümleri `Disabled` hedefinde tutarlıdır; Vulnerability bölümündeki ters anlamlı ifade esas alınmamıştır. `scid_36` kaynağının eksik render edilen default-values tablosundan varsayılan türetilmemiştir.
11. `scid_66` kaynağı iki hive'da `1` olduğunda elevation sağlandığını ve REG_DWORD türünü verir; katalogdaki iki hive için `0` açık güvenli hedefi bu koşulun tersine dayanır. GPO display name veya tenant UI varlığı bu kaynaktan uydurulmamıştır.

### Defender recommendation API: neden tam portal seçenekleri değildir?

Gerçekten alınan ve incelenen resmî belgeler:

- [Recommendation resource type](https://learn.microsoft.com/en-us/defender-endpoint/api/recommendation): `remediationType` değerleri ConfigurationChange, Update, Upgrade, Uninstall; belgelenmiş kaynak şemasında portalın tam GPO/Intune/registry adım metni alanı yoktur.
- [List all recommendations](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-recommendations): `/api/recommendations`; application izni **SecurityRecommendation.Read.All**, delegated izni **SecurityRecommendation.Read**.
- [Supported APIs](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list): API endpoint tabanı **https://api.security.microsoft.com**.
- [Create app / access token](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp): WindowsDefenderATP izinleri ve ayrı OAuth resource/audience gerekir; bazı Defender API'leri modern endpoint kullansa da token için legacy **https://api.securitycenter.microsoft.com/.default** scope bekler. Graph token'ı veya endpoint URL'sini audience kabul etmek doğru değildir.

Bu belgeler API'den metadata alınabileceğini destekler; **tam Remediation options'ın otomatik indirilebildiğini desteklemez**. Gerekli Defender izin/audience/consent olmadan API erişimi varsayılmaz. Bu görevde API token istenmedi, API çağrısı veya private portal scrape yapılmadı. JSON kamuya açık kaynaklarla hazırlanmış küratörlü içeriktir.

## Kapsanan kontroller

| Grup | SCID | Kontrol | Seçenek |
|---|---|---:|---:|
| Remote Assistance | 63, 87 | 2 | 5 |
| AutoPlay / AutoRun | 67, 69, 70 | 3 | 3 |
| Sensor teşhisi / Windows client onboarding | 2000, 2001, 2002, 20000 | 4 | 4 |
| SMB share ACL | 4001 | 1 | 1 |
| SMBv1 client/server | 53, 54 | 2 | 2 |
| Network Protection | 96 | 1 | 2 |
| EDR in block mode | 2004 | 1 | 2 |
| Cloud protection | 2016 | 1 | 2 |
| Real-time / behavior monitoring | 2012, 91 | 2 | 4 |
| Security Options / Credential UI / Installer | 27, 28, 29, 36, 40, 55, 65, 66, 68, 71, 72, 88, 93, 94, 95, 3011 | 16 | 16 |
| **Toplam** | | **33** | **41** |

Her seçenek `label`, plain-text `steps` listesi, `sourceUrls`, `verifiedDate`, `applicability` ve `verification` taşır. Her kontrolde `notes` vardır. Kaynak tarihin doğrulanması canlı tenant başarı testi değildir; skorun hemen değişeceği taahhüt edilmez.

## Kullanılan içerik kaynakları

Seçeneklerde **30 distinct Microsoft Learn URL** bulunur; yukarıdaki **4 distinct API belge URL'si** ayrıca raporun API sınırını destekler. Aşağıdaki adresler gerçekten retrieval yapılmış, redirect varsa hedef metni incelenmiş adreslerdir:

- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remoteassistance
- https://learn.microsoft.com/en-us/intune/intune-service/configuration/settings-catalog
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-credentialsui
- https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated
- https://learn.microsoft.com/en-us/defender-endpoint/onboard-windows-client
- https://learn.microsoft.com/en-us/defender-endpoint/fix-unhealthy-sensors
- https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-windows
- https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection
- https://learn.microsoft.com/en-us/defender-endpoint/edr-in-block-mode
- https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus
- https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus
- https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbshareaccess?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/smbshare/revoke-smbshareaccess?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/smbshare/grant-smbshareaccess?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-limit-local-account-use-of-blank-passwords-to-console-logon-only
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-disable-machine-account-password-changes
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-require-strong-windows-2000-or-later-session-key
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-client-digitally-sign-communications-always
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-client-send-unencrypted-password-to-third-party-smb-servers
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-let-everyone-permissions-apply-to-anonymous-users
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-standard-users

Bazı eski adresler güncel canonical adrese yönlenmiştir: `onboard-windows-client` → `onboard-client`; Intune Settings catalog → `/intune/device-configuration/settings-catalog/`; cloud protection → `cloud-protection-configure`; Security Options → `/previous-versions/windows/it-pro/windows-10/...`. JSON'da gerçek retrieval başlangıç URL'si saklanır, tahmin edilmiş kaynak eklenmez.

## Eksik kapsam ve sonraki doğrulama

- Windows dışı macOS/Linux/WSL ve network cihazları için platforma özel adımlar tamamlanmamıştır.
- ASR ailesi, LSA/Credential Guard, LDAP/NTLM, Firewall/BitLocker ve legacy Adobe/Flash/IE kontrolleri bu sürümde doğrulanmış ayrıntılı seçenek kapsamına dahil değildir.
- ASR reference/configuration ile RemoteManagement ve onboarding troubleshooting gibi bazı uzun sayfalar araştırmada alınmış ancak tam, kontrol düzeyinde inceleme tamamlanmamıştır; sırf belge bulundu diye SCID'ler kapsanmış sayılmamıştır.
- Bazı alternatif belge yollarında retrieval sonucu yoktur; bu sonuç ilgili politikanın bulunmadığını kanıtlamaz. Tamamlanmış alt kaynakla desteklenmeyen seçenekler eklenmemiştir.
- En küçük faydalı devam işi: ASR ailesindeki 19 kontrol için exact rule/GUID, desteklenen OS, Intune/GPO değerleri, audit→block geçişi ve istisna sınırlarını kontrol bazında incelemek; sonra `scid_73/74` için RemoteManagement belgesinin Basic authentication alt bölümlerini doğrulamak. İnceleme bitmeden aynı genel adımları 151 eksik kontrole kopyalamayın.

### Eksik 151 kontrol — exact SCID/title

- `scid_9` — Enable 'Local Machine Zone Lockdown Security'
- `scid_15` — Enable Automatic Updates
- `scid_16` — Enable 'Hide Option to Enable or Disable Updates'
- `scid_17` — Disable 'Allow running plugins that are outdated'
- `scid_19` — Disable 'Continue running background apps when Google Chrome is closed'
- `scid_20` — Disable 'AutoFill'
- `scid_21` — Block webpages from automatically running Flash plugins
- `scid_22` — Disable 'Password Manager'
- `scid_23` — Enable 'Block third party cookies'
- `scid_24` — Set 'Remote Desktop security level' to 'TLS'
- `scid_25` — Enable 'Local Security Authority (LSA) protection'
- `scid_26` — Enable 'Safe DLL Search Mode'
- `scid_30` — Disable 'Insecure guest logons' in SMB
- `scid_32` — Set 'Minimum password length' to '14 or more characters'
- `scid_33` — Set 'Enforce password history' to '24 or more password(s)'
- `scid_34` — Set 'Maximum password age' to '60 or fewer days, but not 0'
- `scid_35` — Set 'Minimum password age' to '1 or more day(s)'
- `scid_37` — Enable 'Domain member: Digitally encrypt or sign secure channel data (always)'
- `scid_38` — Enable Set 'Domain member: Digitally encrypt secure channel data (when possible)'
- `scid_39` — Enable 'Domain member: Digitally sign secure channel data (when possible)'
- `scid_41` — Set 'Account lockout duration' to 15 minutes or more
- `scid_42` — Set 'Reset account lockout counter after' to 15 minutes or more
- `scid_43` — Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile
- `scid_44` — Set 'Account lockout threshold' to 1-10 invalid login attempts
- `scid_45` — Set user authentication for remote connections by using Network Level Authentication to 'Enabled'
- `scid_46` — Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile
- `scid_49` — Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile
- `scid_50` — Disable merging of local Microsoft Defender Firewall rules with group policy firewall rules for the Public profile
- `scid_51` — Disable merging of local Microsoft Defender Firewall connection rules with group policy firewall rules for the Public profile
- `scid_52` — Enable 'Apply UAC restrictions to local accounts on network logons'
- `scid_57` — Disable 'WDigest Authentication'
- `scid_58` — Disable 'Installation and configuration of Network Bridge on your DNS domain network'
- `scid_59` — Enable 'Require domain users to elevate when setting a network's location'
- `scid_60` — Prohibit use of Internet Connection Sharing on your DNS domain network
- `scid_61` — Set 'Minimum PIN length for startup' to '6 or more characters'
- `scid_62` — Enable 'Require additional authentication at startup'
- `scid_64` — Restrict anonymous access to named pipes and Shares
- `scid_73` — Disable 'Allow Basic authentication' for WinRM Client
- `scid_74` — Disable 'Allow Basic authentication' for WinRM Service
- `scid_75` — Disable Flash on Adobe Reader DC
- `scid_76` — Disable JavaScript on Adobe Reader DC
- `scid_77` — Disable Flash on Adobe Acrobat Pro XI
- `scid_78` — Disable JavaScript on Adobe Acrobat Pro XI
- `scid_79` — Disable running or installing downloaded software with invalid signature
- `scid_80` — Block Flash activation in Office documents
- `scid_81` — Set IPv6 source routing to highest protection
- `scid_82` — Disable IP source routing
- `scid_83` — Enable Explorer Data Execution Prevention (DEP)
- `scid_85` — Block outdated ActiveX controls for Internet Explorer
- `scid_89` — Enable scanning of removable drives during a full scan
- `scid_90` — Enable Microsoft Defender Antivirus email scanning
- `scid_92` — Enable Microsoft Defender Antivirus scanning of downloaded files and attachments
- `scid_97` — Disable JavaScript on Adobe DC
- `scid_98` — Disable JavaScript on Adobe Reader 2017
- `scid_99` — Disable JavaScript on Adobe Acrobat 2017
- `scid_100` — Disable JavaScript on Adobe Reader 2015
- `scid_101` — Disable JavaScript on Adobe 2015
- `scid_102` — Enable 'Local Security Authority (LSA) protection' on Windows 11 22h2 and higher
- `scid_103` — Require LDAP client signing to prevent tampering and protect directory authentication
- `scid_104` — Encrypt LDAP client traffic to protect sensitive data in transit
- `scid_105` — Enforce LDAP channel binding to protect authentication sessions from interception
- `scid_106` — Require LDAP server signing to ensure integrity of directory traffic
- `scid_107` — Block outbound network connections from Microsoft HTML Application Host (mshta.exe)
- `scid_108` — Disable Remote Registry Service on Windows
- `scid_109` — Disable NTLM authentication for Windows
- `scid_110` — Block file transfer over RDP
- `scid_111` — SMB server security hardening against authentication relay attacks
- `scid_112` — Ensure devices are updated to Secure Boot 2023 certificates and boot manager
- `scid_113` — Ensure LAPS is enabled on every endpoint and server
- `scid_114` — Reduce unnecessary inbound internet exposure on internet-facing devices
- `scid_115` — Ensure Microsoft Vulnerable Driver Blocklist is enabled
- `scid_118` — scid_118
- `scid_2003` — Turn on Tamper Protection
- `scid_2010` — Turn on Microsoft Defender Antivirus
- `scid_2011` — Update Microsoft Defender Antivirus definitions
- `scid_2013` — Turn on PUA protection in block mode
- `scid_2014` — Fix Windows Defender Antivirus cloud service connectivity
- `scid_2020` — Turn on all system-level Exploit protection settings
- `scid_2021` — Set controlled folder access to enabled or audit mode
- `scid_2030` — Update Microsoft Defender for Endpoint core components
- `scid_2060` — Set Microsoft Defender SmartScreen app and file checking to block or warn
- `scid_2061` — Set Microsoft Defender SmartScreen Microsoft Edge site and download checking to block or warn
- `scid_2070` — Turn on Microsoft Defender Firewall
- `scid_2071` — Secure Microsoft Defender Firewall domain profile
- `scid_2072` — Secure Microsoft Defender firewall private profile
- `scid_2073` — Secure Microsoft Defender Firewall public profile
- `scid_2080` — Turn on Microsoft Defender Credential Guard
- `scid_2090` — Encrypt all BitLocker-supported drives
- `scid_2091` — Resume BitLocker protection on all drives
- `scid_2093` — Ensure BitLocker drive compatibility
- `scid_2100` — Enable UEFI Secure Boot mode
- `scid_2500` — Block executable content from email client and webmail
- `scid_2501` — Block all Office applications from creating child processes
- `scid_2502` — Block Office applications from creating executable content
- `scid_2503` — Block Office applications from injecting code into other processes
- `scid_2504` — Block JavaScript or VBScript from launching downloaded executable content
- `scid_2505` — Block execution of potentially obfuscated scripts
- `scid_2506` — Block Win32 API calls from Office macros
- `scid_2507` — Block executable files from running unless they meet a prevalence, age, or trusted list criterion
- `scid_2508` — Use advanced protection against ransomware
- `scid_2509` — Block credential stealing from the Windows local security authority subsystem (lsass.exe)
- `scid_2510` — Block process creations originating from PSExec and WMI commands
- `scid_2511` — Block untrusted and unsigned processes that run from USB
- `scid_2512` — Block Office communication application from creating child processes
- `scid_2513` — Block Adobe Reader from creating child processes
- `scid_2514` — Block persistence through WMI event subscription
- `scid_2515` — Block abuse of exploited vulnerable signed drivers
- `scid_2516` — Block Webshell creation for Servers
- `scid_2517` — Block use of copied or impersonated system tools
- `scid_2518` — Block rebooting machine in Safe Mode
- `scid_3001` — Fix unquoted service path for Windows services
- `scid_3002` — Change service executable path to a common protected location
- `scid_3003` — Change service account to avoid cached password in windows registry
- `scid_3010` — Disable the built-in Administrator account
- `scid_4000` — Disallow offline access to shares
- `scid_4002` — Remove shares from the root folder
- `scid_4003` — Set folder access-based enumeration for shares
- `scid_5001` — Fix Microsoft Defender for Endpoint sensor data collection in macOS
- `scid_5002` — Fix Microsoft Defender for Endpoint impaired communications in macOS
- `scid_5003` — Set minimum password length to 15 or more characters in macOS
- `scid_5004` — Set 'Enforce password history' to '24 or more password(s)' in macOS
- `scid_5005` — Set 'Maximum password age' to '90 or fewer days, but not 0' in macOS
- `scid_5006` — Set account lockout threshold to 5 or lower in macOS
- `scid_5007` — Turn on Firewall in macOS
- `scid_5009` — Enable Gatekeeper in macOS
- `scid_5010` — Enable System Integrity Protection (SIP) in macOS
- `scid_5011` — Enable FileVault Disk Encryption in macOS
- `scid_5013` — Ensure screensaver is set to start in 20 minutes or less in macOS
- `scid_5014` — Secure Home Folders in macOS
- `scid_5090` — Turn on Microsoft Defender Antivirus real-time protection in macOS
- `scid_5091` — Turn on Microsoft Defender Antivirus PUA protection in block mode in macOS
- `scid_5092` — Turn on Tamper Protection for MacOS
- `scid_5093` — Enable Microsoft Defender Antivirus real-time behavior monitoring in macOS
- `scid_5094` — Enable Microsoft Defender Antivirus cloud-delivered protection in macOS
- `scid_5095` — Update Microsoft Defender Antivirus definitions in macOS
- `scid_5115` — Configure Microsoft Defender system extensions as non-removable on macOS
- `scid_6001` — Fix Microsoft Defender for Endpoint sensor data collection for Linux
- `scid_6002` — Fix Microsoft Defender for Endpoint impaired communications for Linux
- `scid_6014` — Unrestricted Access Accounts for Linux
- `scid_6090` — Turn on Microsoft Defender Antivirus real-time protection for Linux
- `scid_6091` — Turn on Microsoft Defender Antivirus PUA protection in block mode for Linux
- `scid_6092` — Turn on Microsoft Defender Antivirus Tamper Protection for Linux
- `scid_6093` — Enable Microsoft Defender Antivirus real-time behavior monitoring for Linux
- `scid_6094` — Enable Microsoft Defender Antivirus cloud-delivered protection for Linux
- `scid_6095` — Update Microsoft Defender Antivirus definitions for Linux
- `scid_6100` — Enable 'Microsoft Defender for Endpoint Plug-in for WSL'
- `scid_6101` — Turn off custom kernel/commandline in Windows Subsystem for Linux
- `scid_10000` — Disable insecure administration protocol – Telnet
- `scid_10001` — Require authentication for Telnet management interface
- `scid_10002` — Remove insecure administration protocols SNMP V1 and SNMP V2
- `scid_10003` — Require authentication for VNC management interface

## Uygulama ajanına teslim notları

- Dosyalar yalnızca `/mnt/workspace/working/remediation-options-v3.2.json` ve `/mnt/workspace/working/remediation-coverage-v3.2.md` altında oluşturulmuştur; engine düzenlenmemiştir.
- İçeriği How-to altında **Remediation options** olarak gösterirken exact lowercase SCID ile eşleştirin; `title` kontrol eşleşmesini denetlemek için tutulur. `steps` plain-text listelerini numaralandırın, Türkçe applicability/verification/notes ve gerçek sourceUrls alanlarını görünür tutun.
- Katalogda bulunmayan 151 kontrolde bu seçenekler varmış gibi göstermeyin; mevcut genel kaynak yönlendirmesini ayrı ve açık sınırlamayla bırakın. Bu iki içerik dosyası çeviri pack fallback davranışını değiştirmez; v3.2 çeviri uyarlamaları ve kaynak/uyarı gösterimi uygulama ajanının bağımsız engine/pack çalışmasıdır.
- Registry/GPO/Intune seçenekleri alternatif uygulama yollarıdır; aynı ayarı farklı araçlarla çakışacak biçimde uygulama zorunluluğu değildir.
- Herhangi bir command/registry değişikliği bu araştırmada çalıştırılmamıştır. Share ACL için tüm Allow ACE'lerinin kaldırılması, Everyone Deny riski ve tek hedef şartı özellikle korunmuştur.
- JSON parse, required alanlar, exact title eşleşmeleri, coverage sayıları ve eksik liste ham profile karşı doğrulanmıştır. Tenant UI veya cihazdaki etkin sonuçlar uygulanırken ayrıca doğrulanmalıdır.

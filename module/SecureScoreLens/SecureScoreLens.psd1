@{
    RootModule        = 'SecureScoreLens.psm1'
    ModuleVersion     = '3.1.4'
    GUID              = 'b7e4c1a2-5f38-4d6b-9c07-2a1e8d4f6b31'
    Author            = 'KocSistem Siber Guvenlik'
    CompanyName       = 'KocSistem'
    Copyright         = '(c) KocSistem. Tum haklari saklidir.'
    Description       = 'Microsoft 365 Secure Score icin salt-okunur degerlendirme araci. Tenant Secure Score puanini ve tum iyilestirme islemlerini okuyup Turkce, tek dosyalik interaktif HTML rapor uretir. Tenant uzerinde hicbir degisiklik yapmaz ve kimlik bilgisi saklamaz.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @('Invoke-SecureScoreLens', 'Clear-SecureScoreCredential')
    AliasesToExport   = @('Invoke-SecureScoreAssessment')
    CmdletsToExport   = @()
    VariablesToExport = @()

    FileList = @(
        'SecureScoreLens.psm1'
        'SecureScoreLens.psd1'
        'assets/secure_score_assessment.py'
        'assets/secure_score_tr.json'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('Microsoft365','SecureScore','Security','Assessment','Compliance',
                             'Graph','ReadOnly','Turkish','Report')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = @'
2.0.0
- Bolumlendirilmis rapor: Genel Bakis / Tum Iyilestirme Islemleri / 30-60-90 Gun Yol Haritasi
- Etki derecesi modeli (Kritik / Yuksek / Orta / Dusuk) ve etkiye gore siralama
- Acik tema, tek renk sistemi; ust bolumde tiklanabilir metrik kartlari
- Yonetici ozeti, kategori dagilimi ve sektor karsilastirmasi ayni kartta
- Yol haritasi amac ve yaklasim bolumu
- E.E baslik ekrani

1.0.0
- Salt-okunur Secure Score degerlendirmesi
- Her calistirmada tarayicida Microsoft izin ekrani (prompt=consent); kimlik bilgisi saklanmaz
- Tenant'a uygulanabilir tum iyilestirme islemlerinin analizi
- Turkce icerik paketi (islem adimlari ve durum metinleri)
- Tek dosyalik, filtrelenebilir HTML rapor; CSV ve JSON disa aktarim
'@
        }
    }
}

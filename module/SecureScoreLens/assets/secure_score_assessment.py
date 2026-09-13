#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Microsoft 365 Secure Score Assessment Tool  (v2)
================================================

Read-only tenant assessment. Connects to a Microsoft 365 / Entra ID tenant with an
app-only identity, reads the Microsoft Secure Score, evaluates every improvement
action that APPLIES TO THAT TENANT, and produces a clean customer-facing dashboard
(HTML) plus CSV / JSON exports.

Accuracy rules (v2)
-------------------
* The tenant's own score snapshot is authoritative. Headline score, max score and
  percentage are taken verbatim from /security/secureScores - they always match the
  Microsoft 365 Defender portal.
* Only controls present in the tenant snapshot are counted. The global control
  catalogue contains actions for products the tenant is not licensed for; these are
  reported separately as "not applicable", never mixed into totals or category maths.
* Deprecated controls are excluded.
* Action state (Completed / To address / Planned / Risk accepted / Third party /
  Alternate mitigation) follows the portal's own semantics, including the notes and
  timestamps recorded by admins.
* "Regressed" actions are detected by comparing the two most recent snapshots.

Required permission: SecurityEvents.Read.All  (Organization.Read.All optional)
No third-party packages - Python 3.8+ standard library only.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
USER_AGENT = "SecureScoreLens/3.1"
TIMEOUT = 60

# --------------------------------------------------------------------------- #
# Localisation
# --------------------------------------------------------------------------- #
STR = {
    "tr": {
        "title": "Microsoft 365 Secure Score Değerlendirmesi",
        "tenant": "Kurum", "tenant_id": "Tenant ID", "domain": "Birincil alan adı",
        "measured": "Ölçüm tarihi", "generated": "Rapor tarihi",
        "score": "Secure Score", "points": "puan", "of": "/",
        "risk": "Risk seviyesi", "trend30": "Son 30 gün",
        "actions_title": "İşlem durumu",
        "to_address": "Yapılması gereken", "planned": "Planlandı",
        "risk_accepted": "Risk kabul edildi", "third_party": "Üçüncü parti ile çözüldü",
        "alternate": "Alternatif önlemle çözüldü", "completed": "Tamamlandı",
        "partial": "kısmen başlandı", "regressed": "Geriye gitti",
        "not_applicable": "Kapsam dışı (lisans yok)",
        "trend": "Puan gelişimi", "benchmark": "Karşılaştırma",
        "categories": "Kategori bazlı durum",
        "category": "Kategori", "achieved": "Tamamlanma", "gap": "Kazanılabilir puan",
        "done_count": "Tamamlanan işlem",
        "priority": "Öncelikli işlemler — en yüksek puan kazancı",
        "quickwins": "Hızlı kazanımlar — kullanıcı etkisi düşük",
        "open_actions": "Yapılmamış işlemler",
        "done_actions": "Yapılmış işlemler",
        "excluded_actions": "Bilinçli olarak kapatılan işlemler (risk kabul / üçüncü parti / alternatif önlem)",
        "col_action": "İşlem", "col_category": "Kategori", "col_status": "Durum",
        "col_points": "Puan", "col_gain": "Kazanç", "col_impact": "Kullanıcı etkisi",
        "col_note": "Not / yapılan işlem", "col_link": "",
        "impact_low": "Düşük", "impact_moderate": "Orta", "impact_high": "Yüksek",
        "no_items": "Bu grupta işlem yok.",
        "search": "İşlem ara...",
        "summary": "Yönetici özeti",
        "footer": ("Bu rapor Microsoft Graph üzerinden salt-okunur olarak üretilmiştir "
                   "(/security/secureScores ve /security/secureScoreControlProfiles). "
                   "Tenant üzerinde hiçbir değişiklik yapılmamıştır."),
        "na_note": ("kontrol tenant'ta uygulanabilir değil (ilgili ürün/lisans yok) ve "
                    "puan hesabına dahil edilmemiştir."),
        "no_note": "—",
        "summary_tpl": ("Kurumun Secure Score puanı {score} / {maxscore} ({pct}%) — risk seviyesi {risk}. "
                        "Tenant'a uygulanabilir {total} iyileştirme işleminden {done} tanesi tamamlanmış, "
                        "{open} tanesi açık durumda. Açık işlemlerin tamamlanması durumunda "
                        "{gap} puan kazanılabilir."),
        "sum_lead": ("{cust} kurumunun Microsoft Secure Score puanı {pct} "
                     "({score} / {maxscore}) — risk seviyesi {risk}."),
        "sum_body": ("Tenant'a uygulanabilir {total} iyileştirme işleminden {done} tanesi "
                     "tamamlanmış, {open} tanesi açık durumda. Açık işlemler toplam "
                     "{gap} puanlık iyileştirme potansiyeli taşıyor."),
        "sum_cat": ("<b>En büyük fırsat {cat} kategorisinde:</b> {openn} açık işlem, "
                    "{gap} puan kazanç potansiyeli (şu an %{pct} tamamlanmış)."),
        "sum_top": ("<b>İlk {n} öncelik:</b> {items} — yalnızca bu üçü {sub} puan getirir."),
        "sum_quick": ("<b>Hızlı kazanım:</b> kullanıcı etkisi düşük {n} işlem var; "
                      "bunlar {gain} puanı sınırlı operasyonel etkiyle sağlar."),
        "sum_reg": ("<b>Acil inceleme:</b> {n} işlem daha önce aldığı puanı kaybetti — "
                    "bir yapılandırma, kullanıcı veya cihaz değişikliği geri adım attırmış olabilir."),
        "sum_closed": ("{n} işlem bilinçli olarak kapatılmış (risk kabul edildi, üçüncü parti "
                       "çözüm veya alternatif önlem); bunların uygulama doğruluğunu Microsoft denetlemez."),
        "sum_bench_up": ("Kurum, tüm tenant ortalamasının ({avg}) {diff} üzerinde."),
        "sum_bench_down": ("Kurum, tüm tenant ortalamasının ({avg}) {diff} altında."),
        # Graph returns these as raw English enums; give them Turkish labels
        "fnd_exec": "Yönetici Özeti",
        "fnd_exec_b": ("Bu rapor, {cust} Microsoft 365 ortamında Microsoft Secure Score "
                       "çıktısında yer alan ve <b>henüz uygulanmamış {n} güvenlik önerisinin</b> "
                       "kurumsal iyileştirme raporu formatına uyarlanmasıyla hazırlanmıştır. "
                       "Her madde <b>Bulgu 1</b>'den <b>Bulgu {n}</b>'e kadar ayrı bir bulgu "
                       "kartı olarak yapılandırılmış; bulgu adı, etkilenen kaynak, kategori, "
                       "açıklama, etki, risk seviyesi ve iyileştirme değişikliği alanları "
                       "korunarak rapora dahil edilmiştir."),
        "fnd_purpose": "Raporun Amacı",
        "fnd_purpose_b": ("Secure Score önerilerini teknik kontrol listesi seviyesinden çıkarıp "
                          "yönetilebilir, önceliklendirilebilir ve aksiyon alınabilir bir güvenlik "
                          "iyileştirme yol haritasına dönüştürmektir. Her maddenin yapılandırma "
                          "adımları Microsoft'un kendi yönergesinden alınmış; açıklama, etki, "
                          "ortam bağımlılığı ve doğrulama adımları ise kurumsal kullanıma uygun "
                          "biçimde ayrıca hazırlanmıştır. Risk seviyeleri Microsoft'un bir "
                          "sınıflandırması değildir; bu raporun <b>etki önceliklendirme "
                          "modeliyle</b> hesaplanır ve modelin formülü Yol Haritası bölümünde "
                          "açıkça belirtilmiştir."),
        "fnd_posture": "Genel Risk Duruşu",
        "fnd_posture_b": ("Bu belgedeki bulgular etki önceliklendirme modeline göre "
                          "sınıflandırılmıştır. Sınıflandırmalar renk kodludur ve aşağıda "
                          "açıklanmıştır."),
        "fnd_d_kritik": ("Ortam genelinde ele geçirme, kimlik veya veri kaybı ile doğrudan "
                         "istismara yol açabilecek; yüksek puan değeri taşıyan ve Microsoft "
                         "öncelik sıralamasında üst sırada yer alan kontroller."),
        "fnd_d_yuksek": ("Saldırı zincirinde belirleyici olan; istismarı bir ön koşul gerektiren "
                         "ya da etkisi tek bir hizmetle sınırlı kalan kontroller."),
        "fnd_d_orta": ("Güvenlik olgunluğunu ve derinlemesine savunmayı artıran; puan katkısı "
                       "veya öncelik sırası daha sınırlı olan kontroller."),
        "fnd_d_dusuk": ("İyileştirme değeri düşük ya da dar kapsamlı; diğer maddeler "
                        "tamamlandıktan sonra ele alınması uygun kontroller."),
        "fnd_pdf": "PDF olarak indir",
        "fnd_pdf_hint": ("Yazdırma penceresi açılır; hedef olarak “PDF olarak kaydet” seçin. "
                         "Yalnızca Bulgu Raporu basılır. Tarayıcının kendi üst/alt bilgisini "
                         "kaldırmak için “Diğer ayarlar” altındaki “Üstbilgi ve altbilgi” "
                         "seçeneğini kapatın; “Arka plan grafikleri” açık olmalıdır."),
        "fnd_total": "toplam açık bulgu",
        "fnd_pdf_fail": ("Tarayıcı yazdırma penceresini açamadı. Ctrl+P ile elle "
                         "yazdırıp hedef olarak “PDF olarak kaydet” seçebilirsiniz."),
        "nav_findings": "Bulgu Raporu",
        "fnd_lead": ("Açık her madde için ayrı bir bulgu kartı. Yapılandırma adımları, "
                     "öncelik sırası, puan ve tehdit türleri Microsoft Graph'tan; açıklama, "
                     "etki, ortam bağımlılığı ve doğrulama adımları içerik paketinden gelir."),
        "fnd_n": "Bulgu",
        "fnd_resource": "Etkilenen Kaynak",
        "fnd_desc": "Açıklama",
        "fnd_impact": "Etkisi",
        "fnd_risk": "Risk Seviyesi",
        "fnd_fix": "İyileştirme Değişikliği",
        "fnd_config": "Yapılandırma",
        "fnd_dep": "Ortam bağımlılığı",
        "fnd_verify": "Doğrulama",
        "fnd_more": "Ek Bilgi",
        "fnd_record": "Secure Score Kaydı",
        "fnd_link": "Microsoft belgelerini aç",
        "fnd_rank": "Microsoft öncelik sırası",
        "fnd_gain": "tamamlandığında {v} puan kazanılır",
        "fnd_threats": "Tehdit türleri",
        "fnd_scope": "kapsamındaki yapılandırmalar",
        "fnd_none": "Açık madde yok — bu bölümde gösterilecek bulgu bulunmuyor.",
        "fnd_nopack": ("Bu madde için ayrıntılı içerik henüz hazırlanmamıştır. "
                       "Yukarıdaki yapılandırma adımları Microsoft'un kendi yönergesidir."),
        "fnd_count": "açık bulgu",
        "cov_title": "Microsoft 365 Secure Score Değerlendirmesi",
        "cov_prepared_for": "Hazırlanan kurum",
        "cov_prepared_by": "Hazırlayan",
        "cov_date": "Rapor tarihi",
        "cov_tenant": "Tenant",
        "cov_domain": "Birincil alan adı",
        "cov_scope": "Kapsam",
        "cov_scope_v": "{n} uygulanabilir iyileştirme işlemi",
        "cov_score": "Secure Score",
        "cov_risk": "Risk seviyesi",
        "cov_conf": "Gizli — yalnızca kurum içi kullanım",
        "cov_method": ("Bu değerlendirme Microsoft Graph üzerinden salt-okunur olarak "
                       "üretilmiştir. Tenant üzerinde hiçbir değişiklik yapılmamıştır."),
        "cov_contents": "İçindekiler",
        "cov_c1": "Genel Bakış — puan, yönetici özeti, kategori dağılımı",
        "cov_c2": "Tüm İyileştirme İşlemleri — kapsamdaki her maddenin durumu",
        "cov_c3": "30/60/90 Gün Yol Haritası — etki önceliğine göre plan",
        "cov_c4": "İlerleme ve Kapsam — puanın neden değiştiği",
        "cov_c5": "Bulgu Raporu — her açık madde için ayrıntılı bulgu kartı",
        "cov_open": "Raporu aç ↓",
        "exp_btn": "Dışa aktar",
        "exp_title": "Dışa aktarma seçenekleri",
        "exp_scope": "Kapsam",
        "exp_filtered": "Yalnızca filtrelenmiş işlemler",
        "exp_all": "Tüm işlemler",
        "exp_cols": "İçerik",
        "exp_assign": "Sorumlu ve termin sütunları",
        "exp_steps": "Uygulama adımları",
        "exp_notes": "Durum notu",
        "exp_csv": "CSV indir",
        "exp_pdf": "PDF / Yazdır",
        "exp_pdf_hint": "Yazdırma penceresinde hedef olarak “PDF olarak kaydet” seçin.",
        "exp_empty": "Dışa aktarılacak işlem yok. Filtreleri gevşetmeyi deneyin.",
        "exp_fail": "Tarayıcı indirmeyi engelledi. Rapor dosyasını diskten açtığınızdan emin olun.",
        "exp_close": "Kapat",
        "col_max": "Maksimum", "col_regressed": "Geriye gitti",
        "yes": "Evet", "no": "Hayır",
        "asg_title": "Sorumlu ve termin",
        "asg_owner": "Sorumlu kişi / ekip",
        "asg_owner_ph": "örn. Altyapı Ekibi",
        "asg_due": "Hedef tarih",
        "asg_note": "Açıklama / durum notu",
        "asg_note_ph": "örn. değişiklik talebi açıldı",
        "asg_saved": "Bu bilgiler yalnızca bu tarayıcıda saklanır; rapor dosyası değişmez. "
                     "Paylaşmak için CSV olarak dışa aktarın.",
        "asg_export": "Atamaları dışa aktar",
        "asg_clear": "Atamaları temizle",
        "asg_confirm": "Bu rapordaki tüm sorumlu ve termin bilgileri silinecek. Devam edilsin mi?",
        "asg_assigned": "atanmış",
        "asg_overdue": "gecikmiş",
        "asg_col_owner": "Sorumlu", "asg_col_due": "Termin",
        "nav_progress": "İlerleme ve Kapsam",
        "prog_lead": ("Puanın tek başına anlattığı sınırlıdır. Bu bölüm <b>neyin</b> ve "
                      "<b>neden</b> değiştiğini gösterir: kazanılan ve kaybedilen puanlar ile "
                      "ölçüm kapsamına giren veya çıkan kontroller."),
        "prog_window": "Karşılaştırma dönemi",
        "prog_raw": "Ham puan", "prog_pct": "Tamamlanma oranı",
        "prog_measured": "Ölçülen kontrol", "prog_maxs": "Ulaşılabilir puan",
        "prog_improved": "İyileşen kontrol", "prog_regressed": "Gerileyen kontrol",
        "prog_added": "Kapsama giren", "prog_removed": "Kapsamdan çıkan",
        "prog_finding": "Dönem bulgusu",
        "prog_scope_up": ("<b>Kapsam genişledi.</b> Dönem içinde ölçüm kapsamına {added} yeni "
                          "kontrol girdi ve ulaşılabilir puan {frm} → {to} oldu. Yeni bir ürün "
                          "veya lisans devreye alındığında beklenen durumdur; ham puan artsa "
                          "bile yüzde geçici olarak düşebilir."),
        "prog_scope_down": ("<b>Kapsam daraldı.</b> Dönem içinde {removed} kontrol ölçüm "
                            "kapsamından çıktı ve ulaşılabilir puan {frm} → {to} oldu. "
                            "Genellikle bir lisansın veya ürünün devre dışı kalmasıyla olur."),
        "prog_scope_same": ("<b>Kapsam değişmedi.</b> Ulaşılabilir puan dönem boyunca {to} "
                            "seviyesinde kaldı; puandaki hareket doğrudan yapılandırma "
                            "değişikliklerinden geliyor."),
        "prog_net_up": "Dönem net kazancı {v} puan.",
        "prog_net_down": "Dönem net kaybı {v} puan.",
        "prog_net_flat": "Dönem boyunca net puan değişimi olmadı.",
        "prog_t_improved": "İyileşen kontroller",
        "prog_t_regressed": "Gerileyen kontroller",
        "prog_t_added": "Kapsama giren kontroller",
        "prog_t_removed": "Kapsamdan çıkan kontroller",
        "prog_h_before": "Önceki", "prog_h_now": "Şimdi", "prog_h_delta": "Değişim",
        "prog_none": "Bu dönemde bu kategoride değişiklik yok.",
        "prog_nodata": ("Karşılaştırma için yeterli geçmiş ölçüm bulunamadı. En az iki farklı "
                        "günün ölçümü gerekir; ilk çalıştırmada bu bölüm boş görünür."),
        "prog_note": ("Karşılaştırma, tenant'ın kendi ölçüm anlık görüntüleri üzerinden "
                      "yapılır. Gösterilen ilk ve son tarih Microsoft Graph'tan alınan "
                      "en eski ve en yeni ölçümdür."),
        "projection": "Puan projeksiyonu",
        "proj_ky": "Kritik + yüksek işlemler kapatılırsa",
        "proj_qw": "Hızlı kazanımlar uygulanırsa",
        "proj_none": "Açık işlem kalmadı — puan üst sınırda.",
        "sum_trend_up": ("<b>Son {days} gün:</b> puan {frm} seviyesinden {to} seviyesine "
                         "çıktı ({diff})."),
        "sum_trend_down": ("<b>Son {days} gün:</b> puan {frm} seviyesinden {to} seviyesine "
                           "geriledi ({diff}) — değişiklikleri gözden geçirin."),
        "sum_trend_flat": ("<b>Son {days} gün:</b> puan {to} seviyesinde sabit kaldı — "
                           "bu dönemde net bir iyileşme kaydedilmemiş."),
        "sum_service": ("<b>Yoğunlaşma:</b> açık işlemlerin {n} tanesi {svc} tarafında "
                        "({gap} puan) — tek bir üründe yapılacak çalışma en hızlı sonucu verir."),
        "sum_effort": ("<b>Uygulama eforu:</b> açık işlemlerin {n} tanesi düşük maliyetli "
                       "yapılandırma değişikliği; {gain} puan ek yatırım gerektirmeden alınabilir."),
        "basis_alltenants": "Tüm kurumlar ortalaması",
        "basis_totalseats": "Benzer büyüklükteki kurumlar",
        "basis_industrytypes": "Aynı sektördeki kurumlar",
        "threat_account_breach": "Hesap ele geçirilmesi",
        "threat_data_exfiltration": "Veri sızdırılması",
        "threat_data_spillage": "Veri sızıntısı",
        "threat_data_deletion": "Veri silinmesi",
        "threat_elevation_of_privilege": "Yetki yükseltme",
        "threat_malicious_insider": "Kötü niyetli iç kullanıcı",
        "threat_password_cracking": "Parola kırma",
        "threat_phishing_or_whaling": "Kimlik avı",
        "threat_spoofing": "Kimlik sahteciliği",
        # --- v7 report strings -------------------------------------------
        "mark": "E.E",
        "nav_overview": "Genel Bakış", "nav_roadmap": "30/60/90 Gün Yol Haritası",
        "applicable": "Uygulanabilir", "open_short": "Açık",
        "applied_control": "uygulanmış kontrol", "urgent": "acil ele alınmalı",
        "point_loss": "puan kaybı", "gainable": "Kazanılabilir",
        "point_potential": "puan potansiyeli",
        "go_overview": "Genel bakış", "go_all": "Tümünü gör", "go_list": "Listeyi aç",
        "go_roadmap": "Yol haritası",
        "cat_dist": "KATEGORİ DAĞILIMI",
        "sev_label": "Etki derecesi", "sev_short": "Etki",
        "sev_kritik": "Kritik", "sev_yuksek": "Yüksek", "sev_orta": "Orta", "sev_dusuk": "Düşük",
        "sev_open_title": "Etki derecesine göre açık işlemler",
        "sev_open_hint": "karta tıklayın — ilgili liste açılır",
        "top5": "En kritik 5 işlem", "by_severity": "etki derecesine göre",
        "ms_rank": "Microsoft sırası",
        "sort_sev": "Etki derecesine göre",
        "and_more": "ve {n} madde daha",
        "reg_banner": ("işaretli işlemler gösteriliyor — daha önce puan alınmış, "
                       "sonra bu puan kaybedilmiş maddeler."),
        "reg_clear": "Filtreyi kaldır",
        "legend_title": "Etiketler ne anlama geliyor?",
        "legend_open": "İşlem hiç uygulanmamış; bu maddeden puan alınmıyor.",
        "legend_partial": ("İşlem bir kısım kullanıcı veya cihazda uygulanmış. Microsoft "
                           "kapsama oranına göre kısmi puan verir; tamamı kapsandığında "
                           "puanın tamamı alınır."),
        "legend_done": "İşlem tam olarak uygulanmış; maksimum puan alınıyor.",
        "legend_reg": "Daha önce puan alınmış, sonra bu puan kaybedilmiş maddeler.",
        "legend_reg_n": "Bu tenant'ta <b>{n} işlem</b> bu durumda.",
        "purpose": "Amaç",
        "road_h": ("Güvenlik açıklarını, ortama etkisine göre sıraya koyup 90 günde "
                   "kapatılabilir bir plana dönüştürmek"),
        "road_p": ("Secure Score raporları çoğu zaman uzun bir eksik listesi üretir ve "
                   "\"önce hangisi?\" sorusu cevapsız kalır. Bu yol haritası, açık {n} işlemi "
                   "<b>ortamı ne kadar etkilediklerine</b> göre sıralayarak üç faza böler. "
                   "Böylece ekip her ay net bir kapsamla çalışır, yönetim ise her fazın "
                   "puana katkısını önceden görür."),
        "road_1h": "Önce etki, sonra kolaylık",
        "road_1p": ("Sıralama puan büyüklüğü, Microsoft'un öncelik sırası, önlenen tehdit "
                    "türü ve geriye gitme durumuna göre yapılır — alfabetik veya rastgele değil."),
        "road_2h": "Fazlara bölünmüş kapsam",
        "road_2p": ("Faz 1 kritik açıklar (0–30 gün), Faz 2 yüksek etkili maddeler "
                    "(31–60 gün), Faz 3 olgunlaşma çalışmaları (61–90 gün). Her fazın madde "
                    "sayısı ve puan kazancı bellidir."),
        "road_3h": "Ölçülebilir hedef",
        "road_3p": ("Her fazın sonunda ulaşılması beklenen Secure Score yüzdesi hesaplanır. "
                    "Bir sonraki değerlendirmede gerçekleşen ile hedef karşılaştırılabilir."),
        "road_4h": "Operasyonel gerçeklik",
        "road_4p": ("Her madde için kullanıcı etkisi ve uygulama maliyeti gösterilir; böylece "
                    "plan yapılırken kesinti riski ve iş gücü ihtiyacı önceden bilinir."),
        "road_note": ("Hedef, açık işlemlerin tamamının kapatılması durumunda {target} "
                      "seviyesine ulaşmaktır ({gap} puanlık iyileştirme potansiyeli). "
                      "Gerçek hedef ve süreler müşteri ekibiyle birlikte belirlenmelidir."),
        "expected": "Beklenen puan gelişimi", "as_phases": "fazlar tamamlandıkça",
        "today": "Bugün", "d30": "30 gün", "d60": "60 gün", "d90": "90 gün",
        "phase1": "Faz 1", "phase1_when": "0–30 gün",
        "phase1_desc": "Kritik etki — ortamı en çok etkileyen açıklar, derhal ele alınmalı",
        "phase2": "Faz 2", "phase2_when": "31–60 gün",
        "phase2_desc": "Yüksek etki — planlı değişikliklerle kapatılacak maddeler",
        "phase3": "Faz 3", "phase3_when": "61–90 gün",
        "phase3_desc": "Orta ve düşük etki — süreklilik ve olgunlaşma çalışmaları",
        "sev_how": "Etki derecesi nasıl hesaplanıyor?",
        "sev_how_p": ("Microsoft, Secure Score işlemleri için hazır bir önem derecesi "
                      "yayımlamaz. Bu rapordaki etki derecesi, Microsoft'un yayımladığı "
                      "alanlardan hesaplanır:"),
        "sev_f1": "Puan ağırlığı",
        "sev_f1d": "işlemin maksimum puanı; ortama etkisinin en nesnel ölçüsü",
        "sev_f2": "Microsoft öncelik sırası", "sev_f2d": "Microsoft'un kendi sıralaması",
        "sev_f3": "Önlediği tehditler",
        "sev_f3d": "hesap ele geçirilmesi ve yetki yükseltme en yüksek ağırlıkta",
        "sev_f4": "Geriye gitme",
        "sev_f4d": "daha önce alınmış puanın kaybedilmesi ağırlığı belirgin artırır",
        "sev_f5": "Kontrol katmanı",
        "sev_f5d": "Microsoft'un \"Core\" olarak işaretlediği temel kontroller",
        "sev_how_note": ("Hesaplanan değer her işlemin ayrıntısında parantez içinde gösterilir. "
                         "Bu bir Microsoft sınıflandırması değil, bu raporun önceliklendirme "
                         "modelidir."),
        "sum_critical": ("<b>Acil müdahale gerekenler:</b> {n} işlem kritik etki derecesinde — "
                         "bunlar ortamı en çok etkileyen açıklar ve ilk 30 günde kapatılması "
                         "önerilir."),
        "gap_short": "kazanılabilir",
        "customer": "Müşteri", "prepared_for": "Bu değerlendirme şu kurum için hazırlanmıştır",
        "prepared_by": "Hazırlayan", "col_product": "Ürün", "col_cost": "Uygulama maliyeti",
        "col_effect": "Kullanıcı üzerindeki etkisi", "threats": "Önlediği tehditler",
        "quickwins_short": "Hızlı kazanım", "closed_short": "Kapatılan",
        "action_unit": "işlem", "at_glance": "Özet bilgi", "implementation": "Nasıl yapılır",
        "details": "Ayrıntılar", "open_portal": "Portalda aç",
        "no_remediation": "Bu işlem için Microsoft tarafından adım bilgisi sağlanmamış.",
        "all_actions": "Tüm iyileştirme işlemleri",
        "status_dist": "İşlem durumu dağılımı",
        "classification": "GİZLİ — yalnızca yetkili kişilerle paylaşın",
        "users": "Lisanslı kullanıcı",
        "sort": "Sıralama", "sort_gain": "Kazanılabilir puana göre",
        "sort_points": "Toplam puana göre", "sort_title": "İsme göre",
        "expand_all": "Tümünü aç", "collapse_all": "Tümünü kapat",
        "reset": "Temizle", "shown": "işlem gösteriliyor",
        "na_line": "{n} kontrol maddesi bu tenant'ta uygulanabilir değil (ilgili ürün lisansı yok) ve puan hesabına dahil edilmemiştir.",
        "method": "Yöntem ve sınırlar",
        "m1": "Puan, maksimum puan ve yüzde doğrudan tenant'ın Microsoft Secure Score ölçümünden alınır; hesaplanmaz.",
        "m2": "Her iyileştirme işlemi en fazla 10 puandır. Çoğu ya tamamen alınır ya da hiç alınmaz; bazıları ise yapılandırma oranına göre kısmi puan verir (örneğin kullanıcıların yarısı kapsanıyorsa puanın yarısı).",
        "m3": "Bir değişiklik yaptıktan sonra puana yansıması 24-48 saat sürebilir.",
        "m4": "Lisans kapsamı dışındaki maddeler paydaya dahil edilmez; 'risk kabul edildi', 'üçüncü parti' ve 'alternatif önlem' olarak işaretlenen maddelerin uygulama doğruluğunu Microsoft denetlemez.",
        "m5": "Secure Score güvenlik duruşunun sayısal bir özetidir; ihlal olasılığının mutlak ölçüsü değildir.",
        "m6": ("Kullanılan yetkiler (tamamı salt-okunur): SecurityEvents.Read.All — Secure Score ve "
               "kontrol maddeleri; Organization.Read.All — kurum adı ve alan adı. Yazma, değiştirme "
               "veya silme yetkisi istenmemiştir."),
        "regressed_note": "{n} işlem son ölçümde geriye gitti — öncelikle bunlar incelenmelidir.",
    },
    "en": {
        "title": "Microsoft 365 Secure Score Assessment",
        "tenant": "Organisation", "tenant_id": "Tenant ID", "domain": "Primary domain",
        "measured": "Measured", "generated": "Generated",
        "score": "Secure Score", "points": "points", "of": "of",
        "risk": "Risk level", "trend30": "Last 30 days",
        "actions_title": "Action status",
        "to_address": "To address", "planned": "Planned",
        "risk_accepted": "Risk accepted", "third_party": "Resolved through third party",
        "alternate": "Resolved through alternate mitigation", "completed": "Completed",
        "partial": "partially started", "regressed": "Regressed",
        "not_applicable": "Out of scope (not licensed)",
        "trend": "Score trend", "benchmark": "Benchmarks",
        "categories": "Status by category",
        "category": "Category", "achieved": "Achieved", "gap": "Points available",
        "done_count": "Completed actions",
        "priority": "Priority actions — highest point gain",
        "quickwins": "Quick wins — low user impact",
        "open_actions": "Open actions",
        "done_actions": "Completed actions",
        "excluded_actions": "Deliberately closed actions (risk accepted / third party / alternate mitigation)",
        "col_action": "Action", "col_category": "Category", "col_status": "Status",
        "col_points": "Points", "col_gain": "Gain", "col_impact": "User impact",
        "col_note": "Note / what was done", "col_link": "",
        "impact_low": "Low", "impact_moderate": "Moderate", "impact_high": "High",
        "no_items": "No actions in this group.",
        "search": "Search actions...",
        "summary": "Executive summary",
        "footer": ("Produced read-only from Microsoft Graph (/security/secureScores and "
                   "/security/secureScoreControlProfiles). No tenant configuration was changed."),
        "na_note": ("control is not applicable to this tenant (product not licensed) and is "
                    "excluded from the score maths."),
        "no_note": "—",
        "summary_tpl": ("The organisation's Secure Score is {score} / {maxscore} ({pct}%) — risk level {risk}. "
                        "Of the {total} improvement actions applicable to this tenant, {done} are complete "
                        "and {open} remain open. Completing the open actions would gain {gap} points."),
        "sum_lead": ("{cust} has a Microsoft Secure Score of {pct} "
                     "({score} / {maxscore}) — risk level {risk}."),
        "sum_body": ("Of the {total} improvement actions applicable to this tenant, {done} are "
                     "complete and {open} remain open, carrying {gap} points of "
                     "improvement potential."),
        "sum_cat": ("<b>Biggest opportunity is in {cat}:</b> {openn} open actions worth "
                    "{gap} points (currently {pct}% complete)."),
        "sum_top": ("<b>Top {n} priorities:</b> {items} — these three alone are worth {sub} points."),
        "sum_quick": ("<b>Quick wins:</b> {n} actions carry low user impact and deliver "
                      "{gain} points with limited operational disruption."),
        "sum_reg": ("<b>Needs urgent review:</b> {n} actions lost points they previously held — "
                    "a configuration, user or device change may have caused the regression."),
        "sum_closed": ("{n} actions were deliberately closed (risk accepted, third party or "
                       "alternate mitigation); Microsoft does not verify their implementation."),
        "sum_bench_up": ("The organisation is {diff} above the all-tenant average ({avg})."),
        "sum_bench_down": ("The organisation is {diff} below the all-tenant average ({avg})."),
        "fnd_exec": "Executive Summary",
        "fnd_exec_b": ("This report adapts the <b>{n} not-yet-implemented security "
                       "recommendations</b> from the Microsoft Secure Score output for the "
                       "{cust} Microsoft 365 environment into a corporate remediation report "
                       "format. Each item is structured as its own finding card, from "
                       "<b>Finding 1</b> to <b>Finding {n}</b>, preserving the finding name, "
                       "affected resource, category, description, impact, risk level and "
                       "remediation fields."),
        "fnd_purpose": "Purpose of this report",
        "fnd_purpose_b": ("To lift the Secure Score recommendations out of a technical checklist "
                          "and into a manageable, prioritised and actionable remediation "
                          "roadmap. Configuration steps come from Microsoft's own guidance; the "
                          "description, impact, environment dependency and verification steps "
                          "were written separately for enterprise use. Risk levels are not a "
                          "Microsoft classification - they come from this report's <b>impact "
                          "prioritisation model</b>, whose formula is stated in the Roadmap "
                          "section."),
        "fnd_posture": "Overall risk posture",
        "fnd_posture_b": ("Findings are classified by the impact prioritisation model. The "
                          "classifications are colour-coded and explained below."),
        "fnd_d_kritik": ("Controls that can lead to environment-wide compromise, identity or "
                         "data loss, or direct exploitation; high point value and high in "
                         "Microsoft's priority ranking."),
        "fnd_d_yuksek": ("Controls that are decisive in an attack chain but whose exploitation "
                         "needs a precondition, or whose impact is limited to one service."),
        "fnd_d_orta": ("Controls that raise security maturity and defence in depth, with a more "
                       "limited point contribution or priority rank."),
        "fnd_d_dusuk": ("Controls with low or narrowly scoped remediation value, suitable to "
                        "address once the others are complete."),
        "fnd_pdf": "Download as PDF",
        "fnd_pdf_hint": ("The print dialog opens; choose \u201cSave as PDF\u201d as the "
                         "destination. Only the findings report is printed. Turn off "
                         "\u201cHeaders and footers\u201d under More settings to drop the "
                         "browser's own header; keep \u201cBackground graphics\u201d on."),
        "fnd_total": "open findings in total",
        "fnd_pdf_fail": ("The browser could not open the print dialog. Press Ctrl+P and "
                         "choose \u201cSave as PDF\u201d as the destination."),
        "nav_findings": "Findings Report",
        "fnd_lead": ("One finding card per open action. Configuration steps, priority rank, "
                     "points and threat types come from Microsoft Graph; description, impact, "
                     "environment dependency and verification come from the content pack."),
        "fnd_n": "Finding",
        "fnd_resource": "Affected resource",
        "fnd_desc": "Description",
        "fnd_impact": "Impact",
        "fnd_risk": "Risk level",
        "fnd_fix": "Remediation",
        "fnd_config": "Configuration",
        "fnd_dep": "Environment dependency",
        "fnd_verify": "Verification",
        "fnd_more": "Further reading",
        "fnd_record": "Secure Score record",
        "fnd_link": "Open Microsoft documentation",
        "fnd_rank": "Microsoft priority rank",
        "fnd_gain": "worth {v} points once completed",
        "fnd_threats": "Threat types",
        "fnd_scope": "configuration in scope",
        "fnd_none": "No open actions - there are no findings to show.",
        "fnd_nopack": ("Detailed content for this action has not been prepared yet. "
                       "The configuration steps above are Microsoft's own guidance."),
        "fnd_count": "open findings",
        "cov_title": "Microsoft 365 Secure Score Assessment",
        "cov_prepared_for": "Prepared for",
        "cov_prepared_by": "Prepared by",
        "cov_date": "Report date",
        "cov_tenant": "Tenant",
        "cov_domain": "Primary domain",
        "cov_scope": "Scope",
        "cov_scope_v": "{n} applicable improvement actions",
        "cov_score": "Secure Score",
        "cov_risk": "Risk level",
        "cov_conf": "Confidential - internal use only",
        "cov_method": ("This assessment was produced read-only through Microsoft Graph. "
                       "No change was made to the tenant."),
        "cov_contents": "Contents",
        "cov_c1": "Overview - score, executive summary, category breakdown",
        "cov_c2": "All Improvement Actions - status of every in-scope item",
        "cov_c3": "30/60/90 Day Roadmap - plan by impact priority",
        "cov_c4": "Progress & Scope - why the score changed",
        "cov_c5": "Findings Report - a detailed card for every open action",
        "cov_open": "Open the report v",
        "exp_btn": "Export",
        "exp_title": "Export options",
        "exp_scope": "Scope",
        "exp_filtered": "Filtered actions only",
        "exp_all": "All actions",
        "exp_cols": "Content",
        "exp_assign": "Owner and due-date columns",
        "exp_steps": "Implementation steps",
        "exp_notes": "Status note",
        "exp_csv": "Download CSV",
        "exp_pdf": "PDF / Print",
        "exp_pdf_hint": "Choose \u201cSave as PDF\u201d as the destination in the print dialog.",
        "exp_empty": "Nothing to export. Try relaxing the filters.",
        "exp_fail": "The browser blocked the download. Make sure the report is opened from disk.",
        "exp_close": "Close",
        "col_max": "Maximum", "col_regressed": "Regressed",
        "yes": "Yes", "no": "No",
        "asg_title": "Owner and due date",
        "asg_owner": "Owner (person / team)",
        "asg_owner_ph": "e.g. Infrastructure team",
        "asg_due": "Target date",
        "asg_note": "Comment / status note",
        "asg_note_ph": "e.g. change request raised",
        "asg_saved": "These entries are stored in this browser only; the report file is "
                     "unchanged. Export to CSV to share them.",
        "asg_export": "Export assignments",
        "asg_clear": "Clear assignments",
        "asg_confirm": "All owner and due-date entries in this report will be deleted. Continue?",
        "asg_assigned": "assigned",
        "asg_overdue": "overdue",
        "asg_col_owner": "Owner", "asg_col_due": "Due",
        "nav_progress": "Progress & Scope",
        "prog_lead": ("A score alone says little. This section shows <b>what</b> changed and "
                      "<b>why</b>: points gained and lost, plus the controls that entered or "
                      "left the measured scope."),
        "prog_window": "Comparison period",
        "prog_raw": "Raw score", "prog_pct": "Completion rate",
        "prog_measured": "Measured controls", "prog_maxs": "Achievable points",
        "prog_improved": "Improved controls", "prog_regressed": "Regressed controls",
        "prog_added": "Entered scope", "prog_removed": "Left scope",
        "prog_finding": "Period finding",
        "prog_scope_up": ("<b>Scope widened.</b> {added} new controls entered scope and the "
                          "achievable score moved {frm} -> {to}. This is expected when a "
                          "product or licence is switched on; the percentage can dip even "
                          "while the raw score rises."),
        "prog_scope_down": ("<b>Scope narrowed.</b> {removed} controls left scope and the "
                            "achievable score moved {frm} -> {to}, usually because a licence "
                            "or product was switched off."),
        "prog_scope_same": ("<b>Scope unchanged.</b> The achievable score stayed at {to} "
                            "throughout, so score movement comes straight from configuration "
                            "changes."),
        "prog_net_up": "Net gain for the period: {v} points.",
        "prog_net_down": "Net loss for the period: {v} points.",
        "prog_net_flat": "No net score change over the period.",
        "prog_t_improved": "Improved controls",
        "prog_t_regressed": "Regressed controls",
        "prog_t_added": "Controls that entered scope",
        "prog_t_removed": "Controls that left scope",
        "prog_h_before": "Before", "prog_h_now": "Now", "prog_h_delta": "Change",
        "prog_none": "No changes in this category for the period.",
        "prog_nodata": ("Not enough history to compare. At least two measurements on different "
                        "days are needed; on a first run this section stays empty."),
        "prog_note": ("The comparison uses the tenant's own measurement snapshots. The dates "
                      "shown are the oldest and newest measurements returned by Microsoft Graph."),
        "projection": "Score projection",
        "proj_ky": "If critical + high actions are closed",
        "proj_qw": "If quick wins are applied",
        "proj_none": "No open actions - score is at its ceiling.",
        "sum_trend_up": ("<b>Last {days} days:</b> the score rose from {frm} to {to} "
                         "({diff})."),
        "sum_trend_down": ("<b>Last {days} days:</b> the score fell from {frm} to {to} "
                           "({diff}) - review recent changes."),
        "sum_trend_flat": ("<b>Last {days} days:</b> the score stayed flat at {to} - "
                           "no measurable improvement in this period."),
        "sum_service": ("<b>Concentration:</b> {n} of the open actions sit in {svc} "
                        "({gap} points) - focusing on one product gives the fastest result."),
        "sum_effort": ("<b>Implementation effort:</b> {n} open actions are low-cost "
                       "configuration changes worth {gain} points with no extra investment."),
        "basis_alltenants": "All tenants average",
        "basis_totalseats": "Similar-sized organisations",
        "basis_industrytypes": "Same industry",
        "threat_account_breach": "Account breach",
        "threat_data_exfiltration": "Data exfiltration",
        "threat_data_spillage": "Data spillage",
        "threat_data_deletion": "Data deletion",
        "threat_elevation_of_privilege": "Elevation of privilege",
        "threat_malicious_insider": "Malicious insider",
        "threat_password_cracking": "Password cracking",
        "threat_phishing_or_whaling": "Phishing or whaling",
        "threat_spoofing": "Spoofing",
        # --- v7 report strings -------------------------------------------
        "mark": "E.E",
        "nav_overview": "Overview", "nav_roadmap": "30/60/90 Day Roadmap",
        "applicable": "Applicable", "open_short": "Open",
        "applied_control": "controls in place", "urgent": "needs urgent action",
        "point_loss": "points lost", "gainable": "Available",
        "point_potential": "points of potential",
        "go_overview": "Overview", "go_all": "See all", "go_list": "Open list",
        "go_roadmap": "Roadmap",
        "cat_dist": "CATEGORY BREAKDOWN",
        "sev_label": "Impact severity", "sev_short": "Impact",
        "sev_kritik": "Critical", "sev_yuksek": "High", "sev_orta": "Medium", "sev_dusuk": "Low",
        "sev_open_title": "Open actions by impact severity",
        "sev_open_hint": "click a card to open the matching list",
        "top5": "Top 5 critical actions", "by_severity": "by impact severity",
        "ms_rank": "Microsoft rank",
        "sort_sev": "By impact severity",
        "and_more": "and {n} more",
        "reg_banner": ("actions shown — items that previously earned points and then "
                       "lost them."),
        "reg_clear": "Clear filter",
        "legend_title": "What do the labels mean?",
        "legend_open": "The action has not been applied; no points are earned.",
        "legend_partial": ("Applied to some users or devices. Microsoft awards partial credit "
                           "in proportion to coverage; full coverage earns the full points."),
        "legend_done": "Fully applied; the maximum points are earned.",
        "legend_reg": "Items that previously earned points and then lost them.",
        "legend_reg_n": "<b>{n} actions</b> are in this state in this tenant.",
        "purpose": "Purpose",
        "road_h": ("Turn security gaps into a 90-day plan, ordered by how much they affect "
                   "the environment"),
        "road_p": ("Secure Score reports usually produce a long list of gaps and leave "
                   "\"which one first?\" unanswered. This roadmap splits the {n} open actions "
                   "into three phases by <b>how much they affect the environment</b>, so the "
                   "team works to a clear monthly scope and management can see each phase's "
                   "contribution up front."),
        "road_1h": "Impact first, ease second",
        "road_1p": ("Ordering follows points, Microsoft's own rank, the threats prevented and "
                    "whether the action regressed — not alphabetical or arbitrary."),
        "road_2h": "Scope split into phases",
        "road_2p": ("Phase 1 critical gaps (0–30 days), Phase 2 high-impact items (31–60), "
                    "Phase 3 maturity work (61–90). Each phase has a known item count and gain."),
        "road_3h": "Measurable target",
        "road_3p": ("The Secure Score percentage expected at the end of each phase is "
                    "calculated, so the next assessment can compare actual against target."),
        "road_4h": "Operational reality",
        "road_4p": ("User impact and implementation cost are shown per item, so disruption "
                    "risk and effort are known before planning."),
        "road_note": ("Closing every open action would reach {target} ({gap} points of "
                      "improvement potential). Real targets and timing should be agreed with "
                      "the customer's team."),
        "expected": "Expected score progression", "as_phases": "as phases complete",
        "today": "Today", "d30": "30 days", "d60": "60 days", "d90": "90 days",
        "phase1": "Phase 1", "phase1_when": "0–30 days",
        "phase1_desc": "Critical impact — the gaps that affect the environment most",
        "phase2": "Phase 2", "phase2_when": "31–60 days",
        "phase2_desc": "High impact — items to close with planned changes",
        "phase3": "Phase 3", "phase3_when": "61–90 days",
        "phase3_desc": "Medium and low impact — continuity and maturity work",
        "sev_how": "How is impact severity calculated?",
        "sev_how_p": ("Microsoft does not publish a severity for Secure Score actions. The "
                      "impact severity in this report is derived from the fields Microsoft "
                      "does publish:"),
        "sev_f1": "Points weight",
        "sev_f1d": "the action's maximum score; the most objective measure of its effect",
        "sev_f2": "Microsoft rank", "sev_f2d": "Microsoft's own ordering of the action",
        "sev_f3": "Threats prevented",
        "sev_f3d": "account breach and elevation of privilege carry the most weight",
        "sev_f4": "Regression",
        "sev_f4d": "losing points already earned raises the weight sharply",
        "sev_f5": "Control tier", "sev_f5d": "controls Microsoft marks as \"Core\"",
        "sev_how_note": ("The computed value appears in each action's detail. This is not a "
                         "Microsoft classification; it is this report's prioritisation model."),
        "sum_critical": ("<b>Needs urgent action:</b> {n} actions are critical severity — these "
                         "affect the environment most and should be closed in the first 30 days."),
        "gap_short": "available",
        "customer": "Customer", "prepared_for": "This assessment was prepared for",
        "prepared_by": "Prepared by", "col_product": "Product", "col_cost": "Implementation cost",
        "col_effect": "Effect on users", "threats": "Threats mitigated",
        "quickwins_short": "Quick wins", "closed_short": "Closed",
        "action_unit": "actions", "at_glance": "At a glance", "implementation": "Implementation",
        "details": "Details", "open_portal": "Open in portal",
        "no_remediation": "Microsoft provides no step detail for this action.",
        "all_actions": "All improvement actions",
        "status_dist": "Action status distribution",
        "classification": "CONFIDENTIAL — share only with authorised personnel",
        "users": "Licensed users",
        "sort": "Sort", "sort_gain": "By points available",
        "sort_points": "By total points", "sort_title": "By name",
        "expand_all": "Expand all", "collapse_all": "Collapse all",
        "reset": "Reset", "shown": "actions shown",
        "na_line": "{n} controls are not applicable to this tenant (product not licensed) and are excluded from the score maths.",
        "method": "Methodology and limits",
        "m1": "Score, maximum and percentage are taken directly from the tenant's own Microsoft Secure Score measurement; they are not recalculated.",
        "m2": "Each improvement action is worth up to 10 points. Most are scored all-or-nothing; some give partial credit in proportion to configuration coverage (e.g. half the users covered gives half the points).",
        "m3": "After making a change it can take 24-48 hours for the score to reflect it.",
        "m4": "Actions outside the licence scope are excluded from the denominator; Microsoft does not verify implementation for actions marked risk accepted, third party or alternate mitigation.",
        "m5": "Secure Score is a numerical summary of security posture; it is not an absolute measure of breach likelihood.",
        "m6": ("Permissions used (all read-only): SecurityEvents.Read.All — Secure Score and control "
               "data; Organization.Read.All — organisation and domain name. No write, modify or "
               "delete permission was requested."),
        "regressed_note": "{n} action(s) regressed since the previous measurement — review these first.",
    },
}

# Canonical status keys
S_COMPLETED, S_TOADDRESS = "completed", "to_address"
S_PLANNED, S_RISK, S_THIRD, S_ALT = "planned", "risk_accepted", "third_party", "alternate"
OPEN_STATES = (S_TOADDRESS, S_PLANNED)
CLOSED_STATES = (S_RISK, S_THIRD, S_ALT)

STATUS_COLOURS = {
    S_COMPLETED: ("#0f7b3f", "#e7f5ec"),
    S_TOADDRESS: ("#b42318", "#fdeceb"),
    S_PLANNED:   ("#0b5fff", "#e8f0ff"),
    S_RISK:      ("#5b6572", "#eef1f5"),
    S_THIRD:     ("#5b6572", "#eef1f5"),
    S_ALT:       ("#5b6572", "#eef1f5"),
}


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def _request(url: str, *, method: str = "GET", headers: Optional[Dict[str, str]] = None,
             data: Optional[bytes] = None, retries: int = 4) -> Dict[str, Any]:
    headers = dict(headers or {})
    headers.setdefault("User-Agent", USER_AGENT)
    headers.setdefault("Accept", "application/json")
    ctx = ssl.create_default_context()
    last_err = None
    for attempt in range(retries):
        req = urllib.request.Request(url, method=method, headers=headers, data=data)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                wait = int(exc.headers.get("Retry-After", 2 ** attempt))
                time.sleep(max(1, min(wait, 60)))
                last_err = RuntimeError(f"HTTP {exc.code}")
                continue
            raise RuntimeError(f"HTTP {exc.code} calling {url}\n{body[:1000]}") from None
        except urllib.error.URLError as exc:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                last_err = RuntimeError(str(exc))
                continue
            raise RuntimeError(f"Network error calling {url}: {exc}") from None
    raise last_err or RuntimeError("request failed")


def get_token_client_secret(tenant_id: str, client_id: str, client_secret: str) -> str:
    payload = urllib.parse.urlencode({
        "client_id": client_id, "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials",
    }).encode()
    res = _request(f"{LOGIN}/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token",
                   method="POST", data=payload,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    token = res.get("access_token")
    if not token:
        raise RuntimeError("Token alınamadı / token not returned")
    return token


def graph_get_all(path: str, token: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    url = f"{GRAPH}{path}" + (("?" + urllib.parse.urlencode(params)) if params else "")
    items: List[Dict[str, Any]] = []
    headers = {"Authorization": f"Bearer {token}",
               "Accept-Language": os.getenv("SECURESCORE_LANG", "tr-TR,tr;q=0.9,en;q=0.8")}
    while url:
        page = _request(url, headers=headers)
        value = page.get("value")
        if value is None:
            return [page]
        items.extend(value)
        url = page.get("@odata.nextLink")
    return items


def resolve_customer_name(tenant: Dict[str, Any], override: Optional[str] = None) -> str:
    """Decide the customer name shown on the report.

    Priority: explicit --customer value, then the tenant's own organisation
    display name, then the verified default domain (without the suffix), then
    the tenant id. Never invents a name.
    """
    if override and override.strip():
        return override.strip()
    name = str(tenant.get("displayName") or "").strip()
    if name:
        return name
    domain = tenant_domain(tenant)
    if domain:
        base = domain.split(".")[0]
        return base.replace("-", " ").title() if base else domain
    return str(tenant.get("id") or "").strip() or "—"


# --------------------------------------------------------------------------- #
# Microsoft product naming
#
# Graph returns internal service codes ("MDATP", "AzureAD", "Azure ATP") that
# predate several Microsoft rebrands. The report shows the current official
# name so the output matches what an administrator sees in the portal and in
# Microsoft documentation today. The raw code is preserved as serviceCode.
#
# Sources: Azure Active Directory -> Microsoft Entra ID (July 2023);
# Azure ATP -> Microsoft Defender for Identity; Microsoft Defender ATP ->
# Microsoft Defender for Endpoint; Microsoft Cloud App Security -> Microsoft
# Defender for Cloud Apps; Microsoft Information Protection -> Microsoft
# Purview Information Protection (April 2022).
# --------------------------------------------------------------------------- #
PRODUCT_NAMES: Dict[str, str] = {
    "mdatp": "Microsoft Defender for Endpoint",
    "azure atp": "Microsoft Defender for Identity",
    "azureatp": "Microsoft Defender for Identity",
    "atp": "Microsoft Defender for Office 365",
    "mdo": "Microsoft Defender for Office 365",
    "mcas": "Microsoft Defender for Cloud Apps",
    "mda": "Microsoft Defender for Cloud Apps",
    "appg": "Defender for Cloud Apps - App Governance",
    "azuread": "Microsoft Entra ID",
    "aad": "Microsoft Entra ID",
    "exo": "Exchange Online",
    "spo": "SharePoint Online",
    "onedrive": "OneDrive",
    "odb": "OneDrive",
    "mip": "Microsoft Purview Information Protection",
    "ms teams": "Microsoft Teams",
    "teams": "Microsoft Teams",
    "admincenter": "Microsoft 365 admin center",
    "forms": "Microsoft Forms",
    "sway": "Microsoft Sway",
    "powerbi": "Microsoft Power BI",
    "intune": "Microsoft Intune",
    "defender": "Microsoft Defender",
}

# Defender for Cloud Apps connectors arrive as MDA_<vendor>.
MDA_CONNECTORS: Dict[str, str] = {
    "sf": "Salesforce", "snow": "ServiceNow", "zendesk": "Zendesk",
    "citrixsf": "Citrix ShareFile", "github": "GitHub", "atlassian": "Atlassian",
    "zoom": "Zoom", "okta": "Okta", "docusign": "DocuSign", "dropbox": "Dropbox",
    "google": "Google Workspace", "netdocuments": "NetDocuments",
    "workplace": "Workplace from Meta", "box": "Box", "aws": "Amazon Web Services",
    "gcp": "Google Cloud Platform", "webex": "Webex", "slack": "Slack",
}


def product_name(code: Any) -> str:
    """Current official Microsoft product name for a Graph service code.

    Unknown codes are returned unchanged - inventing a name would be worse
    than showing the code Microsoft actually sent.
    """
    raw = str(code or "").strip()
    if not raw:
        return ""
    key = raw.lower()
    if key.startswith("mda_"):
        vendor = MDA_CONNECTORS.get(key[4:], raw[4:])
        return f"Microsoft Defender for Cloud Apps ({vendor})"
    return PRODUCT_NAMES.get(key, raw)


# Legacy brand names that may appear in free text we render ourselves.
LEGACY_TERMS: List[Tuple[str, str]] = [
    (r"\bAzure Active Directory\b", "Microsoft Entra ID"),
    (r"\bAzure AD Identity Protection\b", "Microsoft Entra ID Protection"),
    (r"\bAzure AD\b", "Microsoft Entra ID"),
    (r"\bAzure Advanced Threat Protection\b", "Microsoft Defender for Identity"),
    (r"\bAzure ATP\b", "Microsoft Defender for Identity"),
    (r"\bMicrosoft Defender ATP\b", "Microsoft Defender for Endpoint"),
    (r"\bOffice 365 ATP\b", "Microsoft Defender for Office 365"),
    (r"\bMicrosoft Cloud App Security\b", "Microsoft Defender for Cloud Apps"),
    (r"\bAzure Sentinel\b", "Microsoft Sentinel"),
    (r"\bAzure Information Protection\b", "Microsoft Purview Information Protection"),
    (r"\bMicrosoft Information Protection\b", "Microsoft Purview Information Protection"),
    (r"\bAzure Security Center\b", "Microsoft Defender for Cloud"),
]
_LEGACY_RX = [(re.compile(pat, re.I), rep) for pat, rep in LEGACY_TERMS]


def modernise_terms(text: Any) -> str:
    """Replace retired Microsoft brand names with their current equivalents."""
    out = str(text or "")
    for rx, rep in _LEGACY_RX:
        out = rx.sub(rep, out)
    return out


# --------------------------------------------------------------------------- #
# Corporate branding
#
# A partner delivering this assessment to their own customers needs the report
# to carry their identity. Branding is confined to the header, cover block and
# footer: the severity palette stays untouched so the audited risk colours can
# never be overridden by a brand colour.
# --------------------------------------------------------------------------- #
LOGO_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
              ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp"}
MAX_LOGO_BYTES = 2 * 1024 * 1024


def load_logo(path: Optional[str]) -> str:
    """Read a logo file and return a data URI, or '' if unusable.

    Embedded as a data URI so the report stays a single offline file. Size is
    capped and the extension must be a known image type - the report must never
    embed an arbitrary blob handed to it on the command line.
    """
    if not path:
        return ""
    try:
        ext = os.path.splitext(path)[1].lower()
        mime = LOGO_TYPES.get(ext)
        if not mime:
            sys.stderr.write(f"  ! Logo atlandi: desteklenmeyen tur '{ext}'\n")
            return ""
        size = os.path.getsize(path)
        if size > MAX_LOGO_BYTES:
            sys.stderr.write(f"  ! Logo atlandi: dosya {size // 1024} KB, "
                             f"sinir {MAX_LOGO_BYTES // 1024} KB\n")
            return ""
        with open(path, "rb") as fh:
            raw = fh.read()
        return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"
    except Exception as exc:
        sys.stderr.write(f"  ! Logo okunamadi: {exc}\n")
        return ""


_HEX_RX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


def safe_colour(value: Optional[str], fallback: str) -> str:
    """Accept only a literal hex colour. Anything else would be injected
    straight into a style attribute, so it is rejected outright."""
    v = str(value or "").strip()
    if _HEX_RX.match(v):
        return v
    if v:
        sys.stderr.write(f"  ! Marka rengi yok sayildi (gecersiz): {v}\n")
    return fallback


def tenant_domain(tenant: Dict[str, Any]) -> str:
    """Primary domain for the header.

    Prefers the resolved default domain; falls back to the first verified
    domain so a tenant with no isDefault flag still shows something real.
    Never invents a value.
    """
    d = str(tenant.get("domain") or "").strip()
    if d:
        return d
    for v in (tenant.get("verifiedDomains") or []):
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            n = str(v.get("name") or "").strip()
            if n:
                return n
    return ""


def fetch_tenant_info(token: str) -> Dict[str, Any]:
    try:
        org = graph_get_all("/organization", token)
        if org:
            o = org[0]
            default_domain = next((d.get("name") for d in (o.get("verifiedDomains") or [])
                                   if d.get("isDefault")), None)
            return {"id": o.get("id"), "displayName": o.get("displayName"),
                    "domain": default_domain,
                    "verifiedDomains": [d.get("name") for d in (o.get("verifiedDomains") or [])
                                        if d.get("name")],
                    "country": o.get("countryLetterCode")}
    except Exception:
        pass
    return {}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _strip_html(text: str) -> str:
    out, depth = [], 0
    for ch in str(text or ""):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return html.unescape(" ".join("".join(out).split()))


def _normalise_dates(obj: Any) -> Any:
    """Convert Windows PowerShell's "/Date(1789...)/" serialisation to ISO 8601.

    ConvertTo-Json in Windows PowerShell 5.1 writes DateTime values in the legacy
    Microsoft JSON date format. Graph itself always returns ISO strings, so this
    only ever fires for locally-produced files - and leaves everything else alone.
    """
    if isinstance(obj, dict):
        return {k: _normalise_dates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalise_dates(v) for v in obj]
    if isinstance(obj, str):
        m = _DATE_RE.match(obj.strip())
        if m:
            millis = int(m.group(1))
            offset = m.group(2)
            try:
                stamp = dt.datetime(1970, 1, 1) + dt.timedelta(milliseconds=millis)
            except (OverflowError, OSError, ValueError):
                return obj
            text = stamp.strftime("%Y-%m-%dT%H:%M:%S")
            if offset and offset not in ("+0000", "-0000"):
                return f"{text}{offset[:3]}:{offset[3:]}"
            return text + "Z"
    return obj


_DATE_RE = __import__("re").compile(r"^/Date\((-?\d+)([+-]\d{4})?\)/$")


def _short_date(value: Any) -> str:
    text = str(_normalise_dates(value) or "")
    if _DATE_RE.match(text):          # unparseable legacy value - show nothing
        return ""
    return text[:10] if len(text) >= 10 else text


# Band thresholds only. Colours live in SEV_SOLID / SEV_TEXT so there is exactly
# one place where the palette is defined.
RISK_BANDS = [(80, "dusuk"), (60, "orta"), (40, "yuksek"), (0, "kritik")]
# Risk verdict labels. Keys match the severity keys used across the report so a
# single vocabulary covers both the tenant verdict and the per-action severity.
RISK_LABEL = {"dusuk": {"tr": "Düşük", "en": "Low"},
              "orta": {"tr": "Orta", "en": "Moderate"},
              "yuksek": {"tr": "Yüksek", "en": "Elevated"},
              "kritik": {"tr": "Kritik", "en": "High"},
              # legacy keys kept so older callers keep working
              "low": {"tr": "Düşük", "en": "Low"},
              "moderate": {"tr": "Orta", "en": "Moderate"},
              "elevated": {"tr": "Yüksek", "en": "Elevated"},
              "high": {"tr": "Kritik", "en": "High"}}


def _relative_luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    channels = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    adjusted = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
                for c in channels]
    return 0.2126 * adjusted[0] + 0.7152 * adjusted[1] + 0.0722 * adjusted[2]


def _contrast(a: str, b: str) -> float:
    """WCAG contrast ratio between two hex colours."""
    l1, l2 = sorted((_relative_luminance(a), _relative_luminance(b)), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)


def risk_band(pct: float) -> Tuple[str, str]:
    """Band key for a percentage. Colour comes from the palette, never from here."""
    for threshold, key in RISK_BANDS:
        if pct >= threshold:
            return key, SEV_TEXT[key] if "SEV_TEXT" in globals() else ""
    return "kritik", ""


def _latest_state_update(profile: Dict[str, Any]) -> Dict[str, Any]:
    updates = profile.get("controlStateUpdates") or []
    if not isinstance(updates, list) or not updates:
        return {}
    def key(u: Dict[str, Any]) -> str:
        return str(u.get("updatedDateTime") or "")
    return sorted(updates, key=key, reverse=True)[0]


STATE_MAP = {
    "ignored": S_RISK,
    "riskaccepted": S_RISK,
    "thirdparty": S_THIRD,
    "resolvedthroughthirdparty": S_THIRD,
    "reviewed": S_ALT,
    "resolvedthroughalternatemitigation": S_ALT,
    "alternatemitigation": S_ALT,
    "planned": S_PLANNED,
}


def classify(entry: Dict[str, Any], profile: Dict[str, Any],
             score: float, max_score: float) -> Tuple[str, Dict[str, Any]]:
    """Return (status_key, state_update) using the portal's own semantics."""
    update = _latest_state_update(profile)
    raw_state = (update.get("state") or entry.get("controlState")
                 or entry.get("state") or "").replace(" ", "").lower()
    mapped = STATE_MAP.get(raw_state)
    if mapped:
        return mapped, update
    if max_score > 0 and score >= max_score - 1e-9:
        return S_COMPLETED, update
    # The portal keeps a partially-scored action in "To address" until it is
    # fully complete; the partial progress is shown in the points column.
    return S_TOADDRESS, update


# --------------------------------------------------------------------------- #
# Turkish content pack
#
# Microsoft Graph returns improvement-action titles, remediation steps and user
# impact text in English only. When a Turkish report is requested we overlay a
# bundled translation pack, matched by control id. Anything without a
# translation keeps its original English text, so no content is ever lost.
# --------------------------------------------------------------------------- #
TR_PACK_FILES = ("secure_score_tr.json", "tr/secure_score_tr.json")
_TR_PACK_CACHE: Optional[Dict[str, Dict[str, str]]] = None


def load_translation_pack(explicit: Optional[str] = None) -> Dict[str, Dict[str, str]]:
    """Load the Turkish content pack from disk (next to this script)."""
    global _TR_PACK_CACHE
    if _TR_PACK_CACHE is not None and not explicit:
        return _TR_PACK_CACHE
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [explicit] if explicit else [os.path.join(here, f) for f in TR_PACK_FILES]
    pack: Dict[str, Dict[str, str]] = {}
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8-sig") as fh:
                raw = json.load(fh)
        except Exception:
            continue
        entries = raw.get("controls", raw) if isinstance(raw, dict) else raw
        if isinstance(entries, dict):
            for key, value in entries.items():
                if isinstance(value, dict):
                    pack[str(key).lower()] = value
        elif isinstance(entries, list):
            for value in entries:
                if isinstance(value, dict) and value.get("id"):
                    pack[str(value["id"]).lower()] = value
        break
    if not explicit:
        _TR_PACK_CACHE = pack
    return pack


def apply_translations(controls: List[Dict[str, Any]],
                       pack: Dict[str, Dict[str, str]]) -> int:
    """Overlay translated title / remediation / impact text. Returns hit count."""
    hits = 0
    for c in controls:
        entry = pack.get(str(c.get("id", "")).lower())
        if not entry:
            continue
        used = False
        # The action's main name deliberately stays in English so it matches the
        # Microsoft 365 Defender portal; the Turkish wording is offered alongside.
        tr_title = entry.get("title")
        if isinstance(tr_title, str) and tr_title.strip():
            c["titleTr"] = modernise_terms(tr_title.strip())
            used = True
        for field in ("remediation", "remediationImpact"):
            text = entry.get(field)
            if isinstance(text, str) and text.strip():
                c[field] = modernise_terms(text.strip())
                used = True
        # Findings-report fields. Optional: a control without them still renders
        # a card from Graph data alone, it is just shorter.
        for field in ("aciklama", "etkisi", "bagimlilik", "dogrulama"):
            text = entry.get(field)
            if isinstance(text, str) and text.strip():
                c[field] = modernise_terms(text.strip())
                used = True
        if used:
            hits += 1
    return hits


# --------------------------------------------------------------------------- #
# Tenant status-text localisation
#
# controlScores[].implementationStatus carries Microsoft's live, per-tenant
# wording ("You have 1 out of 1 users ... that aren't registered with MFA").
# These strings are formulaic, so they are localised with ordered regex rules.
# Anything that matches no rule keeps its English wording rather than being
# mistranslated.
# --------------------------------------------------------------------------- #
import re as _re

_APO = "['\u2019\u2018\u00b4]"

STATUS_RULES_TR: List[Tuple[Any, str]] = [
    (r"^(\d+)\s*/\s*(\d+)\s+exposed devices?$", r"\1/\2 cihaz risk altında"),
    (r"^(\d+(?:\.\d+)?)%\s+of users are affected by policies that are configured securely\s*(.*)$",
     r"Kullanıcıların %\1'i güvenli yapılandırılmış ilkelerden etkileniyor \2"),
    (r"^(\d+(?:\.\d+)?)%\s+of users are affected by policies that are configured less securely than is recommended\s*(.*)$",
     r"Kullanıcıların %\1'i önerilenden daha az güvenli yapılandırılmış ilkelerden etkileniyor \2"),
    (r"^Policies were published on (\d+) of the (\d+) users$",
     r"İlkeler \2 kullanıcıdan \1 tanesine uygulanmış"),
    (r"^You have (\d+) (?:out )?of (\d+) users with administrative roles that (?:aren|are not|arent)"
     + _APO + r"?t? ?registered and protected with MFA\.?$",
     r"Yönetici rolüne sahip \2 kullanıcıdan \1 tanesi MFA ile kayıtlı ve korumalı değil."),
    (r"^You have (\d+) (?:out )?of (\d+) users that (?:aren|are not|arent)" + _APO + r"?t? ?registered with MFA\.?$",
     r"\2 kullanıcıdan \1 tanesi MFA ile kayıtlı değil."),
    (r"^You have (\d+) (?:out )?of (\d+) users who don" + _APO + r"?t have self-service password reset enabled\.?$",
     r"\2 kullanıcıdan \1 tanesinde self servis parola sıfırlama etkin değil."),
    (r"^You have (\d+) (?:out )?of (\d+) users that don" + _APO + r"?t have legacy authentication blocked\.?$",
     r"\2 kullanıcıdan \1 tanesinde legacy authentication engellenmemiş."),
    (r"^You have (\d+) (?:out )?of (\d+) users that don" + _APO + r"?t have the sign-?in risky policy turned on\.?$",
     r"\2 kullanıcıdan \1 tanesinde oturum açma riski ilkesi açık değil."),
    (r"^You have (\d+) users? out of (\d+) that do not have user risk policy enabled\.?$",
     r"\2 kullanıcıdan \1 tanesinde kullanıcı riski ilkesi etkin değil."),
    (r"^You currently have (\d+) global admins?\.?$", r"Şu anda \1 global admin hesabınız var."),
    (r"^You have (\d+) users? with least privileged administrative roles\.?$",
     r"En az ayrıcalıklı yönetici rolüne sahip \1 kullanıcınız var."),
    (r"^You have no user consent policy in place\.?$", r"Tanımlı bir kullanıcı onay ilkeniz yok."),
    (r"^You have disabled password hash sync\.?$", r"Password hash sync devre dışı bırakılmış."),
    (r"^Your current policy is set to never let passwords expire\.?$",
     r"Mevcut ilkeniz parolaların hiç süresi dolmayacak şekilde ayarlanmış."),
    (r"^current status:\s*On$", r"mevcut durum: Açık"),
    (r"^current status:\s*Off$", r"mevcut durum: Kapalı"),
    (r"^The setting is not compliant\.?$", r"Ayar uyumlu değil."),
    (r"^The setting was not enabled\.?$", r"Ayar etkinleştirilmemiş."),
    (r"^Feature in place:\s*true\.?$", r"Özellik devrede: evet."),
    (r"^Feature in place:\s*false\.?$", r"Özellik devrede: hayır."),
    (r"^The allowed IP addresses list in the connection filter policy is empty\.?$",
     r"Connection filter policy içindeki izinli IP adresi listesi boş."),
    (r"^Modern authentication for Exchange Online is enabled\.?$",
     r"Exchange Online için modern authentication etkin."),
    (r"^Modern authentication for Exchange Online is disabled\.?$",
     r"Exchange Online için modern authentication devre dışı."),
    (r"^MailTips for end users are disabled\.?$", r"Son kullanıcılar için MailTips devre dışı."),
    (r"^MailTips for end users are enabled\.?$", r"Son kullanıcılar için MailTips etkin."),
    (r"^Spam confidence level \(SCL\) is not configured in mail transport rules with specific domain\.?$",
     r"Belirli etki alanı için mail transport kurallarında spam confidence level (SCL) yapılandırılmamış."),
    (r"^Microsoft (\d+) audit log search is enabled\.?$", r"Microsoft \1 denetim günlüğü araması etkin."),
    (r"^Microsoft (\d+) audit log search is disabled\.?$", r"Microsoft \1 denetim günlüğü araması devre dışı."),
    (r"^Mailbox auditing for all users is disabled\.?$",
     r"Tüm kullanıcılar için posta kutusu denetimi devre dışı."),
    (r"^Mailbox auditing for all users is enabled\.?$",
     r"Tüm kullanıcılar için posta kutusu denetimi etkin."),
    (r"^Installing Outlook add-ins configuration is disabled\.?$",
     r"Outlook eklentisi yükleme yapılandırması devre dışı."),
    (r"^Installing Outlook add-ins configuration is enabled\.?$",
     r"Outlook eklentisi yükleme yapılandırması etkin."),
    (r"^Internal phishing protection for Forms is:\s*enabled\.?$",
     r"Forms için dahili kimlik avı koruması: etkin."),
    (r"^Internal phishing protection for Forms is:\s*disabled\.?$",
     r"Forms için dahili kimlik avı koruması: devre dışı."),
    (r"^Blocking OneDrive for Business sync from unmanaged devices is:\s*enabled\.?$",
     r"Yönetilmeyen cihazlardan OneDrive for Business eşitlemesinin engellenmesi: etkin."),
    (r"^Blocking OneDrive for Business sync from unmanaged devices is:\s*disabled\.?$",
     r"Yönetilmeyen cihazlardan OneDrive for Business eşitlemesinin engellenmesi: devre dışı."),
    (r"^Document sharing is being controlled by domains setting is (enabled|disabled)\.?$",
     r"Belge paylaşımının etki alanlarına göre denetlenmesi ayarı: \1"),
    (r"^Prevent external users from sharing files, folders, and sites that they don"
     + _APO + r"?t own is:\s*(enabled|disabled)\.?$",
     r"Dış kullanıcıların sahibi olmadıkları dosya, klasör ve siteleri paylaşmasının engellenmesi: \1"),
    (r"^DLP policies in Teams are:\s*true\.?$", r"Teams içinde DLP ilkeleri: var."),
    (r"^DLP policies in Teams are:\s*false\.?$", r"Teams içinde DLP ilkeleri: yok."),
    (r"^Third party applications integration is:\s*true\.?$", r"Üçüncü parti uygulama entegrasyonu: açık."),
    (r"^Third party applications integration is:\s*false\.?$", r"Üçüncü parti uygulama entegrasyonu: kapalı."),
    (r"^Additional storage providers are restricted in Outlook on the web is not configured correctly\.?\s*(.*)$",
     r"Outlook on the web içinde ek depolama sağlayıcılarının kısıtlanması doğru yapılandırılmamış. \1"),
    (r"^Phishing-resistant MFA strength is mFA strength is (enabled|disabled)(.*)$",
     r"Kimlik avına dayanıklı MFA gücü: \1\2"),
    (r"^Setting is:\s*sign in frequency is not yet enabled in the following accounts:\s*(.*)$",
     r"Ayar: şu hesaplarda oturum açma sıklığı henüz etkinleştirilmemiş: \1"),
    (r"^" + r"'User owned apps and services' is \[Not Measured\]\.?$",
     r"'User owned apps and services' ayarı ölçülmedi."),
    (r"^Admin consent workflow is:\s*true\.?$", r"Admin consent workflow: etkin."),
    (r"^Admin consent workflow is:\s*false\.?$", r"Admin consent workflow: devre dışı."),
    (r"^Administrator accounts are separate, unassigned and cloud-only account:\s*true\.?$",
     r"Yönetici hesapları ayrı, lisanssız ve yalnızca bulut hesabı: evet."),
    (r"^Administrator accounts are separate, unassigned and cloud-only account:\s*false\.?$",
     r"Yönetici hesapları ayrı, lisanssız ve yalnızca bulut hesabı değil."),
    (r"^Custom banned passwords lists are:\s*enabled\.?$", r"Özel yasaklı parola listeleri: etkin."),
    (r"^Custom banned passwords lists are:\s*disabled\.?$",
     r"Özel yasaklı parola listeleri: devre dışı."),
    (r"^Defender for Cloud Apps is:\s*true\.?$", r"Defender for Cloud Apps: etkin."),
    (r"^Defender for Cloud Apps is:\s*false\.?$", r"Defender for Cloud Apps: devre dışı."),
    (r"^LinkedIn account connections is\s*-?\s*Not disabled\.?$",
     r"LinkedIn hesap bağlantıları devre dışı bırakılmamış."),
    (r"^LinkedIn account connections is\s*-?\s*Disabled\.?$",
     r"LinkedIn hesap bağlantıları devre dışı bırakılmış."),
    (r"^Microsoft Entra ID Password Protection is not configured\.?$",
     r"Microsoft Entra ID Password Protection yapılandırılmamış."),
    (r"^Microsoft Entra ID Password Protection is configured\.?$",
     r"Microsoft Entra ID Password Protection yapılandırılmış."),
    (r"^SPF is:\s*true\.?$", r"SPF kaydı: var."),
    (r"^SPF is:\s*false\.?$", r"SPF kaydı: yok."),
    (r"^Sharing SWAY outside the organization is enabled\.?$",
     r"Sway içeriğinin kurum dışıyla paylaşımı etkin."),
    (r"^Sharing SWAY outside the organization is disabled\.?$",
     r"Sway içeriğinin kurum dışıyla paylaşımı devre dışı."),
    (r"^'?Microsoft Azure Management'? is limited to administrative roles\s*-?\s*(.*)$",
     r"'Microsoft Azure Management' yalnızca yönetici rolleriyle sınırlı \1"),
    # generic tails
    (r"\bno Conditional policies exists\b", r"Conditional Access ilkesi bulunmuyor"),
    (r"\bis:\s*enabled\b", r"durumu: etkin"),
    (r"\bis:\s*disabled\b", r"durumu: devre dışı"),
    (r"\bis:\s*true\b", r"durumu: evet"),
    (r"\bis:\s*false\b", r"durumu: hayır"),
]
_STATUS_RULES_C = [(_re.compile(p, _re.I), r) for p, r in STATUS_RULES_TR]


def localise_status(text: str, lang: str = "tr") -> str:
    """Translate Microsoft's live per-tenant status wording into Turkish."""
    raw = (text or "").strip()
    if not raw or lang != "tr":
        return raw
    for pattern, repl in _STATUS_RULES_C:
        new, n = pattern.subn(repl, raw)
        if n:
            return _re.sub(r"\s+", " ", new).strip(" -")
    return raw


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Impact severity
#
# Microsoft does not publish a severity for Secure Score actions, so it is
# derived here from the fields Microsoft DOES publish. The formula is shown to
# the reader in the report, and the computed value appears on every action.
#
#   points weight   the action's maximum score - the most objective measure of
#                   how much it moves the tenant's posture
#   Microsoft rank  Microsoft's own ordering of the action
#   threats         what the action prevents; account breach and elevation of
#                   privilege carry the most weight
#   regression      losing points already earned is a step backwards
#   tier            Microsoft's "Core" controls are foundational
# --------------------------------------------------------------------------- #
THREAT_WEIGHT = {
    "account breach": 3, "elevation of privilege": 3, "phishing or whaling": 3,
    "data exfiltration": 2, "data spillage": 2, "data deletion": 2,
    "password cracking": 2, "malicious insider": 2, "spoofing": 2,
}
SEV_KRITIK, SEV_YUKSEK, SEV_ORTA, SEV_DUSUK = "kritik", "yuksek", "orta", "dusuk"
SEV_THRESHOLDS = [(SEV_KRITIK, 20.0), (SEV_YUKSEK, 15.0), (SEV_ORTA, 10.0), (SEV_DUSUK, 0.0)]
SEV_ORDER = [SEV_KRITIK, SEV_YUKSEK, SEV_ORTA, SEV_DUSUK]
SEV_DOTS = {SEV_KRITIK: 4, SEV_YUKSEK: 3, SEV_ORTA: 2, SEV_DUSUK: 1}
MAX_RANK = 236.0


def severity_value(max_score: float, rank: Any, threats: List[Any],
                   regressed: bool, tier: Any) -> float:
    """Score an action by how much it affects the environment."""
    rank_n = _num(rank, MAX_RANK) or MAX_RANK
    tw = min(6, sum(THREAT_WEIGHT.get(str(t).lower(), 1) for t in (threats or [])))
    return (max_score * 0.9
            + (1 - min(rank_n, MAX_RANK) / MAX_RANK) * 6
            + tw * 0.9
            + (8 if regressed else 0)
            + (2 if str(tier) == "Core" else 0))


def severity_key(value: float) -> str:
    for key, threshold in SEV_THRESHOLDS:
        if value >= threshold:
            return key
    return SEV_DUSUK


def analyse(latest: Dict[str, Any], previous: Optional[Dict[str, Any]],
            profiles: List[Dict[str, Any]], lang: str = "tr",
            history: Optional[List[Dict[str, Any]]] = None,
            regression_days: int = 30) -> Dict[str, Any]:
    profile_by_id = {str(p.get("id", "")).lower(): p for p in profiles}

    # A control has "regressed" when its current score is below the best score it
    # reached inside the comparison window - this mirrors the portal's Regressed
    # counter far better than comparing only with yesterday's snapshot.
    window = [latest]
    if history:
        window = sorted(history, key=lambda h: str(h.get("createdDateTime")),
                        reverse=True)[:max(2, regression_days)]
    elif previous:
        window = [latest, previous]
    prev_scores: Dict[str, float] = {}
    for snap in window:
        for c in snap.get("controlScores", []) or []:
            key = str(c.get("controlName", "")).lower()
            prev_scores[key] = max(prev_scores.get(key, 0.0), _num(c.get("score")))

    controls: List[Dict[str, Any]] = []
    not_applicable: List[Dict[str, Any]] = []

    for entry in latest.get("controlScores", []) or []:
        cid = str(entry.get("controlName") or "")
        prof = profile_by_id.get(cid.lower(), {})
        if prof.get("deprecated"):
            continue

        score = _num(entry.get("score"))
        max_score = _num(prof.get("maxScore"))
        if max_score <= 0:
            # Fall back to the snapshot's own percentage when the catalogue has no max
            pct_in = _num(entry.get("scoreInPercentage"))
            max_score = round(score / (pct_in / 100.0), 2) if pct_in > 0 else score
        status, update = classify(entry, prof, score, max_score)

        gap = 0.0 if status in (S_COMPLETED,) else max(0.0, max_score - score)
        prev = prev_scores.get(cid.lower())
        regressed = prev is not None and score < prev - 1e-9 and status != S_COMPLETED

        note_parts = []
        if update.get("comment"):
            note_parts.append(_strip_html(update["comment"]))
        if update.get("updatedDateTime"):
            who = update.get("updatedBy") or update.get("assignedTo") or ""
            note_parts.append(f"{_short_date(update['updatedDateTime'])}"
                              + (f" · {who}" if who else ""))
        impl = localise_status(_strip_html(entry.get("implementationStatus") or ""), lang)
        if impl:
            note_parts.append(impl)
        on_flag = str(entry.get("on") or "").strip().lower()
        count, total = entry.get("count"), entry.get("total")
        if count is not None and total not in (None, "", 0, "0"):
            note_parts.append(f"{count}/{total}")
        elif on_flag in ("true", "false") and not impl:
            note_parts.append("on" if on_flag == "true" else "off")
        if regressed:
            note_parts.insert(0, f"↓ {prev:.1f} → {score:.1f}")

        sev_v = severity_value(max_score, prof.get("rank"), prof.get("threats"),
                               regressed, prof.get("tier"))
        sev_k = severity_key(sev_v)
        controls.append({
            "id": cid,
            "severity": sev_k,
            "severityValue": round(sev_v, 1),
            "title": prof.get("title") or _strip_html(entry.get("description") or "") or cid,
            "titleTr": "",
            "category": entry.get("controlCategory") or prof.get("controlCategory") or "Other",
            "service": product_name(prof.get("service")),
            "serviceCode": str(prof.get("service") or ""),
            "score": round(score, 2),
            "maxScore": round(max_score, 2),
            "gap": round(gap, 2),
            "achievedPct": round(score / max_score * 100, 1) if max_score else 0.0,
            "status": status,
            "partial": bool(0 < score < max_score),
            "regressed": regressed,
            "userImpact": (prof.get("userImpact") or "").strip(),
            "implementationCost": prof.get("implementationCost") or "",
            "threats": prof.get("threats") or [],
            "note": " · ".join([p for p in note_parts if p]),
            "remediation": modernise_terms(_strip_html(prof.get("remediation") or "")),
            "remediationImpact": modernise_terms(
                _strip_html(prof.get("remediationImpact") or "")),
            "actionUrl": prof.get("actionUrl") or "",
            "rank": prof.get("rank"),
        })

    seen = {c["id"].lower() for c in controls}
    for prof in profiles:
        pid = str(prof.get("id") or "")
        if pid and pid.lower() not in seen and not prof.get("deprecated"):
            not_applicable.append({
                "id": pid, "title": prof.get("title") or pid,
                "category": prof.get("controlCategory") or "Other",
                "service": product_name(prof.get("service")),
            "serviceCode": str(prof.get("service") or ""),
                "maxScore": round(_num(prof.get("maxScore")), 2),
            })

    translated = 0
    if lang == "tr":
        translated = apply_translations(controls, load_translation_pack())

    controls.sort(key=lambda c: (-c["severityValue"], -c["gap"], str(c["title"])))

    # ---- Headline figures: the tenant snapshot is authoritative -------------
    current = _num(latest.get("currentScore"))
    maximum = _num(latest.get("maxScore"))
    if maximum <= 0:
        maximum = sum(c["maxScore"] for c in controls)
    pct = round(current / maximum * 100, 1) if maximum else 0.0
    band_key, band_colour = risk_band(pct)

    catalogue_max = round(sum(c["maxScore"] for c in controls), 1)
    reconciles = abs(catalogue_max - maximum) <= max(1.0, maximum * 0.02)

    counts = {k: 0 for k in (S_COMPLETED, S_TOADDRESS, S_PLANNED,
                             S_RISK, S_THIRD, S_ALT)}
    for c in controls:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    regressed_count = sum(1 for c in controls if c["regressed"])
    partial_count = sum(1 for c in controls if c["partial"] and c["status"] in OPEN_STATES)

    categories: Dict[str, Dict[str, Any]] = {}
    for c in controls:
        cat = categories.setdefault(c["category"] or "Other",
                                    {"score": 0.0, "maxScore": 0.0, "count": 0,
                                     "completed": 0, "gap": 0.0, "critical": 0})
        cat["score"] += c["score"]
        cat["maxScore"] += c["maxScore"]
        cat["gap"] += c["gap"]
        cat["count"] += 1
        if c["status"] == S_COMPLETED:
            cat["completed"] += 1
        if c["severity"] == SEV_KRITIK and c["status"] in OPEN_STATES:
            cat["critical"] += 1
    for cat in categories.values():
        cat["achievedPct"] = round(cat["score"] / cat["maxScore"] * 100, 1) if cat["maxScore"] else 0.0
        for k in ("score", "maxScore", "gap"):
            cat[k] = round(cat[k], 1)

    sev_counts = {k: sum(1 for c in controls if c["severity"] == k) for k in SEV_ORDER}
    sev_open = {k: sum(1 for c in controls
                       if c["severity"] == k and c["status"] in OPEN_STATES) for k in SEV_ORDER}
    sev_gap = {k: round(sum(c["gap"] for c in controls
                            if c["severity"] == k and c["status"] in OPEN_STATES), 1)
               for k in SEV_ORDER}

    open_controls = [c for c in controls if c["status"] in OPEN_STATES]
    done_controls = [c for c in controls if c["status"] == S_COMPLETED]
    closed_controls = [c for c in controls if c["status"] in CLOSED_STATES]
    total_gap = round(sum(c["gap"] for c in open_controls), 1)

    return {
        "lang": lang,
        "currentScore": round(current, 2),
        "maxScore": round(maximum, 2),
        "achievedPct": pct,
        "riskKey": band_key,
        "riskColour": band_colour,
        "measuredAt": latest.get("createdDateTime"),
        "activeUserCount": latest.get("activeUserCount"),
        "licensedUserCount": latest.get("licensedUserCount"),
        "comparativeScores": latest.get("averageComparativeScores") or [],
        "applicableCount": len(controls),
        "translatedCount": translated,
        "notApplicableCount": len(not_applicable),
        "notApplicable": not_applicable,
        "catalogueMax": catalogue_max,
        "reconciles": reconciles,
        "counts": counts,
        "sevCounts": sev_counts,
        "sevOpen": sev_open,
        "sevGap": sev_gap,
        "regressedCount": regressed_count,
        "partialCount": partial_count,
        "categories": categories,
        "controls": controls,
        "openControls": open_controls,
        "doneControls": done_controls,
        "closedControls": closed_controls,
        "totalGap": total_gap,
        "priority": sorted(open_controls,
                           key=lambda c: (-c["severityValue"], -c["gap"]))[:10],
        "quickWins": [c for c in sorted(open_controls, key=lambda c: -c["gap"])
                      if c["userImpact"].lower() == "low"][:10],
        "regressed": [c for c in controls if c["regressed"]],
    }


# --------------------------------------------------------------------------- #
# HTML report  (v7 - sectioned, light theme, impact-driven)
#
# Three sections in one self-contained file, reached from a top tab bar:
#   1  Genel Bakış     score, executive summary, severity, categories, trend
#   2  Tüm işlemler    every applicable action, filterable and expandable
#   3  Yol haritası    30/60/90 day plan ordered by impact severity
#
# Colour system - one palette for the whole report:
#   Kritik #C00000   Yüksek #F56A00   Orta #FFD500   Düşük #00A14B
# SOLID tones fill bars, dots, badges and chart strokes; TEXT tones are the same
# hues darkened only as far as WCAG AA (4.5:1) needs for small text on white.
# A neutral blue is reserved for descriptive elements (category breakdown) so it
# can never be read as a risk level.
#
# Grounding for the layout decisions (unchanged from the previous revision):
#  * grouped dense table with expandable rows - IBM Carbon data-table usage
#  * two disclosure levels at most - NN/g progressive disclosure
#  * status = icon/shape + text + colour, never colour alone - W3C WCAG SC 1.4.1
#  * no gauge, no pie - Cleveland & McGill 1984 (position beats angle)
#  * clickable KPI tiles act as filters - Prowler dashboard pattern
# --------------------------------------------------------------------------- #
SEV_SOLID = {"kritik": "#C00000", "yuksek": "#F56A00",
             "orta": "#FFD500", "dusuk": "#00A14B"}
# Text tones: same hues, darkened until small text clears WCAG AA on both white
# and on the matching tint (measured, not estimated).
SEV_TEXT = {"kritik": "#C00000", "yuksek": "#A84800",
            "orta": "#756200", "dusuk": "#046B34"}
# Display tones for very large numerals (the headline score). WCAG asks only
# 3:1 for large bold text, so these stay closer to the true hue instead of the
# darkened small-text tones - #756200 reads as muddy olive at 62px.
SEV_DISPLAY = {"kritik": "#C00000", "yuksek": "#D25400",
               "orta": "#A88400", "dusuk": "#00875A"}
# Ink to place ON a solid fill. White only works on the red; the other three are
# light fills and need dark ink.
SEV_INK = {"kritik": "#FFFFFF", "yuksek": "#2E1400",
           "orta": "#3A3000", "dusuk": "#00190E"}
# Ink for LARGE numerals sitting on a solid severity fill (risk-posture table).
# Large bold text only needs 3:1, so white works on red/orange/green. The yellow
# fill is too light for white at any weight, so it keeps dark ink.
SEV_BIG_INK = {"kritik": "#FFFFFF", "yuksek": "#FFFFFF",
               "orta": "#FFFFFF", "dusuk": "#FFFFFF"}
# Fill for the risk-posture chips. Every numeral there is plain white at the
# same size and weight, so each fill must carry white on its own - no outline,
# no per-band exception. The yellow is darkened to reach that threshold while
# The gold is set by the report owner. White on #FFC000 measures 1.64:1, below
# the 3:1 large-text threshold, so the numeral there relies on size and weight
# rather than contrast - a deliberate, recorded choice, not an oversight.
SEV_BIG_FILL = {"kritik": "#C00000", "yuksek": "#F56A00",
                "orta": "#FFC000", "dusuk": "#00A14B"}
SEV_TINT = {"kritik": "#FCEAEA", "yuksek": "#FFF0E3",
            "orta": "#FFF9DB", "dusuk": "#E6F7EC"}
SEV_BDR = {"kritik": "#F0B3B3", "yuksek": "#FBC496",
           "orta": "#F2DE85", "dusuk": "#9FDCB6"}
BLUE, BLUE_T, BLUE_TINT, BLUE_BDR = "#0070C0", "#0070C0", "#EBF4FA", "#B2D4EC"

# Status shares the same four colours; deliberately-closed states are neutral
# grey because they are a decision, not a risk level.
ST_SOLID = {S_TOADDRESS: SEV_SOLID["kritik"], S_COMPLETED: SEV_SOLID["dusuk"],
            S_PLANNED: BLUE, S_RISK: "#8496AD", S_THIRD: "#8496AD", S_ALT: "#8496AD"}
ST_TEXT = {S_TOADDRESS: SEV_TEXT["kritik"], S_COMPLETED: SEV_TEXT["dusuk"],
           S_PLANNED: BLUE_T, S_RISK: "#556A85", S_THIRD: "#556A85", S_ALT: "#556A85"}
ST_TINT = {S_TOADDRESS: SEV_TINT["kritik"], S_COMPLETED: SEV_TINT["dusuk"],
           S_PLANNED: BLUE_TINT, S_RISK: "#F2F5F9", S_THIRD: "#F2F5F9", S_ALT: "#F2F5F9"}
ST_BDR = {S_TOADDRESS: SEV_BDR["kritik"], S_COMPLETED: SEV_BDR["dusuk"],
          S_PLANNED: BLUE_BDR, S_RISK: "#CFDAE8", S_THIRD: "#CFDAE8", S_ALT: "#CFDAE8"}
ST_INK = {S_TOADDRESS: SEV_INK["kritik"], S_COMPLETED: SEV_INK["dusuk"],
          S_PLANNED: "#FFFFFF", S_RISK: "#FFFFFF", S_THIRD: "#FFFFFF", S_ALT: "#FFFFFF"}

CATEGORY_ORDER = ["Identity", "Device", "Apps", "Data", "Infrastructure"]


def risk_verdict(pct: float) -> Tuple[str, str, str, str]:
    """Overall verdict on the tenant score.

    Reads as a traffic light - green good, red poor - and each band is painted
    in the colour of the band it is NAMED after, so the label and the colour can
    never disagree. Returns (key, text colour, fill colour, ink on that fill).
    """
    key = ("dusuk" if pct >= 80 else
           "orta" if pct >= 60 else
           "yuksek" if pct >= 40 else "kritik")
    return key, SEV_TEXT[key], SEV_SOLID[key], SEV_INK[key]


def build_html(res: Dict[str, Any], tenant: Dict[str, Any],
               history: List[Dict[str, Any]], lang: str = "tr",
               brand: Optional[Dict[str, Any]] = None) -> str:
    brand = brand or {}
    brand_logo = str(brand.get("logo") or "")
    brand_colour = safe_colour(brand.get("colour"), BLUE)
    provider = str(brand.get("provider") or "").strip()
    t = STR.get(lang, STR["tr"])
    e = html.escape

    def jsq(v: Any) -> str:
        """Escape a value for embedding inside a single-quoted JS string.
        HTML-escaping is wrong inside <script>; this is the correct escape."""
        return json.dumps(str(v))[1:-1].replace("'", "\\'")

    # localStorage namespace: keeps one browser's entries separate per tenant,
    # so the same report file reused for another tenant starts clean.
    tenant_key = re.sub(r"[^A-Za-z0-9_-]", "",
                        str(tenant.get("id") or "default")) or "default"
    owner_lbl = jsq(t["asg_col_owner"])
    due_lbl = jsq(t["asg_col_due"])
    overdue_lbl = jsq(t["asg_overdue"])
    yes_lbl = jsq(t["yes"])
    no_lbl = jsq(t["no"])
    generated = dt.datetime.now().strftime("%d.%m.%Y %H:%M" if lang == "tr" else "%Y-%m-%d %H:%M")
    customer = str(tenant.get("customerName") or tenant.get("displayName") or t["tenant"])

    controls = res["controls"]
    open_c = res["openControls"]
    done_c = res["doneControls"]
    closed_c = res["closedControls"]
    regressed = res["regressed"]
    score, maxs, pct = res["currentScore"], res["maxScore"], res["achievedPct"]
    gap = res["totalGap"]
    sev_open, sev_counts, sev_gap = res["sevOpen"], res["sevCounts"], res["sevGap"]

    rk, RISK_C, RISK_SOLID, RISK_INK = risk_verdict(pct)
    # Headline numeral uses the large-text tone of the same risk band.
    RISK_BIG = SEV_DISPLAY[rk]
    risk_text = RISK_LABEL[rk][lang]
    imp = lambda v: t["impact_" + str(v or "").lower()] if str(v or "").lower() in (
        "low", "moderate", "high") else (t["impact_moderate"] if str(v or "").lower() == "medium" else "—")

    # ------------------------------------------------------------------ #
    # Small components
    # ------------------------------------------------------------------ #
    def sev_cell(c: Dict[str, Any]) -> str:
        key = c["severity"]
        solid, text = SEV_SOLID[key], SEV_TEXT[key]
        dots = SEV_DOTS[key]
        marks = "".join(
            f'<i style="background:{solid if i < dots else "#E2E9F2"};'
            f'{"width:15px" if i < dots else "width:7px"}"></i>' for i in range(4))
        return (f'<span class="sev"><span class="dots">{marks}</span>'
                f'<span style="color:{text}">{e(t["sev_" + key])}</span></span>')

    def status_pill(c: Dict[str, Any]) -> str:
        k = c["status"]
        return (f'<span class="pill" style="color:{ST_TEXT[k]};background:{ST_TINT[k]};'
                f'border-color:{ST_BDR[k]}"><i style="background:{ST_SOLID[k]}"></i>'
                f'{e(t[k])}</span>')

    def action_row(c: Dict[str, Any]) -> str:
        flags = ""
        if c["regressed"]:
            flags += (f'<span class="tag" style="color:{SEV_TEXT["yuksek"]};'
                      f'background:{SEV_TINT["yuksek"]};border-color:{SEV_BDR["yuksek"]}">'
                      f'↓ {e(t["regressed"])}</span>')
        if c["partial"] and c["status"] in OPEN_STATES:
            flags += (f'<span class="tag" style="color:{SEV_TEXT["orta"]};'
                      f'background:{SEV_TINT["orta"]};border-color:{SEV_BDR["orta"]}">'
                      f'{e(t["partial"])} %{c["achievedPct"]:.0f}</span>')
        threats = ", ".join(
            t.get("threat_" + str(x).strip().lower().replace(" ", "_"), str(x))
            for x in c["threats"][:4]) or "—"
        steps = c["remediation"] or t["no_remediation"]
        # Scheme allow-list: the action URL comes from Microsoft's control profiles,
        # but a report must never be able to carry a javascript:/data: link.
        safe_url = str(c["actionUrl"] or "")
        if not safe_url.lower().startswith(("https://", "http://")):
            safe_url = ""
        link = (f'<a class="dl" href="{e(safe_url)}" target="_blank" rel="noopener noreferrer">'
                f'{e(t["open_portal"])} ↗</a>' if safe_url else "")
        impact_line = (f'<p class="dimp"><b>{e(t["col_effect"])}:</b> '
                       f'{e(c["remediationImpact"])}</p>' if c.get("remediationImpact") else "")
        note_line = (f'<p class="dnote"><b>{e(t["col_note"])}:</b> {e(c["note"])}</p>'
                     if c.get("note") else "")
        blob = e(f'{c["title"]} {c.get("titleTr","")} {c["id"]} {c["category"]} '
                 f'{c["service"]}').lower()
        # Owner / due date turn the report into a follow-up tool. Offered only
        # for actions that are still open - there is nothing to assign on a
        # completed control.
        assign_box = ""
        if c["status"] in OPEN_STATES:
            cid_a = e(str(c["id"]))
            assign_box = f"""
    <div class="dbox asg" data-aid="{cid_a}"><h5>{e(t['asg_title'])}</h5>
      <label class="af"><span>{e(t['asg_owner'])}</span>
        <input type="text" class="ai" data-k="owner" maxlength="80"
               placeholder="{e(t['asg_owner_ph'])}"></label>
      <label class="af"><span>{e(t['asg_due'])}</span>
        <input type="date" class="ai" data-k="due"></label>
      <label class="af"><span>{e(t['asg_note'])}</span>
        <input type="text" class="ai" data-k="note" maxlength="120"
               placeholder="{e(t['asg_note_ph'])}"></label>
      <p class="ahint">{e(t['asg_saved'])}</p>
    </div>"""
        return f"""
<tbody class="grp" data-status="{c['status']}" data-sev="{c['severity']}"
       data-cat="{e(str(c['category']))}" data-reg="{'1' if c['regressed'] else '0'}"
       data-gain="{c['gap']:.2f}" data-sevv="{c['severityValue']:.2f}" data-t="{blob}">
  <tr class="r" onclick="tog(this)">
    <td class="c-st">{status_pill(c)}{flags}</td>
    <td class="c-f"><div class="ft">{e(str(c['title']))}</div>
        <div class="fs">{e(str(c['category']))} · {e(str(c['service']) or str(c['id']))}</div>
        <div class="abadge" data-abid="{e(str(c['id']))}" hidden></div></td>
    <td class="c-cat"><span class="cbadge">{e(str(c['category']))}</span></td>
    <td class="c-pt mono">{c['score']:.1f} <span class="sl">/ {c['maxScore']:.0f}</span></td>
    <td class="c-gn mono">{('+%.0f' % c['gap']) if c['gap'] > 0 else '—'}</td>
    <td class="c-sv">{sev_cell(c)}</td>
    <td class="c-ch"><span class="chev">›</span></td>
  </tr>
  <tr class="det" hidden><td colspan="7"><div class="dwrap">
    <div class="dbox"><h5>{e(t['at_glance'])}</h5><dl>
      <dt>{e(t['col_category'])}</dt><dd>{e(str(c['category']))}</dd>
      <dt>{e(t['col_product'])}</dt><dd>{e(str(c['service']) or '—')}</dd>
      <dt>{e(t['col_points'])}</dt><dd class="mono">{c['score']:.1f} / {c['maxScore']:.0f}</dd>
      <dt>{e(t['col_gain'])}</dt><dd class="mono" style="color:{SEV_TEXT['dusuk']}">+{c['gap']:.0f}</dd>
      <dt>{e(t['sev_label'])}</dt><dd>{e(t['sev_' + c['severity']])}
        <span class="mut">({c['severityValue']:.1f})</span></dd>
      <dt>{e(t['ms_rank'])}</dt><dd class="mono">#{e(str(c['rank'] or '—'))}</dd>
      <dt>{e(t['col_impact'])}</dt><dd>{e(imp(c['userImpact']))}</dd>
      <dt>{e(t['col_cost'])}</dt><dd>{e(imp(c['implementationCost']))}</dd>
      <dt>{e(t['threats'])}</dt><dd>{e(threats)}</dd>
    </dl></div>
    <div class="dbox grow"><h5>{e(t['implementation'])}</h5><p>{e(steps)}</p>
      {impact_line}{note_line}{link}</div>
    {assign_box}
  </div></td></tr>
</tbody>"""

    # ------------------------------------------------------------------ #
    # Section 1 - overview
    # ------------------------------------------------------------------ #
    cats_sorted = sorted(res["categories"].items(),
                         key=lambda kv: (CATEGORY_ORDER.index(kv[0])
                                         if kv[0] in CATEGORY_ORDER else 9))
    mini_cats = ""
    for name, d in cats_sorted:
        p = d["achievedPct"]
        mini_cats += f"""
        <div class="mc"><div class="mc-t"><span>{e(name)}</span>
          <b class="mono" style="color:{BLUE_T}">%{p:.0f}</b></div>
          <div class="mc-b"><span style="width:{min(100.0, p):.0f}%;background:{BLUE}"></span></div>
        </div>"""

    # Score projection - what the percentage becomes once a given set of open
    # actions is closed. Short, Secure-Score-specific, and directly actionable;
    # the peer-average comparison lives in the executive summary instead.
    def _proj_row(label: str, gain: float) -> str:
        if gain <= 0:
            return ""
        target = min(100.0, (score + gain) / max(1.0, maxs) * 100.0)
        delta = target - pct
        fmt = (lambda v: f"%{v:.1f}") if lang == "tr" else (lambda v: f"{v:.1f}%")
        return f"""
        <div class="pj"><div class="pj-l">{e(label)}</div>
          <div class="pj-r"><b class="pj-v mono">{fmt(target)}</b>
            <span class="pj-d mono" style="color:{SEV_TEXT['dusuk']}">▲ {fmt(delta)}</span>
          </div></div>"""

    gain_ky = sev_gap.get(SEV_KRITIK, 0.0) + sev_gap.get(SEV_YUKSEK, 0.0)
    gain_qw = sum(c["gap"] for c in res["quickWins"])
    bench_html = _proj_row(t["proj_ky"], gain_ky) + _proj_row(t["proj_qw"], gain_qw)
    if not bench_html and not open_c:
        bench_html = f'<div class="pj-none">{e(t["proj_none"])}</div>'

    # executive summary
    def em(v: Any, colour: Optional[str] = None) -> str:
        style = f' style="color:{colour}"' if colour else ""
        return f'<b class="em"{style}>{e(str(v))}</b>'

    bullets: List[str] = []
    worst = max(res["categories"].items(), key=lambda kv: kv[1]["gap"], default=None)
    if worst and worst[1]["gap"] > 0:
        wn, wd = worst
        bullets.append(t["sum_cat"].format(
            cat=e(wn), openn=em(int(wd["count"] - wd["completed"])),
            gap=em("+%.0f" % wd["gap"], SEV_TEXT["dusuk"]), pct=f"{wd['achievedPct']:.0f}"))
    if sev_open.get(SEV_KRITIK):
        bullets.append(t["sum_critical"].format(
            n=em(sev_open[SEV_KRITIK], SEV_TEXT["kritik"])))
    top3 = res["priority"][:3]
    if top3:
        def _short(text: str, limit: int = 62) -> str:
            """Trim on a word boundary and mark the cut, so two different
            controls can never render as the same string."""
            text = str(text)
            if len(text) <= limit:
                return text
            cut = text[:limit].rsplit(" ", 1)[0]
            return (cut if cut else text[:limit]) + "…"

        names = ", ".join(f'{e(_short(c["title"]))} ({em("+%.0f" % c["gap"], SEV_TEXT["dusuk"])})'
                          for c in top3)
        bullets.append(t["sum_top"].format(
            n=len(top3), items=names,
            sub=em("+%.0f" % sum(c["gap"] for c in top3), SEV_TEXT["dusuk"])))
    if res["quickWins"]:
        bullets.append(t["sum_quick"].format(
            n=em(len(res["quickWins"])),
            gain=em("+%.0f" % sum(c["gap"] for c in res["quickWins"]), SEV_TEXT["dusuk"])))
    if regressed:
        bullets.append(t["sum_reg"].format(n=em(len(regressed), SEV_TEXT["yuksek"])))
    # Trend over the measured window: first vs last history point. Uses the
    # same snapshots the trend chart is drawn from, so the two can never disagree.
    hist_pts = [h for h in sorted(history, key=lambda h: str(h.get("createdDateTime")))
                if _num(h.get("maxScore"))]
    if len(hist_pts) >= 2:
        def _hp(h: Dict[str, Any]) -> float:
            return _num(h.get("currentScore")) / _num(h.get("maxScore"), 1) * 100.0
        first_p, last_p = _hp(hist_pts[0]), _hp(hist_pts[-1])
        delta_p = last_p - first_p
        # Report the real elapsed span, not the snapshot count - Graph may skip
        # days, so len(history) would overstate or understate the window.
        span_days = len(hist_pts)
        try:
            d0 = str(hist_pts[0].get("createdDateTime") or "")[:10]
            d1 = str(hist_pts[-1].get("createdDateTime") or "")[:10]
            span_days = max(1, (dt.datetime.strptime(d1, "%Y-%m-%d")
                                - dt.datetime.strptime(d0, "%Y-%m-%d")).days)
        except Exception:
            pass
        fmtp = (lambda v: f"%{v:.1f}") if lang == "tr" else (lambda v: f"{v:.1f}%")
        if abs(delta_p) < 0.05:
            bullets.append(t["sum_trend_flat"].format(
                days=span_days, to=em(fmtp(last_p))))
        else:
            up_t = delta_p > 0
            bullets.append(t["sum_trend_up" if up_t else "sum_trend_down"].format(
                days=span_days, frm=fmtp(first_p), to=em(fmtp(last_p)),
                diff=em(("▲ " if up_t else "▼ ") + fmtp(abs(delta_p)),
                        SEV_TEXT["dusuk"] if up_t else SEV_TEXT["kritik"])))

    # Where the open work is concentrated - a single product usually dominates.
    svc_gap: Dict[str, float] = {}
    svc_n: Dict[str, int] = {}
    for c in open_c:
        key = str(c.get("service") or "").strip()
        if not key:
            continue
        svc_gap[key] = svc_gap.get(key, 0.0) + c["gap"]
        svc_n[key] = svc_n.get(key, 0) + 1
    if svc_gap:
        top_svc = max(svc_gap.items(), key=lambda kv: kv[1])
        if svc_n[top_svc[0]] >= 2 and top_svc[1] > 0:
            bullets.append(t["sum_service"].format(
                n=em(svc_n[top_svc[0]]), svc=e(top_svc[0]),
                gap=em("+%.0f" % top_svc[1], SEV_TEXT["dusuk"])))

    # Low implementation cost - budget-free points.
    cheap = [c for c in open_c
             if str(c.get("implementationCost") or "").lower() == "low" and c["gap"] > 0]
    if len(cheap) >= 2:
        bullets.append(t["sum_effort"].format(
            n=em(len(cheap)),
            gain=em("+%.0f" % sum(c["gap"] for c in cheap), SEV_TEXT["dusuk"])))

    bench = next((b for b in (res["comparativeScores"] or [])
                  if str(b.get("basis", "")).lower() == "alltenants"
                  and b.get("averageScore") is not None), None)
    if bench:
        avg = _num(bench["averageScore"])
        diff = pct - avg
        key = "sum_bench_up" if diff >= 0 else "sum_bench_down"
        bullets.append(t[key].format(
            avg=f"%{avg:.1f}" if lang == "tr" else f"{avg:.1f}%",
            diff=em(f"%{abs(diff):.1f}" if lang == "tr" else f"{abs(diff):.1f}%",
                    SEV_TEXT["dusuk"] if diff >= 0 else SEV_TEXT["kritik"])))

    summary_lead = t["sum_lead"].format(
        cust=e(customer), pct=em(f"%{pct:.1f}" if lang == "tr" else f"{pct:.1f}%", RISK_C),
        score=em(f"{score:.1f}"), maxscore=f"{maxs:.0f}", risk=em(risk_text, RISK_C),
        total=em(res["applicableCount"]), done=em(len(done_c), SEV_TEXT["dusuk"]),
        open=em(len(open_c), SEV_TEXT["kritik"]),
        gap=em("+%.0f" % gap, SEV_TEXT["dusuk"]))
    na_line = (t["na_line"].format(n=res["notApplicableCount"])
               if res["notApplicableCount"] else "")

    sev_cards = "".join(f"""
      <button class="sevcard" data-jump="{k}" style="--c:{SEV_TEXT[k]};--b:{SEV_TINT[k]};
        --d:{SEV_BDR[k]};--s:{SEV_SOLID[k]}"><span class="sc-bar"></span>
        <div class="sc-n mono">{sev_open.get(k, 0)}</div>
        <div class="sc-l">{e(t['sev_' + k])}</div>
        <div class="sc-g mono">+{sev_gap.get(k, 0):.0f} {e(t['points'])}</div>
      </button>""" for k in SEV_ORDER)

    total_ctrl = max(1, res["applicableCount"])
    seg_order = [S_COMPLETED, S_TOADDRESS, S_PLANNED, S_RISK]
    seg_counts = {S_COMPLETED: len(done_c), S_TOADDRESS: res["counts"].get(S_TOADDRESS, 0),
                  S_PLANNED: res["counts"].get(S_PLANNED, 0), S_RISK: len(closed_c)}
    stack = "".join(
        f'<div class="sg" style="width:{seg_counts[k]/total_ctrl*100:.2f}%;'
        f'background:{ST_SOLID[k]};color:{ST_INK[k]}" '
        f'title="{e(t[k] if k != S_RISK else t["closed_short"])}: {seg_counts[k]}">'
        f'<span>{seg_counts[k] if seg_counts[k]/total_ctrl > .06 else ""}</span></div>'
        for k in seg_order if seg_counts[k])
    legend = "".join(
        f'<span class="lg"><i style="background:{ST_SOLID[k]}"></i>'
        f'{e(t[k] if k != S_RISK else t["closed_short"])} <b>{seg_counts[k]}</b></span>'
        for k in seg_order if seg_counts[k])

    cat_rows = ""
    for name, d in cats_sorted:
        p = d["achievedPct"]
        krit = (f'<span class="minipill" style="color:{SEV_TEXT["kritik"]};'
                f'background:{SEV_TINT["kritik"]};border-color:{SEV_BDR["kritik"]}">'
                f'{int(d["critical"])} {e(t["sev_kritik"]).lower()}</span>'
                if d.get("critical") else "")
        cat_rows += f"""
        <tr><td><b>{e(name)}</b><div class="fs">{int(d['completed'])}/{int(d['count'])}
            {e(t['done_count']).lower()} {krit}</div></td>
          <td class="bcell"><div class="bar"><span style="width:{min(100.0, p):.0f}%;
            background:{BLUE}"></span></div></td>
          <td class="num mono">{d['score']:.0f} <span class="sl">/ {d['maxScore']:.0f}</span></td>
          <td class="num mono" style="color:{BLUE_T}">%{p:.0f}</td>
          <td class="num mono" style="color:{SEV_TEXT['dusuk']}">+{d['gap']:.0f}</td></tr>"""

    # trend
    pts = [(_short_date(h.get("createdDateTime")),
            _num(h.get("currentScore")) / _num(h.get("maxScore"), 1) * 100
            if _num(h.get("maxScore")) else 0.0)
           for h in sorted(history, key=lambda h: str(h.get("createdDateTime")))]
    pts = pts[::max(1, len(pts) // 30)] if len(pts) > 30 else pts
    trend = ""
    if len(pts) > 2:
        vals = [v for _, v in pts]
        lo, hi = min(vals), max(vals)
        pad = max(2.0, (hi - lo) * .3)
        lo, hi = max(0.0, lo - pad), min(100.0, hi + pad)
        span = max(.1, hi - lo)
        w, h = 1100, 150
        step = w / (len(vals) - 1)
        co = [(i * step, h - (v - lo) / span * h) for i, v in enumerate(vals)]
        line = " ".join(f"{x:.0f},{y:.0f}" for x, y in co)
        trend = f"""
        <div class="panel"><div class="p-h"><h3>{e(t['trend'])}</h3>
          <span class="sub">{e(t['trend30'])}</span></div><div class="p-b">
        <svg viewBox="-8 -10 {w+16} {h+34}" class="spark" role="img"
             aria-label="{e(t['trend'])}">
          <defs><linearGradient id="tg" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stop-color="{SEV_SOLID['dusuk']}" stop-opacity=".28"/>
            <stop offset="100%" stop-color="{SEV_SOLID['dusuk']}" stop-opacity="0"/>
          </linearGradient></defs>
          <polygon points="0,{h} {line} {w},{h}" fill="url(#tg)"/>
          <polyline points="{line}" fill="none" stroke="{SEV_SOLID['dusuk']}" stroke-width="2.5"
            stroke-linejoin="round"/>
          <circle cx="{co[-1][0]:.0f}" cy="{co[-1][1]:.0f}" r="5" fill="{SEV_SOLID['dusuk']}"/>
          <text x="0" y="{h+24}" font-size="11" fill="#5C6F87">{e(pts[0][0])}</text>
          <text x="{w}" y="{h+24}" font-size="11" fill="#5C6F87"
            text-anchor="end">{e(pts[-1][0])}</text>
        </svg></div></div>"""

    top_cards = "".join(f"""
      <div class="tcard" style="--c:{SEV_SOLID[c['severity']]}">
        <div class="tc-h"><span class="tc-g mono">+{c['gap']:.0f}</span>{sev_cell(c)}</div>
        <div class="tc-t">{e(str(c['title']))}</div>
        <div class="fs">{e(str(c['category']))} · {e(str(c['service']))}</div></div>"""
        for c in res["priority"][:5])

    # ------------------------------------------------------------------ #
    # Section 4 - progress and scope change
    #
    # Compares the oldest and newest measurement snapshots the tenant itself
    # reported. This is what turns "the score moved" into "here is what moved
    # it": a percentage can fall while the raw score rises, purely because new
    # controls entered scope. Saying so explicitly is the point of the section.
    # ------------------------------------------------------------------ #
    prog_html = ""
    snaps = sorted([h for h in history if h.get("controlScores") is not None],
                   key=lambda h: str(h.get("createdDateTime")))
    if len(snaps) >= 2 and str(snaps[0].get("createdDateTime"))[:10] \
            != str(snaps[-1].get("createdDateTime"))[:10]:
        base, cur_snap = snaps[0], snaps[-1]

        def _scores(sn: Dict[str, Any]) -> Dict[str, float]:
            out: Dict[str, float] = {}
            for c in (sn.get("controlScores") or []):
                k = str(c.get("controlName") or "").lower()
                if k:
                    out[k] = _num(c.get("score"))
            return out

        base_sc, cur_sc = _scores(base), _scores(cur_snap)
        base_score, base_max = _num(base.get("currentScore")), _num(base.get("maxScore"))
        base_pct = base_score / base_max * 100.0 if base_max else 0.0
        by_id = {c["id"].lower(): c for c in res["controls"]}

        added_ids = [k for k in cur_sc if k not in base_sc]
        removed_ids = [k for k in base_sc if k not in cur_sc]
        improved = sorted(
            [(by_id[k], base_sc[k], cur_sc[k]) for k in cur_sc
             if k in base_sc and k in by_id and cur_sc[k] > base_sc[k] + 1e-9],
            key=lambda r: -(r[2] - r[1]))
        regressed_l = sorted(
            [(by_id[k], base_sc[k], cur_sc[k]) for k in cur_sc
             if k in base_sc and k in by_id and cur_sc[k] < base_sc[k] - 1e-9],
            key=lambda r: (r[2] - r[1]))

        fmtp = (lambda v: f"%{v:.1f}") if lang == "tr" else (lambda v: f"{v:.1f}%")

        def _kpi(label: str, val: str, delta: str = "", colour: str = "") -> str:
            d = (f'<div class="pk-d" style="color:{colour}">{delta}</div>'
                 if delta else "")
            return (f'<div class="pk"><div class="pk-v mono">{val}</div>'
                    f'<div class="pk-l">{e(label)}</div>{d}</div>')

        d_raw = score - base_score
        d_pct = pct - base_pct
        kpis = (
            _kpi(t["prog_raw"], f"{base_score:.0f} → {score:.0f}",
                 ("▲ +" if d_raw >= 0 else "▼ ") + f"{abs(d_raw):.0f}",
                 SEV_TEXT["dusuk"] if d_raw >= 0 else SEV_TEXT["kritik"])
            + _kpi(t["prog_pct"], f"{fmtp(base_pct)} → {fmtp(pct)}",
                   ("▲ +" if d_pct >= 0 else "▼ ") + fmtp(abs(d_pct)).lstrip("%"),
                   SEV_TEXT["dusuk"] if d_pct >= 0 else SEV_TEXT["kritik"])
            + _kpi(t["prog_measured"], f"{len(base_sc)} → {len(cur_sc)}",
                   (f"+{len(added_ids)}" if added_ids else "")
                   + (f" −{len(removed_ids)}" if removed_ids else ""), BLUE_T)
            + _kpi(t["prog_maxs"], f"{base_max:.0f} → {maxs:.0f}", "", BLUE_T))

        if added_ids and base_max and abs(maxs - base_max) > 0.5:
            finding = t["prog_scope_up"].format(
                added=f"<b>{len(added_ids)}</b>", frm=f"{base_max:.0f}", to=f"<b>{maxs:.0f}</b>")
        elif removed_ids and base_max and abs(maxs - base_max) > 0.5:
            finding = t["prog_scope_down"].format(
                removed=f"<b>{len(removed_ids)}</b>", frm=f"{base_max:.0f}",
                to=f"<b>{maxs:.0f}</b>")
        else:
            finding = t["prog_scope_same"].format(to=f"<b>{maxs:.0f}</b>")
        if abs(d_raw) < 0.05:
            finding += " " + t["prog_net_flat"]
        else:
            finding += " " + t["prog_net_up" if d_raw > 0 else "prog_net_down"].format(
                v=f'<b style="color:'
                  f'{SEV_TEXT["dusuk"] if d_raw > 0 else SEV_TEXT["kritik"]}">'
                  f'{abs(d_raw):.0f}</b>')

        def _delta_table(rows: List[Tuple[Dict[str, Any], float, float]],
                         good: bool) -> str:
            if not rows:
                return f'<p class="pnone">{e(t["prog_none"])}</p>'
            col = SEV_TEXT["dusuk"] if good else SEV_TEXT["kritik"]
            body = "".join(
                f'<tr><td><div class="ft">{e(str(c["title"]))}</div>'
                f'<div class="fs">{e(str(c["category"]))} · {e(str(c["service"]))}</div></td>'
                f'<td class="num mono">{b:.1f}</td><td class="num mono">{n:.1f}</td>'
                f'<td class="num mono"><b style="color:{col}">'
                f'{"+" if n >= b else "−"}{abs(n - b):.1f}</b></td></tr>'
                for c, b, n in rows[:15])
            return (f'<table class="ptbl"><thead><tr><th>{e(t["col_action"])}</th>'
                    f'<th class="num">{e(t["prog_h_before"])}</th>'
                    f'<th class="num">{e(t["prog_h_now"])}</th>'
                    f'<th class="num">{e(t["prog_h_delta"])}</th></tr></thead>'
                    f'<tbody>{body}</tbody></table>')

        def _list_table(ids: List[str]) -> str:
            rows = [by_id[k] for k in ids if k in by_id]
            if not rows:
                return f'<p class="pnone">{e(t["prog_none"])}</p>'
            body = "".join(
                f'<tr><td><div class="ft">{e(str(c["title"]))}</div>'
                f'<div class="fs">{e(str(c["category"]))} · {e(str(c["service"]))}</div></td>'
                f'<td class="num mono">{c["maxScore"]:.0f}</td></tr>'
                for c in sorted(rows, key=lambda c: -c["maxScore"])[:15])
            return (f'<table class="ptbl"><thead><tr><th>{e(t["col_action"])}</th>'
                    f'<th class="num">{e(t["col_points"])}</th></tr></thead>'
                    f'<tbody>{body}</tbody></table>')

        removed_block = ""
        if removed_ids:
            removed_block = f"""
      <div class="panel"><div class="p-h"><h3>{e(t['prog_t_removed'])}</h3>
        <span class="n">{len(removed_ids)}</span></div>
        <div class="p-b">{_list_table(removed_ids)}</div></div>"""

        prog_html = f"""
  <div class="panel pfind"><div class="p-h"><h3>{e(t['prog_finding'])}</h3>
    <span class="sub">{e(t['prog_window'])}: {e(_short_date(base.get('createdDateTime')))}
      → {e(_short_date(cur_snap.get('createdDateTime')))}</span></div>
    <div class="p-b">
      <div class="pkgrid">{kpis}</div>
      <p class="pfind-t">{finding}</p>
    </div></div>

  <div class="pkgrid pk2">
    {_kpi(t['prog_improved'], str(len(improved)), '', SEV_TEXT['dusuk'])}
    {_kpi(t['prog_regressed'], str(len(regressed_l)), '', SEV_TEXT['kritik'])}
    {_kpi(t['prog_added'], str(len(added_ids)), '', BLUE_T)}
    {_kpi(t['prog_removed'], str(len(removed_ids)), '', BLUE_T)}
  </div>

  <div class="grid-b">
    <div class="panel"><div class="p-h"><h3>{e(t['prog_t_improved'])}</h3>
      <span class="n">{len(improved)}</span></div>
      <div class="p-b">{_delta_table(improved, True)}</div></div>
    <div class="panel"><div class="p-h"><h3>{e(t['prog_t_regressed'])}</h3>
      <span class="n">{len(regressed_l)}</span></div>
      <div class="p-b">{_delta_table(regressed_l, False)}</div></div>
  </div>

  <div class="panel"><div class="p-h"><h3>{e(t['prog_t_added'])}</h3>
    <span class="n">{len(added_ids)}</span></div>
    <div class="p-b">{_list_table(added_ids)}</div></div>
  {removed_block}
  <p class="pnote">{e(t['prog_note'])}</p>"""
    else:
        prog_html = f'<div class="panel"><div class="p-b"><p class="pnone">{e(t["prog_nodata"])}</p></div></div>'

    # ------------------------------------------------------------------ #
    # Section 5 - findings report
    #
    # One consulting-style card per open action. Graph supplies the factual
    # half (steps, rank, points, threats); the content pack supplies the
    # interpretive half (what it is, why it matters, what to watch for, how to
    # prove the fix). A control missing pack content still renders - it just
    # shows Microsoft's own guidance and says so, rather than inventing text.
    # ------------------------------------------------------------------ #
    fnd_cards = ""
    fnd_list = sorted(open_c, key=lambda c: (-c["severityValue"], c["rank"] or 999))
    for n, c in enumerate(fnd_list, 1):
        k = c["severity"]
        threats_f = ", ".join(
            t.get("threat_" + str(x).strip().lower().replace(" ", "_"), str(x))
            for x in c["threats"]) or "—"
        url_f = str(c["actionUrl"] or "")
        if not url_f.lower().startswith(("https://", "http://")):
            url_f = ""
        link_f = (f'<a href="{e(url_f)}" target="_blank" rel="noopener noreferrer">'
                  f'{e(t["fnd_link"])} ↗</a>' if url_f else "—")

        def _row(label: str, body: str) -> str:
            return f"<tr><th>{e(label)}</th><td>{body}</td></tr>"

        desc_rows = ""
        if c.get("aciklama"):
            desc_rows += _row(t["fnd_desc"], e(str(c["aciklama"])))
        if c.get("etkisi"):
            desc_rows += _row(t["fnd_impact"], e(str(c["etkisi"])))

        fix = f'<p><b>{e(t["fnd_config"])}:</b> {e(c["remediation"] or t["no_remediation"])}</p>'
        if c.get("bagimlilik"):
            fix += f'<p><b>{e(t["fnd_dep"])}:</b> {e(str(c["bagimlilik"]))}</p>'
        if c.get("dogrulama"):
            fix += f'<p><b>{e(t["fnd_verify"])}:</b> {e(str(c["dogrulama"]))}</p>'
        if not (c.get("aciklama") or c.get("etkisi")):
            fix += f'<p class="fn-gap">{e(t["fnd_nopack"])}</p>'

        fnd_cards += f"""
  <article class="bulgu" id="bulgu-{n}">
    <div class="b-h" style="background:{BLUE}">
      <span class="b-n">{e(t['fnd_n'])} {n}</span> {e(str(c['title']))}</div>
    <div class="b-sev" style="background:{SEV_SOLID[k]};color:{SEV_INK[k]}">
      {e(t['sev_' + k])}</div>
    <table class="b-t">
      {_row(t['fnd_resource'],
            f"{e(str(c['service']) or '—')} · {e(str(c['category']))} {e(t['fnd_scope'])}")}
      {_row(t['col_category'], e(str(c['category'])))}
      {desc_rows}
      {_row(t['fnd_risk'],
            f'<b style="color:{SEV_TEXT[k]}">{e(t["sev_" + k])}</b> '
            f'<span class="b-m">({c["severityValue"]:.1f})</span>')}
      {_row(t['fnd_fix'], fix)}
      {_row(t['fnd_more'], link_f)}
      {_row(t['fnd_record'],
            f"{e(t['fnd_rank'])}: <b>{e(str(c['rank'] or '—'))}</b> · "
            f"{e(str(c['category']))} · {e(str(c['service']) or '—')}<br>"
            f"<b class=\"mono\">{c['score']:.1f} / {c['maxScore']:.0f}</b> — "
            + t['fnd_gain'].format(
                v=f'<b style="color:{SEV_TEXT["dusuk"]}">+{c["gap"]:.0f}</b>')
            + f"<br>{e(t['fnd_threats'])}: {e(threats_f)}.")}
    </table>
  </article>"""

    if not fnd_cards:
        fnd_cards = (f'<div class="panel"><div class="p-b">'
                     f'<p class="pnone">{e(t["fnd_none"])}</p></div></div>')

    # Findings front matter: executive summary, purpose, and the colour-coded
    # risk posture table. Counts are the OPEN findings actually carded below,
    # so the table can never disagree with the cards.
    fnd_open_n = len(fnd_list)
    fnd_sev_n = {k: sum(1 for c in fnd_list if c["severity"] == k) for k in SEV_ORDER}
    posture_rows = "".join(
        f"""
      <div class="rp-r">
        <div class="rp-c" style="background:{SEV_BIG_FILL[k]}">
          <div class="rp-n mono">{fnd_sev_n[k]}</div>
          <div class="rp-l">{e(t['sev_' + k])}</div></div>
        <div class="rp-d"><b>{e(t['sev_' + k])}:</b> {e(t['fnd_d_' + k])}</div>
      </div>""" for k in SEV_ORDER if fnd_sev_n[k])

    fnd_intro = f"""
  <div class="panel fnd-intro"><div class="p-b">
    <h3 class="fi-h">{e(t['fnd_exec'])}</h3>
    <p class="fi-p">{t['fnd_exec_b'].format(cust=e(customer), n=fnd_open_n)}</p>

    <h3 class="fi-h">{e(t['fnd_purpose'])}</h3>
    <p class="fi-p">{t['fnd_purpose_b']}</p>

    <h3 class="fi-h">{e(t['fnd_posture'])}</h3>
    <p class="fi-p">{e(t['fnd_posture_b'])}</p>
    <div class="rptbl">{posture_rows}</div>
    <p class="fi-tot"><b class="mono">{fnd_open_n}</b> {e(t['fnd_total'])}</p>

    <div class="fi-act">
      <button class="btn btn-p" id="fndpdf">{e(t['fnd_pdf'])}</button>
      <span class="fi-hint">{e(t['fnd_pdf_hint'])}</span>
    </div>
  </div></div>
"""

    # ------------------------------------------------------------------ #
    # Section 2 - all actions
    # ------------------------------------------------------------------ #
    st_chips = "".join(
        f'<button class="chip" data-f="status" data-v="{k}" '
        f'style="--c:{ST_SOLID[k]};--ink:{ST_INK[k]}">'
        f'<i style="background:{ST_SOLID[k]}"></i>{e(t[k])}<b>{res["counts"].get(k, 0)}</b></button>'
        for k in (S_TOADDRESS, S_COMPLETED, S_PLANNED, S_RISK, S_THIRD, S_ALT)
        if res["counts"].get(k))
    sv_chips = "".join(
        f'<button class="chip" data-f="sev" data-v="{k}" '
        f'style="--c:{SEV_SOLID[k]};--ink:{SEV_INK[k]}">'
        f'<i style="background:{SEV_SOLID[k]}"></i>{e(t["sev_" + k])}'
        f'<b>{sev_counts.get(k, 0)}</b></button>' for k in SEV_ORDER if sev_counts.get(k))
    cat_chips = "".join(
        f'<button class="chip" data-f="cat" data-v="{e(n)}" style="--c:{BLUE};--ink:#FFFFFF">'
        f'{e(n)}<b>{int(d["count"])}</b></button>' for n, d in cats_sorted)
    rows = "".join(action_row(c) for c in controls)

    # ------------------------------------------------------------------ #
    # Section 3 - roadmap
    # ------------------------------------------------------------------ #
    phases: Dict[int, List[Dict[str, Any]]] = {0: [], 1: [], 2: []}
    for c in sorted(open_c, key=lambda c: (-c["severityValue"], -c["gap"])):
        phases[0 if c["severity"] == SEV_KRITIK
               else (1 if c["severity"] == SEV_YUKSEK else 2)].append(c)

    meta = [(0, t["phase1"], t["phase1_when"], t["phase1_desc"],
             SEV_SOLID["kritik"], SEV_INK["kritik"]),
            (1, t["phase2"], t["phase2_when"], t["phase2_desc"],
             SEV_SOLID["yuksek"], SEV_INK["yuksek"]),
            (2, t["phase3"], t["phase3_when"], t["phase3_desc"],
             SEV_SOLID["orta"], SEV_INK["orta"])]

    blocks, running, curve = "", score, [pct]
    for idx, name, when, desc, col, fgc in meta:
        items = phases[idx]
        pgain = sum(c["gap"] for c in items)
        running += pgain
        curve.append(min(100.0, running / maxs * 100) if maxs else pct)
        krit = sum(1 for c in items if c["severity"] == SEV_KRITIK)
        reg = sum(1 for c in items if c["regressed"])
        prows = "".join(f"""
          <tr><td class="ph-n mono">{i}</td>
            <td><div class="ft">{e(str(c['title']))}</div>
                <div class="fs">{e(str(c['category']))} · {e(str(c['service']))}</div></td>
            <td>{sev_cell(c)}</td>
            <td>{e(imp(c['userImpact']))}</td>
            <td>{e(imp(c['implementationCost']))}</td>
            <td class="num mono" style="color:{SEV_TEXT['dusuk']}">+{c['gap']:.0f}</td></tr>"""
            for i, c in enumerate(items[:10], 1))
        more = (f'<tr><td colspan="6" class="more">… {t["and_more"].format(n=len(items)-10)}</td></tr>'
                if len(items) > 10 else "")
        badges = ""
        if krit:
            badges += (f'<span class="minipill" style="color:{SEV_TEXT["kritik"]};'
                       f'background:{SEV_TINT["kritik"]};border-color:{SEV_BDR["kritik"]}">'
                       f'{krit} {e(t["sev_kritik"]).lower()}</span>')
        if reg:
            badges += (f'<span class="minipill" style="color:{SEV_TEXT["yuksek"]};'
                       f'background:{SEV_TINT["yuksek"]};border-color:{SEV_BDR["yuksek"]}">'
                       f'{reg} {e(t["regressed"]).lower()}</span>')
        blocks += f"""
        <div class="panel phase" style="--c:{col}">
          <div class="p-h ph-h">
            <span class="ph-badge" style="background:{col};color:{fgc}">{e(name)}</span>
            <span class="ph-when">{e(when)}</span><span class="sub">{e(desc)}</span>
            <span class="ph-sum">{badges}
              <span class="minipill neutral">{len(items)} {e(t['action_unit'])}</span>
              <span class="minipill" style="color:{SEV_TEXT['dusuk']};background:{SEV_TINT['dusuk']};
                border-color:{SEV_BDR['dusuk']}">+{pgain:.0f} {e(t['points'])}</span></span>
          </div>
          <table class="road"><thead><tr>
            <th class="num">#</th><th>{e(t['col_action'])}</th><th>{e(t['sev_label'])}</th>
            <th>{e(t['col_impact'])}</th><th>{e(t['col_cost'])}</th>
            <th class="num">{e(t['col_gain'])}</th>
          </tr></thead><tbody>{prows}{more}</tbody></table>
        </div>"""

    w, h = 1000, 150
    step = w / (len(curve) - 1)
    line = " ".join(f"{i*step:.0f},{h-(v/100*h):.0f}" for i, v in enumerate(curve))
    dots = "".join(f'<circle cx="{i*step:.0f}" cy="{h-(v/100*h):.0f}" r="5" '
                   f'fill="{SEV_SOLID["dusuk"]}"/>' for i, v in enumerate(curve))
    labels = "".join(
        f'<text x="{i*step:.0f}" y="{h-(v/100*h)-14:.0f}" font-size="14.5" font-weight="800" '
        f'fill="{SEV_TEXT["dusuk"]}" text-anchor="middle">%{v:.0f}</text>'
        for i, v in enumerate(curve))
    xlab = "".join(
        f'<text x="{i*step:.0f}" y="{h+24}" font-size="11.5" fill="#5C6F87" '
        f'text-anchor="middle">{e(lbl)}</text>'
        for i, lbl in enumerate([t["today"], t["d30"], t["d60"], t["d90"]]))

    target_pct = min(100.0, pct + (gap / maxs * 100 if maxs else 0))

    return f"""<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(t['title'])} · {e(customer)}</title>
<style>
:root{{
 --bg:#F4F7FB; --pan:#FFFFFF; --pan2:#F7FAFD; --bd:#E2E9F2; --bd2:#CFDAE8;
 --tx:#0F1D2E; --mut:#4A5D75; --dim:#5C6F87;
 --acc:{SEV_TEXT['dusuk']}; --acc2:{SEV_SOLID['dusuk']};
 --shadow:0 1px 2px rgba(15,29,46,.05),0 1px 3px rgba(15,29,46,.04);
 --f:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,
     "Helvetica Neue",Arial,sans-serif;
 --fn:"Segoe UI Variable Display","Segoe UI",system-ui,-apple-system,sans-serif;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--tx);font:15px/1.62 var(--f);
 -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}}
.mono{{font-variant-numeric:tabular-nums}} .mut{{color:var(--mut)}}
.sl{{color:var(--dim);font-weight:400}}
a{{color:var(--acc);text-decoration:none}} a:hover{{text-decoration:underline}}
.wrap{{max-width:1360px;margin:0 auto;padding:0 26px}}

header{{background:radial-gradient(1100px 300px at 10% -60%,{RISK_SOLID}14,transparent 62%),
 radial-gradient(900px 280px at 90% -70%,{SEV_SOLID['dusuk']}12,transparent 62%),var(--pan);
 border-bottom:1px solid var(--bd)}}
.h-top{{display:flex;align-items:center;gap:16px;padding:20px 0 16px;flex-wrap:wrap}}
.mark{{width:42px;height:42px;border-radius:12px;flex:none;
 background:linear-gradient(135deg,{RISK_SOLID},{SEV_SOLID['dusuk']});display:flex;
 align-items:center;justify-content:center;font-weight:800;color:#fff;font-size:19px;
 box-shadow:0 2px 8px {RISK_SOLID}44}}
.cust{{font-size:25px;font-weight:800;letter-spacing:-.5px;line-height:1.1}}
.tsub{{color:var(--mut);font-size:13px;margin-top:1px}}
.hmeta{{display:flex;gap:8px;flex-wrap:wrap;margin-top:9px}}
.hm{{display:inline-flex;align-items:baseline;gap:7px;background:var(--pan2);
 border:1px solid var(--bd);border-radius:8px;padding:5px 12px}}
.hm b{{font-size:9.5px;letter-spacing:.11em;text-transform:uppercase;color:var(--dim);font-weight:700}}
.hm span{{font-size:12.5px;color:var(--tx);font-weight:600}}
/* Branding: logo slot, provider credit and the brand accent bar. Scoped to
   the header/footer so the risk palette can never be recoloured by a brand. */
.mark.logo{{background:#fff;border:1px solid var(--bd);box-shadow:none;
 width:auto;min-width:42px;max-width:190px;height:44px;padding:5px 10px}}
.mark.logo img{{max-height:34px;max-width:168px;display:block;object-fit:contain}}
.hright{{margin-left:auto;text-align:right}}
.prov{{margin-top:6px;font-size:11.5px;color:var(--mut)}}
.prov b{{color:var(--tx);font-weight:700}}
header{{border-top:3px solid {brand_colour}}}
/* ---- Cover page ----
   Branded hand-off page. The accent colour is the customer/provider brand;
   the score numeral keeps its risk colour, because a brand colour must never
   be able to make a critical score look calm. */
.cover{{min-height:100vh;display:flex;align-items:stretch;
 background:linear-gradient(155deg,{brand_colour}0E,var(--bg) 55%,{brand_colour}14);
 border-bottom:1px solid var(--bd)}}
.cv-in{{max-width:1000px;margin:0 auto;padding:44px 30px 40px;display:flex;
 flex-direction:column;width:100%}}
.cv-top{{display:flex;align-items:center;gap:16px}}
.cv-logo{{background:#fff;border:1px solid var(--bd);border-radius:12px;
 padding:9px 14px;display:flex;align-items:center}}
.cv-logo img{{max-height:46px;max-width:240px;display:block;object-fit:contain}}
.cv-mark{{width:54px;height:54px;border-radius:15px;display:flex;align-items:center;
 justify-content:center;font-size:23px;font-weight:800;color:#fff;
 background:linear-gradient(135deg,{brand_colour},{RISK_SOLID});
 box-shadow:0 3px 12px {brand_colour}44}}
.cv-conf{{margin-left:auto;display:inline-flex;align-items:center;gap:7px;
 background:{SEV_TINT['kritik']};border:1px solid {SEV_BDR['kritik']};
 color:{SEV_TEXT['kritik']};border-radius:8px;padding:7px 13px;
 font-size:11.5px;font-weight:700}}
.cv-mid{{margin:auto 0;padding:40px 0}}
.cv-kicker{{font-size:11px;letter-spacing:.17em;text-transform:uppercase;
 color:{brand_colour};font-weight:800}}
.cv-cust{{font-family:var(--fn);margin:9px 0 0;font-size:47px;font-weight:800;
 letter-spacing:-1.4px;line-height:1.08;color:var(--tx)}}
.cv-rule{{width:74px;height:4px;border-radius:3px;background:{brand_colour};margin:20px 0 28px}}
.cv-score{{display:flex;align-items:center;gap:24px;flex-wrap:wrap;margin-bottom:32px}}
.cv-pct{{font-family:var(--fn);font-size:84px;font-weight:800;letter-spacing:-3.4px;
 line-height:.92}}
.cv-pct small{{font-size:.42em;letter-spacing:-1px;margin-left:2px}}
.cv-sl{{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;
 color:var(--dim);font-weight:700}}
.cv-sv{{font-size:16px;font-weight:750;color:var(--tx);margin:4px 0 10px}}
.cv-pill{{display:inline-block;border-radius:999px;padding:6px 15px;
 font-size:12.5px;font-weight:800}}
.cv-meta{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px 26px;margin:0}}
.cv-meta div{{min-width:0}}
.cv-meta dt{{font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--dim);font-weight:700}}
.cv-meta dd{{margin:4px 0 0;font-size:14.5px;font-weight:650;color:var(--tx);
 overflow-wrap:anywhere}}
.cv-meta dd.sm{{font-size:12px;font-weight:600;color:var(--mut)}}
.cv-bot{{border-top:1px solid var(--bd);padding-top:22px}}
.cv-tl{{font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--dim);font-weight:700;margin-bottom:9px}}
.cv-toc ol{{margin:0;padding-left:19px;columns:2;column-gap:34px}}
.cv-toc li{{font-size:13px;color:var(--mut);line-height:1.5;margin-bottom:6px;
 break-inside:avoid}}
.cv-note{{margin:20px 0 0;font-size:12px;color:var(--dim);line-height:1.6}}
.cv-go{{margin-top:20px;font:inherit;font-size:13px;font-weight:750;cursor:pointer;
 background:{brand_colour};color:#fff;border:0;border-radius:9px;padding:10px 20px}}
.cv-go:hover{{filter:brightness(.92)}}
body.nocover .cover{{display:none}}
@media(max-width:760px){{
 .cv-cust{{font-size:34px}} .cv-pct{{font-size:64px}}
 .cv-meta{{grid-template-columns:repeat(2,minmax(0,1fr))}}
 .cv-toc ol{{columns:1}}
}}
.conf{{display:inline-flex;gap:7px;align-items:center;background:{SEV_TINT['kritik']};
 border:1px solid {SEV_BDR['kritik']};color:{SEV_TEXT['kritik']};border-radius:8px;
 padding:7px 13px;font-size:11.5px;font-weight:700}}
.strip{{background:var(--pan2);border-top:1px solid var(--bd);border-bottom:1px solid var(--bd);
 padding:16px 0}}
.stats{{display:grid;grid-template-columns:repeat(7,1fr);gap:12px}}
@media(max-width:1160px){{.stats{{grid-template-columns:repeat(4,1fr)}}}}
@media(max-width:740px){{.stats{{grid-template-columns:repeat(2,1fr)}}}}
.st{{all:unset;cursor:pointer;position:relative;display:block;background:var(--pan);
 border:1px solid var(--bd);border-radius:12px;padding:14px 16px 13px;box-shadow:var(--shadow);
 overflow:hidden;transition:.15s;font-family:var(--f)}}
.st:hover{{transform:translateY(-3px);box-shadow:0 6px 18px rgba(15,29,46,.12);border-color:var(--c)}}
.st:focus-visible{{outline:2px solid var(--c);outline-offset:2px}}
.st:before{{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c)}}
.st b{{display:block;font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;
 color:var(--dim);font-weight:700;margin-bottom:6px}}
.st span{{display:block;font-size:29px;font-weight:800;line-height:1;letter-spacing:-1px;
 font-variant-numeric:tabular-nums;color:var(--c)}}
.st small{{display:block;font-size:11.5px;color:var(--mut);font-weight:600;margin-top:4px}}
.st-go{{display:block;font-style:normal;font-size:10.5px;font-weight:700;color:var(--c);
 margin-top:7px;opacity:0;transform:translateY(-3px);transition:.15s}}
.st:hover .st-go{{opacity:1;transform:none}}

nav{{position:sticky;top:0;z-index:40;background:rgba(255,255,255,.95);backdrop-filter:blur(10px);
 border-bottom:1px solid var(--bd);box-shadow:0 1px 3px rgba(15,29,46,.05)}}
.tabs{{display:flex;gap:4px;align-items:center;flex-wrap:wrap}}
.tab{{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:9px;padding:14px 18px;
 color:var(--mut);font-size:14px;font-weight:600;border-bottom:2px solid transparent;transition:.14s}}
.tab:hover{{color:var(--tx)}}
.tab.on{{color:var(--tx);border-bottom-color:var(--acc2)}}
.tab .n{{font-size:11.5px;font-weight:700;background:#EDF2F8;color:var(--mut);
 padding:1px 8px;border-radius:9px}}
.tab.on .n{{background:{SEV_TINT['dusuk']};color:var(--acc)}}
.tab .ic{{width:7px;height:7px;border-radius:2px;background:currentColor;opacity:.5}}
.tab.on .ic{{opacity:1;background:var(--acc2)}}

main{{padding:22px 0 60px}}
.sec{{display:none}} .sec.on{{display:block}}
.panel{{background:var(--pan);border:1px solid var(--bd);border-radius:14px;margin-bottom:16px;
 box-shadow:var(--shadow)}}
.panel.glow{{background:linear-gradient(158deg,{RISK_SOLID}0F,#FFFFFF 62%);border-color:{RISK_SOLID}3D}}
.p-h{{padding:14px 20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;
 gap:12px;flex-wrap:wrap}}
.p-h h3{{margin:0;font-size:14.5px;font-weight:750}}
.p-h .sub{{font-size:12.5px;color:var(--dim)}}
.p-b{{padding:20px}}
.grid-a{{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-bottom:16px;align-items:stretch}}
.grid-a>.panel{{display:flex;flex-direction:column}}
.grid-a>.panel>.p-b{{flex:1;display:flex;flex-direction:column}}
.sdiv.push{{margin-top:auto}}
.grid-b{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
@media(max-width:1060px){{.grid-a,.grid-b{{grid-template-columns:1fr}}}}

.lab{{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);font-weight:700}}
.big{{font-family:var(--fn);font-size:62px;font-weight:800;letter-spacing:-2.6px;
 line-height:1;margin-top:6px;
 font-variant-numeric:tabular-nums}}
.big small{{font-size:27px;font-weight:700;letter-spacing:-1px}}
.prog{{height:10px;background:#E8EEF5;border-radius:6px;overflow:hidden;margin:17px 0 5px}}
.prog span{{display:block;height:100%;border-radius:6px}}
.pl{{display:flex;justify-content:space-between;font-size:11px;color:var(--dim)}}
.pts{{margin-top:14px;font-size:13.5px;color:var(--mut)}} .pts b{{color:var(--tx)}}
.dot{{margin:0 7px;color:var(--dim)}}
.riskpill{{display:inline-flex;margin-top:14px;padding:5px 13px;border-radius:20px;
 font-size:12.5px;font-weight:750;border:1px solid;align-self:flex-start}}
.sdiv{{height:1px;background:var(--bd);margin:18px 0 14px}}
.minicats{{display:grid;gap:11px;margin-top:11px}}
.mc-t{{display:flex;justify-content:space-between;align-items:baseline;font-size:12.5px;
 color:var(--mut);margin-bottom:5px}}
.mc-t b{{font-size:12.5px;font-weight:800}}
.mc-b{{height:7px;background:#E8EEF5;border-radius:4px;overflow:hidden}}
.mc-b span{{display:block;height:100%;border-radius:4px}}
/* Score projection - one compact row per scenario. Deliberately flat and
   short so the score card stops overrunning the executive summary beside it. */
.projrow{{margin-top:9px;border:1px solid var(--bd);border-radius:9px;
 background:var(--pan2);overflow:hidden}}
.pj{{display:flex;align-items:center;justify-content:space-between;gap:10px;
 padding:8px 11px}}
.pj + .pj{{border-top:1px solid var(--bd)}}
.pj-l{{font-size:12.2px;color:var(--mut);font-weight:600;line-height:1.35}}
.pj-r{{display:flex;align-items:baseline;gap:7px;white-space:nowrap}}
.pj-v{{font-size:15.5px;font-weight:800;color:var(--tx);line-height:1}}
.pj-d{{font-size:11.5px;font-weight:700}}
.pj-none{{padding:9px 11px;font-size:12.2px;color:var(--dim)}}
.summary{{font-size:15.5px;line-height:1.68;color:var(--tx);margin:0 0 14px}}
.summary .em{{font-weight:800;font-variant-numeric:tabular-nums}}
.sumlist{{margin:0;padding:0;list-style:none}}
.sumlist li{{position:relative;padding:10px 0 10px 20px;font-size:14.2px;line-height:1.62;
 border-top:1px solid var(--bd);color:var(--mut)}}
.sumlist li:first-child{{border-top:none}}
.sumlist li:before{{content:"";position:absolute;left:0;top:17px;width:7px;height:7px;
 border-radius:50%;background:var(--bd2)}}
.sumlist b{{color:var(--tx)}}
.sumlist .em{{font-weight:800;font-variant-numeric:tabular-nums}}
.nal{{margin:12px 0 0;font-size:12.5px;color:var(--dim)}}
.sevgrid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
@media(max-width:720px){{.sevgrid{{grid-template-columns:repeat(2,1fr)}}}}
.sevcard{{all:unset;cursor:pointer;position:relative;background:var(--b);border:1px solid var(--d);
 border-radius:12px;padding:15px 16px 14px;transition:.15s;overflow:hidden;font-family:var(--f)}}
.sevcard:hover{{transform:translateY(-2px);border-color:var(--s)}}
.sevcard:focus-visible{{outline:2px solid var(--s);outline-offset:2px}}
.sc-bar{{position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--s)}}
.sc-n{{font-size:29px;font-weight:800;color:var(--c);line-height:1}}
.sc-l{{font-size:13px;color:var(--tx);margin-top:4px;font-weight:650}}
.sc-g{{font-size:11.5px;color:var(--c);margin-top:2px;font-weight:700;opacity:.95}}
.stack{{display:flex;height:36px;border-radius:9px;overflow:hidden;margin-bottom:14px}}
.sg{{display:flex;align-items:center;justify-content:center}}
.sg span{{font-size:12.5px;font-weight:800}}
.lg{{display:inline-flex;align-items:center;gap:7px;margin:0 17px 6px 0;font-size:12.5px;color:var(--mut)}}
.lg i{{width:10px;height:10px;border-radius:3px}} .lg b{{color:var(--tx)}}
table{{width:100%;border-collapse:collapse}}
th{{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);font-weight:700;
 text-align:left;padding:11px 15px;border-bottom:1px solid var(--bd);background:var(--pan2)}}
td{{padding:12px 15px;border-bottom:1px solid var(--bd);vertical-align:top;font-size:14px}}
tbody:last-child td{{border-bottom:none}}
.num,th.num{{text-align:right;white-space:nowrap}}
/* ---- Section 4: progress and scope change ---- */
.seclead{{font-size:14.5px;line-height:1.62;color:var(--mut);margin:0 0 16px;max-width:110ch}}
.seclead b{{color:var(--tx)}}
.pkgrid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
.pk{{background:var(--pan2);border:1px solid var(--bd);border-radius:11px;padding:13px 15px}}
.pk-v{{font-size:20px;font-weight:800;color:var(--tx);line-height:1.15;
 letter-spacing:-.4px}}
.pk-l{{font-size:12.2px;color:var(--mut);margin-top:4px;font-weight:600}}
.pk-d{{font-size:12px;font-weight:750;margin-top:3px}}
.pk2{{margin:16px 0}}
.pk2 .pk{{background:var(--pan);text-align:center}}
.pk2 .pk-v{{font-size:28px}}
.pfind{{border-color:{BLUE_BDR}}}
.pfind .p-h{{background:{BLUE_TINT}}}
.pfind-t{{margin:15px 0 0;font-size:14.5px;line-height:1.65;color:var(--tx)}}
.ptbl{{width:100%;border-collapse:collapse;margin:-4px 0}}
.ptbl th{{padding:0 0 8px}}
.ptbl td{{padding:10px 0;border-bottom:1px solid var(--bd)}}
.ptbl tr:last-child td{{border-bottom:0}}
.ptbl td.num,.ptbl th.num{{padding-left:14px;width:1%}}
.pnone{{margin:6px 0;font-size:13px;color:var(--dim)}}
/* ---- Section 5: findings report ---- */
.fndwrap{{max-width:980px}}
.bulgu{{background:var(--pan);border:1px solid var(--bd);border-radius:11px;
 overflow:hidden;margin-bottom:20px;box-shadow:var(--shadow);break-inside:avoid}}
.b-h{{color:#fff;font-size:15.5px;font-weight:750;padding:12px 16px;line-height:1.42}}
.b-n{{font-weight:800;opacity:.82;margin-right:8px}}
.b-sev{{padding:7px 16px;font-size:13.5px;font-weight:800;letter-spacing:.01em}}
.b-t{{width:100%;border-collapse:collapse}}
.b-t th{{width:176px;text-align:left;vertical-align:top;padding:12px 16px;
 background:var(--pan2);border-bottom:1px solid var(--bd);border-right:1px solid var(--bd);
 font-size:13.5px;font-weight:750;color:var(--tx)}}
.b-t td{{padding:12px 16px;border-bottom:1px solid var(--bd);font-size:14px;
 vertical-align:top;line-height:1.62}}
.b-t tr:last-child th,.b-t tr:last-child td{{border-bottom:0}}
.b-t p{{margin:0 0 9px}} .b-t p:last-child{{margin-bottom:0}}
.b-m{{color:var(--dim);font-size:12.5px}}
.fn-gap{{color:var(--dim);font-size:12.5px;font-style:italic}}
/* ---- Findings front matter ---- */
.fnd-intro{{margin-bottom:22px}}
.fi-h{{margin:22px 0 8px;font-size:16px;font-weight:800;color:{SEV_TEXT['kritik']}}}
.fi-h:first-child{{margin-top:0}}
.fi-p{{margin:0;font-size:14.5px;line-height:1.68;color:var(--tx);max-width:104ch}}
.rptbl{{margin-top:15px;border:1px solid var(--bd2);border-radius:10px;overflow:hidden}}
.rp-r{{display:flex;align-items:stretch;border-bottom:1px solid var(--bd)}}
.rp-r:last-child{{border-bottom:0}}
.rp-c{{flex:none;width:118px;display:flex;flex-direction:column;align-items:center;
 justify-content:center;padding:14px 8px;text-align:center;color:#FFFFFF}}
/* Identical treatment for all four: same face, size, weight, colour, no
   shadow. The fill is the only thing that differs between bands. */
.rp-n{{font-family:var(--fn);font-size:30px;font-weight:800;line-height:1;
 color:#FFFFFF;text-shadow:none;letter-spacing:-.5px}}
.rp-l{{font-size:12.5px;font-weight:800;margin-top:3px;letter-spacing:.01em;
 color:#FFFFFF;text-shadow:none}}
.rp-d{{padding:14px 17px;font-size:14px;line-height:1.6;display:flex;align-items:center}}
.fi-tot{{margin:13px 0 0;font-size:13px;color:var(--mut)}}
.fi-tot b{{font-size:15px;color:var(--tx)}}
.fi-act{{margin-top:20px;padding-top:17px;border-top:1px solid var(--bd);
 display:flex;align-items:center;gap:13px;flex-wrap:wrap}}
.fi-hint{{font-size:12px;color:var(--dim);line-height:1.5;max-width:52ch}}
@media(max-width:620px){{.rp-c{{width:92px}}}}
@media print{{ .fi-act{{display:none!important}} }}
@media(max-width:720px){{
 .b-t,.b-t tbody,.b-t tr,.b-t th,.b-t td{{display:block;width:auto}}
 .b-t th{{border-right:0;border-bottom:0;padding-bottom:2px}}
}}
@media print{{ .bulgu{{border-color:#bbb;box-shadow:none}} }}
.pnote{{margin:14px 0 0;font-size:12.2px;color:var(--dim);line-height:1.6}}
/* ---- Owner / due-date assignment ---- */
.dbox.asg{{min-width:230px}}
.af{{display:block;margin-bottom:10px}}
.af>span{{display:block;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
 color:var(--dim);font-weight:700;margin-bottom:4px}}
.af input{{width:100%;font:inherit;font-size:13px;padding:7px 10px;color:var(--tx);
 background:var(--pan);border:1px solid var(--bd2);border-radius:8px}}
.af input:focus{{outline:2px solid {BLUE};outline-offset:1px;border-color:{BLUE}}}
.ahint{{margin:0;font-size:11px;color:var(--dim);line-height:1.5}}
.abadge{{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}}
.abadge span{{font-size:11px;font-weight:700;border-radius:999px;padding:2px 9px;
 background:{BLUE_TINT};color:{BLUE_T};border:1px solid {BLUE_BDR}}}
.abadge .late{{background:{SEV_TINT['kritik']};color:{SEV_TEXT['kritik']};
 border-color:{SEV_BDR['kritik']}}}
/* ---- Export panel ---- */
.expwrap{{position:relative;display:inline-block}}
.btn-p{{background:{BLUE};border-color:{BLUE};color:#fff}}
.btn-p:hover{{background:#005A9C;border-color:#005A9C}}
.exppop{{position:absolute;z-index:40;top:calc(100% + 7px);left:0;width:288px;
 background:var(--pan);border:1px solid var(--bd2);border-radius:12px;padding:14px 15px;
 box-shadow:0 8px 28px rgba(15,29,46,.16)}}
.ep-h{{font-size:13px;font-weight:750;margin-bottom:10px}}
.ep-s{{font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--dim);
 font-weight:700;margin:12px 0 6px}}
.ep-s:first-of-type{{margin-top:0}}
.ep-o{{display:flex;align-items:center;gap:9px;padding:5px 0;font-size:13px;cursor:pointer}}
.ep-o input{{margin:0;flex:none;accent-color:{BLUE};width:15px;height:15px}}
.ep-o b{{color:var(--dim);font-weight:700}}
.ep-b{{display:flex;gap:8px;margin-top:14px}}
.ep-b .btn{{flex:1;justify-content:center;text-align:center}}
.ep-hint{{margin:9px 0 0;font-size:11px;color:var(--dim);line-height:1.5}}
@media print{{ .af input{{border:1px solid #999}} }}
.p-h .n{{font-size:11.5px;font-weight:700;background:#EDF2F8;color:var(--mut);
 border-radius:999px;padding:2px 9px;margin-left:auto}}
@media(max-width:900px){{.pkgrid{{grid-template-columns:repeat(2,1fr)}}}}

.bcell{{width:36%}}
.bar{{height:8px;background:#E8EEF5;border-radius:5px;overflow:hidden}}
.bar span{{display:block;height:100%;border-radius:5px}}
.fs{{font-size:11.5px;color:var(--dim);margin-top:3px}}
.ft{{font-weight:650;color:var(--tx);line-height:1.42}}
.tgrid{{display:grid;gap:11px}}
.tcard{{background:var(--pan);border:1px solid var(--bd);border-left:3px solid var(--c);
 border-radius:10px;padding:12px 14px}}
.tc-h{{display:flex;align-items:center;gap:11px;margin-bottom:6px}}
.tc-g{{font-size:19px;font-weight:800;color:{SEV_TEXT['dusuk']}}}
.tc-t{{font-weight:650;font-size:13.5px;line-height:1.4}}
.pill{{display:inline-flex;align-items:center;gap:6px;padding:3px 11px;border-radius:8px;
 font-size:11.5px;font-weight:750;border:1px solid;white-space:nowrap}}
.pill i{{width:6px;height:6px;border-radius:50%}}
.tag{{display:inline-block;margin-top:5px;margin-right:4px;padding:2px 8px;border-radius:7px;
 font-size:10.5px;font-weight:700;border:1px solid}}
.minipill{{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;
 font-weight:700;border:1px solid;margin-left:7px}}
.minipill.neutral{{color:var(--mut);background:var(--pan2);border-color:var(--bd2)}}
.cbadge{{display:inline-block;padding:2px 10px;border-radius:7px;font-size:11.5px;font-weight:650;
 color:var(--mut);background:var(--pan2);border:1px solid var(--bd)}}
.sev{{display:inline-flex;align-items:center;gap:9px;font-size:12.5px;font-weight:700;white-space:nowrap}}
.dots{{display:inline-flex;gap:3px;align-items:center}}
.dots i{{height:7px;border-radius:4px;display:block}}
.toolbar{{background:var(--pan);border:1px solid var(--bd);border-radius:14px 14px 0 0;
 border-bottom:none;padding:15px 20px}}
.tb-1{{display:flex;gap:11px;align-items:center;flex-wrap:wrap}}
.srch{{flex:1 1 260px;min-width:200px;display:flex;align-items:center;gap:9px;background:var(--pan2);
 border:1px solid var(--bd2);border-radius:9px;padding:0 13px}}
.srch span{{color:var(--dim);font-size:16px}}
.srch input{{flex:1;background:none;border:none;outline:none;color:var(--tx);font:14px var(--f);
 padding:10px 0}}
.sel,.btn{{background:var(--pan2);border:1px solid var(--bd2);border-radius:9px;color:var(--tx);
 font:13px var(--f);padding:10px 13px;cursor:pointer}}
.btn:hover,.sel:hover{{border-color:var(--acc2)}}
.cnt{{margin-left:auto;font-size:12.5px;color:var(--dim);white-space:nowrap}}
.tb-2{{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:13px}}
.tb-l{{font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--dim);
 font-weight:700;margin-right:3px}}
.tb-sep{{width:1px;height:18px;background:var(--bd2);margin:0 7px}}
.chip{{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:7px;background:var(--pan2);
 border:1px solid var(--bd2);border-radius:8px;padding:5px 12px;font-size:12.5px;color:var(--mut);
 transition:.13s;font-family:var(--f)}}
.chip i{{width:7px;height:7px;border-radius:50%}}
.chip b{{font-size:11.5px;color:var(--dim);font-weight:700}}
.chip:hover{{border-color:var(--c);color:var(--tx)}}
.chip.on{{background:var(--c);border-color:var(--c);color:var(--ink,#fff);font-weight:750}}
.chip.on b{{color:var(--ink,#fff);opacity:.82}}
.chip:focus-visible{{outline:2px solid var(--c);outline-offset:2px}}
.regnote{{background:{SEV_TINT['yuksek']};border:1px solid {SEV_BDR['yuksek']};border-top:none;
 padding:11px 20px;font-size:13px;color:{SEV_TEXT['yuksek']};display:flex;
 align-items:center;gap:10px;flex-wrap:wrap}}
.regnote b{{color:{SEV_INK['yuksek']}}}
.rn-x{{all:unset;cursor:pointer;margin-left:auto;font-size:12px;font-weight:700;
 color:{SEV_TEXT['yuksek']};border-bottom:1px solid currentColor;font-family:var(--f)}}
.tblwrap{{background:var(--pan);border:1px solid var(--bd);border-radius:0 0 14px 14px;overflow:hidden}}
.find tbody.grp tr.r{{cursor:pointer}}
.find tbody.grp:hover tr.r td{{background:#F5F9FD}}
.find tbody.grp.open tr.r td{{background:{BLUE_TINT}}}
.c-st{{width:190px}} .c-cat{{width:112px}} .c-pt{{width:96px;color:var(--tx)}}
.c-gn{{width:78px;font-weight:800;color:{SEV_TEXT['dusuk']}}} .c-sv{{width:136px}}
.c-ch{{width:34px;text-align:right}}
.chev{{color:var(--dim);font-size:19px;line-height:1;display:inline-block;transition:.15s}}
tbody.grp.open .chev{{transform:rotate(90deg);color:var(--acc2)}}
tr.det td{{background:var(--pan2);padding:0;border-top:1px solid var(--bd)}}
.dwrap{{display:grid;grid-template-columns:340px 1fr;gap:15px;padding:17px 20px 20px}}
@media(max-width:900px){{.dwrap{{grid-template-columns:1fr}}}}
.dbox{{background:var(--pan);border:1px solid var(--bd);border-radius:10px;padding:15px 17px}}
.dbox h5{{margin:0 0 11px;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
 color:var(--dim);font-weight:700}}
.dbox dl{{margin:0;display:grid;grid-template-columns:auto 1fr;gap:7px 15px;font-size:13px}}
.dbox dt{{color:var(--dim)}} .dbox dd{{margin:0;color:var(--tx);font-weight:650}}
.dbox p{{margin:0;font-size:13.5px;line-height:1.65;color:var(--mut)}}
.dimp,.dnote{{margin-top:11px!important;padding-top:10px;border-top:1px dashed var(--bd);
 font-size:12.5px!important;color:var(--dim)!important}}
.dimp b,.dnote b{{color:var(--mut)}}
.dl{{display:inline-block;margin-top:12px;font-size:13px;font-weight:700}}
.empty{{padding:52px;text-align:center;color:var(--dim)}}
.more{{color:var(--dim);font-size:12.5px;font-style:italic}}
.lgrid{{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}}
@media(max-width:860px){{.lgrid{{grid-template-columns:1fr}}}}
.lg-i p{{margin:8px 0 0;font-size:13px;line-height:1.6;color:var(--mut)}}
.lg-i p b{{color:var(--tx)}}
.intro{{background:linear-gradient(140deg,{SEV_TINT['dusuk']},#F8FCFA 55%,var(--pan));
 border-color:{SEV_BDR['dusuk']}}}
.in-k{{font-size:9.5px;letter-spacing:.15em;text-transform:uppercase;color:var(--acc);font-weight:800}}
.in-h{{margin:7px 0 10px;font-size:20px;font-weight:800;letter-spacing:-.35px;line-height:1.3;
 color:var(--tx);max-width:860px}}
.in-p{{margin:0 0 18px;font-size:14.5px;line-height:1.65;color:var(--mut);max-width:900px}}
.in-p b{{color:var(--tx)}}
.in-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:13px}}
@media(max-width:1040px){{.in-grid{{grid-template-columns:repeat(2,1fr)}}}}
@media(max-width:640px){{.in-grid{{grid-template-columns:1fr}}}}
.in-c{{display:flex;gap:11px;background:var(--pan);border:1px solid var(--bd);border-radius:11px;
 padding:13px 14px}}
.in-n{{flex:none;width:24px;height:24px;border-radius:7px;background:{SEV_SOLID['dusuk']};
 color:{SEV_INK['dusuk']};
 font-size:12.5px;font-weight:800;display:flex;align-items:center;justify-content:center}}
.in-c b{{display:block;font-size:13.5px;color:var(--tx);margin-bottom:3px}}
.in-c p{{margin:0;font-size:12.5px;line-height:1.55;color:var(--mut)}}
.in-note{{margin:16px 0 0;padding:12px 15px;background:var(--pan);border:1px solid var(--bd);
 border-left:3px solid var(--acc2);border-radius:9px;font-size:13.5px;color:var(--mut)}}
.in-note b{{color:var(--acc);font-weight:800}}
.phase .ph-h{{border-left:3px solid var(--c);border-radius:14px 0 0 0}}
.ph-badge{{display:inline-block;padding:4px 13px;border-radius:8px;font-size:12.5px;
 font-weight:800;letter-spacing:.02em}}
.ph-when{{font-size:14px;font-weight:750;color:var(--tx)}}
.ph-sum{{margin-left:auto}} .ph-n{{width:36px;color:var(--dim)}}
.spark{{width:100%;height:185px;display:block}}
.method p{{margin:0 0 11px;font-size:13.5px}}
.method ul{{margin:0 0 11px;padding-left:20px;font-size:13.5px;line-height:1.85;color:var(--mut)}}
.method li b{{color:var(--tx)}}
footer{{padding:24px 0 0;color:var(--dim);font-size:11.5px;text-align:center}}
@media print{{
 nav,.toolbar,.chev,.c-ch,.st-go{{display:none!important}}
 /* Page box. The browser's own header/footer (URL, date, page numbers) is a
    browser print setting we cannot switch off from CSS - the margin here keeps
    the content clear of it, and the help text tells the user how to turn it
    off in the dialog. */
 @page{{margin:14mm 12mm}}
 body{{background:#fff;color:#000}} header{{background:#fff}}
 /* Keep colour fills and their ink - otherwise the risk-posture numerals and
    card headers print as black on white and lose their meaning. */
 .b-h,.b-sev,.rp-c,.rp-n,.rp-l,.riskpill,.cv-pill,.sg span,.sevcard .sc-bar{{
  -webkit-print-color-adjust:exact;print-color-adjust:exact}}
 .rp-c *{{color:inherit}}
 .sec{{display:block!important;break-after:page}}
 /* "filtered only" export: print just the open section and skip hidden rows */
 body.pr-sec .sec:not(.on){{display:none!important}}
 body.pr-sec nav,body.pr-sec .toolbar{{display:none!important}}
 tbody.grp[hidden]{{display:none!important}}
 .exppop{{display:none!important}}
 /* The cover always prints as page one, even if it was dismissed on screen. */
 .cover{{display:flex!important;min-height:auto;height:96vh;break-after:page;
  background:#fff;border-bottom:0}}
 .cv-go{{display:none!important}}
 /* Findings-only PDF: EXACTLY what the findings section shows on screen -
    no cover, no report header, no nav, no footer, no lead paragraph. The
    customer receives the findings document and nothing around it. */
 body.pr-fnd header,body.pr-fnd nav,body.pr-fnd footer,
 body.pr-fnd .toolbar,body.pr-fnd .cover,
 body.pr-fnd #s-bulgu > .seclead{{display:none!important}}
 body.pr-fnd .sec:not(#s-bulgu){{display:none!important}}
 body.pr-fnd #s-bulgu{{display:block!important;padding:0!important}}
 body.pr-fnd main,body.pr-fnd .wrap{{padding:0!important;margin:0!important;
  max-width:none!important}}
 body.pr-fnd .fnd-intro{{break-after:page;margin-bottom:0}}
 /* Nothing in the findings section may be clipped, collapsed or scrolled away
    when printing - the PDF must carry every word and every card. */
 body.pr-fnd #s-bulgu,body.pr-fnd .fndwrap,body.pr-fnd .bulgu,
 body.pr-fnd .fnd-intro{{overflow:visible!important;max-height:none!important}}
 body.pr-fnd .fndwrap{{max-width:none!important}}
 body.pr-fnd .b-t,body.pr-fnd .b-t tr,body.pr-fnd .b-t td,
 body.pr-fnd .b-t th{{overflow:visible!important}}
 body.pr-fnd [hidden]:not(tr.det){{display:revert}}
 .b-h,.b-sev,.rp-c{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
 .bulgu{{break-inside:avoid;page-break-inside:avoid}}
 .rp-r{{break-inside:avoid}}
 .panel{{background:#fff;border-color:#bbb;box-shadow:none}}
 tr.det{{display:table-row!important}}
 tbody.grp,tr.r,tr.det,.panel,.tcard{{break-inside:avoid}}
 .pill,.tag,.minipill{{border-width:1.5px}}
 a[href^="http"]::after{{content:" (" attr(href) ")";font-size:9px;color:#555}}
}}
</style></head><body>

<!-- Cover page: the branded first impression when the report is handed to a
     customer or printed to PDF. Always its own printed page; on screen it can
     be skipped with the button. -->
<section class="cover" id="cover">
  <div class="cv-in">
    <div class="cv-top">
      {f'<div class="cv-logo"><img src="{brand_logo}" alt=""></div>' if brand_logo
        else f'<div class="cv-mark">{e(t["mark"])}</div>'}
      <div class="cv-conf">🔒 {e(t['cov_conf'])}</div>
    </div>

    <div class="cv-mid">
      <div class="cv-kicker">{e(t['cov_title'])}</div>
      <h1 class="cv-cust">{e(customer)}</h1>
      <div class="cv-rule"></div>

      <div class="cv-score">
        <div class="cv-pct" style="color:{RISK_BIG}">{pct:.1f}<small>%</small></div>
        <div class="cv-sd">
          <div class="cv-sl">{e(t['cov_score'])}</div>
          <div class="cv-sv mono">{score:.1f} / {maxs:.0f} {e(t['points'])}</div>
          <div class="cv-pill" style="background:{RISK_SOLID};color:{RISK_INK}">
            ● {e(t['cov_risk'])}: {e(risk_text)}</div>
        </div>
      </div>

      <dl class="cv-meta">
        <div><dt>{e(t['cov_prepared_for'])}</dt><dd>{e(customer)}</dd></div>
        {f"<div><dt>{e(t['cov_prepared_by'])}</dt><dd>{e(provider)}</dd></div>" if provider else ''}
        <div><dt>{e(t['cov_date'])}</dt><dd>{e(generated)}</dd></div>
        <div><dt>{e(t['cov_tenant'])}</dt>
          <dd class="mono sm">{e(str(tenant.get('id') or '—'))}</dd></div>
        {f"<div><dt>{e(t['cov_domain'])}</dt><dd>{e(tenant_domain(tenant))}</dd></div>" if tenant_domain(tenant) else ''}
        <div><dt>{e(t['cov_scope'])}</dt>
          <dd>{e(t['cov_scope_v'].format(n=res['applicableCount']))}</dd></div>
      </dl>
    </div>

    <div class="cv-bot">
      <div class="cv-toc">
        <div class="cv-tl">{e(t['cov_contents'])}</div>
        <ol>
          <li>{e(t['cov_c1'])}</li><li>{e(t['cov_c2'])}</li>
          <li>{e(t['cov_c3'])}</li><li>{e(t['cov_c4'])}</li>
          <li>{e(t['cov_c5'])}</li>
        </ol>
      </div>
      <p class="cv-note">{e(t['cov_method'])}</p>
      <button class="cv-go" id="cvgo">{e(t['cov_open'])}</button>
    </div>
  </div>
</section>

<header><div class="wrap">
  <div class="h-top">
    {f'<div class="mark logo"><img src="{brand_logo}" alt=""></div>' if brand_logo
      else f'<div class="mark">{e(t["mark"])}</div>'}
    <div><div class="cust">{e(customer)}</div>
      <div class="tsub">{e(t['title'])} · {e(generated)}</div>
      <div class="hmeta">
        <span class="hm"><b>{e(t['tenant_id'])}</b>
          <span class="mono">{e(str(tenant.get('id') or '—'))}</span></span>
        {f'<span class="hm"><b>{e(t["domain"])}</b><span>{e(tenant_domain(tenant))}</span></span>' if tenant_domain(tenant) else ''}
      </div></div>
    <div class="hright"><div class="conf">🔒 {e(t['classification'])}</div>
      {f'<div class="prov">{e(t["prepared_by"])}: <b>{e(provider)}</b></div>' if provider else ''}
    </div>
  </div>
</div>
<div class="strip"><div class="wrap"><div class="stats">
  <button class="st" data-go="genel" style="--c:{RISK_SOLID}"><b>{e(t['score'])}</b>
    <span>%{pct:.1f}</span><small>{score:.1f} / {maxs:.0f} {e(t["points"])}</small>
    <em class="st-go">{e(t['go_overview'])} ↗</em></button>
  <button class="st" data-go="all" style="--c:{BLUE}"><b>{e(t['applicable'])}</b>
    <span>{res['applicableCount']}</span><small>{e(t['action_unit'])}</small>
    <em class="st-go">{e(t['go_all'])} ↗</em></button>
  <button class="st" data-go="acik" style="--c:{SEV_SOLID['kritik']}"><b>{e(t['open_short'])}</b>
    <span>{len(open_c)}</span><small>{e(t['to_address']).lower()}</small>
    <em class="st-go">{e(t['go_list'])} ↗</em></button>
  <button class="st" data-go="tamam" style="--c:{SEV_SOLID['dusuk']}"><b>{e(t['completed'])}</b>
    <span>{len(done_c)}</span><small>{e(t['applied_control'])}</small>
    <em class="st-go">{e(t['go_list'])} ↗</em></button>
  <button class="st" data-go="kritik" style="--c:{SEV_SOLID['kritik']}"><b>{e(t['sev_kritik'])}</b>
    <span>{sev_open.get(SEV_KRITIK, 0)}</span><small>{e(t['urgent'])}</small>
    <em class="st-go">{e(t['go_list'])} ↗</em></button>
  <button class="st" data-go="regres" style="--c:{SEV_SOLID['yuksek']}"><b>{e(t['regressed'])}</b>
    <span>{len(regressed)}</span><small>{e(t['point_loss'])}</small>
    <em class="st-go">{e(t['go_list'])} ↗</em></button>
  <button class="st" data-go="yol" style="--c:{SEV_SOLID['dusuk']}"><b>{e(t['gainable'])}</b>
    <span>+{gap:.0f}</span><small>{e(t['point_potential'])}</small>
    <em class="st-go">{e(t['go_roadmap'])} ↗</em></button>
</div></div></div>
</header>

<nav><div class="wrap"><div class="tabs">
  <button class="tab on" data-sec="s-genel"><span class="ic"></span>{e(t['nav_overview'])}</button>
  <button class="tab" data-sec="s-islemler"><span class="ic"></span>{e(t['all_actions'])}
    <span class="n">{res['applicableCount']}</span></button>
  <button class="tab" data-sec="s-yol"><span class="ic"></span>{e(t['nav_roadmap'])}
    <span class="n">{len(open_c)}</span></button>
  <button class="tab" data-sec="s-ilerleme"><span class="ic"></span>{e(t['nav_progress'])}</button>
  <button class="tab" data-sec="s-bulgu"><span class="ic"></span>{e(t['nav_findings'])}
    <span class="n">{len(open_c)}</span></button>
</div></div></nav>

<main><div class="wrap">

<section id="s-genel" class="sec on">
  <div class="grid-a">
    <div class="panel glow"><div class="p-b">
      <div class="lab">{e(t['score'])}</div>
      <div class="big" style="color:{RISK_BIG}">{pct:.1f}<small>%</small></div>
      <div class="prog"><span style="width:{min(100.0, pct):.1f}%;background:{RISK_SOLID}"></span></div>
      <div class="pl"><span>0%</span><span>100%</span></div>
      <div class="pts"><b class="mono">{score:.1f}</b> / {maxs:.0f} {e(t['points'])}
        <span class="dot">·</span><b class="mono" style="color:{SEV_TEXT['dusuk']}">+{gap:.0f}</b>
        {e(t['gap_short'])}</div>
      <div class="riskpill" style="background:{RISK_SOLID};border-color:{RISK_SOLID};
        color:{RISK_INK}">● {e(t['risk'])}: {e(risk_text)}</div>
      <div class="sdiv"></div>
      <div class="lab">{e(t['cat_dist'])}</div>
      <div class="minicats">{mini_cats}</div>
      {f'<div class="sdiv push"></div><div class="lab">{e(t["projection"])}</div><div class="projrow">{bench_html}</div>' if bench_html else ''}
    </div></div>

    <div class="panel">
      <div class="p-h"><h3>{e(t['summary'])}</h3></div>
      <div class="p-b">
        <p class="summary">{summary_lead}</p>
        <ul class="sumlist">{"".join(f"<li>{b}</li>" for b in bullets)}</ul>
        {f'<p class="nal">{e(na_line)}</p>' if na_line else ''}
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="p-h"><h3>{e(t['sev_open_title'])}</h3>
      <span class="sub">{e(t['sev_open_hint'])}</span></div>
    <div class="p-b"><div class="sevgrid">{sev_cards}</div></div>
  </div>

  <div class="panel">
    <div class="p-h"><h3>{e(t['status_dist'])}</h3></div>
    <div class="p-b"><div class="stack" role="img"
      aria-label="{e(t['status_dist'])}">{stack}</div><div>{legend}</div></div>
  </div>

  <div class="grid-b">
    <div class="panel"><div class="p-h"><h3>{e(t['categories'])}</h3></div>
      <table class="cats"><tbody>{cat_rows}</tbody></table></div>
    <div class="panel"><div class="p-h"><h3>{e(t['top5'])}</h3>
      <span class="sub">{e(t['by_severity'])}</span></div>
      <div class="p-b"><div class="tgrid">{top_cards}</div></div></div>
  </div>
  {trend}
</section>

<section id="s-islemler" class="sec">
  <div class="toolbar">
    <div class="tb-1">
      <div class="srch"><span>⌕</span>
        <input id="q" type="search" placeholder="{e(t['search'])}" aria-label="{e(t['search'])}"></div>
      <select id="sort" class="sel" aria-label="{e(t['sort'])}">
        <option value="sev">{e(t['sort_sev'])}</option>
        <option value="gain">{e(t['sort_gain'])}</option>
        <option value="title">{e(t['sort_title'])}</option>
      </select>
      <button class="btn" id="expand">{e(t['expand_all'])}</button>
      <div class="expwrap">
        <button class="btn btn-p" id="exp" aria-haspopup="true" aria-expanded="false">
          {e(t['exp_btn'])} ▾</button>
        <div class="exppop" id="exppop" hidden role="dialog"
             aria-label="{e(t['exp_title'])}">
          <div class="ep-h">{e(t['exp_title'])}</div>
          <div class="ep-s">{e(t['exp_scope'])}</div>
          <label class="ep-o"><input type="radio" name="epsc" value="f" checked>
            <span>{e(t['exp_filtered'])} <b id="epn"></b></span></label>
          <label class="ep-o"><input type="radio" name="epsc" value="a">
            <span>{e(t['exp_all'])}</span></label>
          <div class="ep-s">{e(t['exp_cols'])}</div>
          <label class="ep-o"><input type="checkbox" id="epa" checked>
            <span>{e(t['asg_export'])}</span></label>
          <label class="ep-o"><input type="checkbox" id="epn2">
            <span>{e(t['exp_notes'])}</span></label>
          <label class="ep-o"><input type="checkbox" id="eps">
            <span>{e(t['exp_steps'])}</span></label>
          <div class="ep-b">
            <button class="btn btn-p" id="epcsv">{e(t['exp_csv'])}</button>
            <button class="btn" id="eppdf">{e(t['exp_pdf'])}</button>
          </div>
          <p class="ep-hint">{e(t['exp_pdf_hint'])}</p>
        </div>
      </div>
      <button class="btn" id="asgc">{e(t['asg_clear'])}</button>
      <button class="btn" id="clear">{e(t['reset'])}</button>
      <span class="cnt" id="cnt"></span>
    </div>
    <div class="tb-2">
      <span class="tb-l">{e(t['col_status'])}</span>{st_chips}
      <span class="tb-sep"></span>
      <span class="tb-l">{e(t['sev_short'])}</span>{sv_chips}
      <span class="tb-sep"></span>
      <span class="tb-l">{e(t['col_category'])}</span>{cat_chips}
    </div>
  </div>
  <div class="regnote" id="regnote" hidden>
    <b>{e(t['regressed'])}</b> {e(t['reg_banner'])}
    <button class="rn-x" onclick="document.getElementById('clear').click()">{e(t['reg_clear'])}</button>
  </div>
  <div class="tblwrap">
    <table class="find"><thead><tr>
      <th>{e(t['col_status'])}</th><th>{e(t['col_action'])}</th><th>{e(t['col_category'])}</th>
      <th class="num">{e(t['col_points'])}</th><th class="num">{e(t['col_gain'])}</th>
      <th>{e(t['sev_label'])}</th><th></th>
    </tr></thead>{rows}</table>
    <div class="empty" id="none" hidden>{e(t['no_items'])}</div>
  </div>

  <div class="panel" style="margin-top:16px">
    <div class="p-h"><h3>{e(t['legend_title'])}</h3></div>
    <div class="p-b"><div class="lgrid">
      <div class="lg-i"><span class="pill" style="color:{ST_TEXT[S_TOADDRESS]};
        background:{ST_TINT[S_TOADDRESS]};border-color:{ST_BDR[S_TOADDRESS]}">
        <i style="background:{ST_SOLID[S_TOADDRESS]}"></i>{e(t[S_TOADDRESS])}</span>
        <p>{e(t['legend_open'])}</p></div>
      <div class="lg-i"><span class="tag" style="color:{SEV_TEXT['orta']};
        background:{SEV_TINT['orta']};border-color:{SEV_BDR['orta']}">{e(t['partial'])}</span>
        <p>{e(t['legend_partial'])}</p></div>
      <div class="lg-i"><span class="pill" style="color:{ST_TEXT[S_COMPLETED]};
        background:{ST_TINT[S_COMPLETED]};border-color:{ST_BDR[S_COMPLETED]}">
        <i style="background:{ST_SOLID[S_COMPLETED]}"></i>{e(t[S_COMPLETED])}</span>
        <p>{e(t['legend_done'])}</p></div>
      <div class="lg-i"><span class="tag" style="color:{SEV_TEXT['yuksek']};
        background:{SEV_TINT['yuksek']};border-color:{SEV_BDR['yuksek']}">↓ {e(t['regressed'])}</span>
        <p>{e(t['legend_reg'])} {t['legend_reg_n'].format(n=len(regressed))}</p></div>
    </div></div>
  </div>
</section>

<section id="s-yol" class="sec">
  <div class="panel intro"><div class="p-b">
    <div class="in-k">{e(t['purpose'])}</div>
    <h2 class="in-h">{e(t['road_h'])}</h2>
    <p class="in-p">{t['road_p'].format(n=f'<b>{len(open_c)}</b>')}</p>
    <div class="in-grid">
      <div class="in-c"><div class="in-n">1</div><div><b>{e(t['road_1h'])}</b>
        <p>{e(t['road_1p'])}</p></div></div>
      <div class="in-c"><div class="in-n">2</div><div><b>{e(t['road_2h'])}</b>
        <p>{e(t['road_2p'])}</p></div></div>
      <div class="in-c"><div class="in-n">3</div><div><b>{e(t['road_3h'])}</b>
        <p>{e(t['road_3p'])}</p></div></div>
      <div class="in-c"><div class="in-n">4</div><div><b>{e(t['road_4h'])}</b>
        <p>{e(t['road_4p'])}</p></div></div>
    </div>
    <p class="in-note">{t['road_note'].format(target=f'<b>%{target_pct:.0f}</b>', gap=f'{gap:.0f}')}</p>
  </div></div>

  <div class="panel"><div class="p-h"><h3>{e(t['expected'])}</h3>
    <span class="sub">{e(t['as_phases'])}</span></div>
    <div class="p-b"><svg viewBox="-14 -28 {w+40} {h+52}" class="spark" style="height:215px"
      role="img" aria-label="{e(t['expected'])}">
      <line x1="0" y1="{h}" x2="{w}" y2="{h}" stroke="#E2E9F2"/>
      <polyline points="{line}" fill="none" stroke="{SEV_SOLID['dusuk']}" stroke-width="3"
        stroke-linejoin="round" stroke-linecap="round"/>{dots}{labels}{xlab}
    </svg></div></div>
  {blocks}

  <div class="panel"><div class="p-h"><h3>{e(t['sev_how'])}</h3></div>
    <div class="p-b method">
      <p>{e(t['sev_how_p'])}</p>
      <ul><li><b>{e(t['sev_f1'])}</b> — {e(t['sev_f1d'])}</li>
        <li><b>{e(t['sev_f2'])}</b> — {e(t['sev_f2d'])}</li>
        <li><b>{e(t['sev_f3'])}</b> — {e(t['sev_f3d'])}</li>
        <li><b>{e(t['sev_f4'])}</b> — {e(t['sev_f4d'])}</li>
        <li><b>{e(t['sev_f5'])}</b> — {e(t['sev_f5d'])}</li></ul>
      <p class="mut">{e(t['sev_how_note'])}</p>
    </div></div>

  <div class="panel"><div class="p-h"><h3>{e(t['method'])}</h3></div>
    <div class="p-b method"><ul>
      <li>{e(t['m1'])}</li><li>{e(t['m2'])}</li><li>{e(t['m3'])}</li>
      <li>{e(t['m4'])}</li><li>{e(t['m5'])}</li><li>{e(t['m6'])}</li>
    </ul></div></div>
</section>

<section id="s-ilerleme" class="sec">
  <p class="seclead">{t['prog_lead']}</p>
  {prog_html}
</section>

<section id="s-bulgu" class="sec">
  <p class="seclead">{t['fnd_lead']}</p>
  <div class="fndwrap">{fnd_intro}{fnd_cards}</div>
</section>

<footer>{e(t['prepared_for'])}: <b>{e(customer)}</b>{f' · {e(t["prepared_by"])}: <b>{e(provider)}</b>' if provider else ''}<br>{e(t['footer'])}</footer>
</div></main>

<script>
var state={{q:'',status:null,sev:null,cat:null,reg:false}};
var groups=[].slice.call(document.querySelectorAll('tbody.grp'));

function show(id){{
  document.querySelectorAll('.sec').forEach(function(s){{s.classList.toggle('on',s.id===id);}});
  document.querySelectorAll('.tab').forEach(function(x){{x.classList.toggle('on',x.dataset.sec===id);}});
  window.scrollTo({{top:0,behavior:'smooth'}});
}}
document.querySelectorAll('.tab').forEach(function(x){{
  x.addEventListener('click',function(){{ show(x.dataset.sec); }}); }});

function resetFilters(){{
  state={{q:'',status:null,sev:null,cat:null,reg:false}};
  var qi=document.getElementById('q'); if(qi) qi.value='';
  document.querySelectorAll('.chip').forEach(function(x){{x.classList.remove('on');}});
  document.getElementById('regnote').hidden=true;
}}
document.querySelectorAll('.st[data-go]').forEach(function(b){{
  b.addEventListener('click',function(){{
    var go=b.dataset.go;
    if(go==='genel'){{ show('s-genel'); return; }}
    if(go==='yol'){{ show('s-yol'); return; }}
    resetFilters(); show('s-islemler');
    if(go==='all'){{ apply(); }}
    else if(go==='acik'){{ setChip('status','{S_TOADDRESS}'); }}
    else if(go==='tamam'){{ setChip('status','{S_COMPLETED}'); }}
    else if(go==='kritik'){{ setChip('sev','kritik','{S_TOADDRESS}'); }}
    else if(go==='regres'){{ state.reg=true;
      document.getElementById('regnote').hidden=false; apply(); }}
  }}); }});
document.querySelectorAll('.sevcard').forEach(function(b){{
  b.addEventListener('click',function(){{
    resetFilters(); show('s-islemler'); setChip('sev',b.dataset.jump,'{S_TOADDRESS}'); }}); }});

function setChip(f,v,alsoStatus){{
  var sel='.chip[data-f="'+f+'"]';
  document.querySelectorAll(sel).forEach(function(x){{x.classList.remove('on');}});
  if(state[f]===v && !alsoStatus){{ state[f]=null; }}
  else {{ state[f]=v;
    var el=document.querySelector(sel+'[data-v="'+v+'"]'); if(el) el.classList.add('on'); }}
  if(alsoStatus){{ state.status=alsoStatus;
    document.querySelectorAll('.chip[data-f="status"]').forEach(function(x){{
      x.classList.toggle('on',x.dataset.v===alsoStatus); }}); }}
  apply();
}}
document.querySelectorAll('.chip').forEach(function(b){{
  b.addEventListener('click',function(){{ setChip(b.dataset.f,b.dataset.v); }}); }});

function apply(){{
  var n=0;
  groups.forEach(function(g){{
    var ok=true;
    if(state.q && g.dataset.t.indexOf(state.q)===-1) ok=false;
    if(ok && state.status && g.dataset.status!==state.status) ok=false;
    if(ok && state.sev && g.dataset.sev!==state.sev) ok=false;
    if(ok && state.cat && g.dataset.cat!==state.cat) ok=false;
    if(ok && state.reg && g.dataset.reg!=='1') ok=false;
    g.hidden=!ok; if(ok) n++;
  }});
  document.getElementById('cnt').textContent=n+' / '+groups.length+' {e(t["shown"])}';
  document.getElementById('none').hidden=n>0;
}}
document.getElementById('q').addEventListener('input',function(){{
  state.q=this.value.toLowerCase().trim(); apply(); }});
document.getElementById('clear').addEventListener('click',function(){{ resetFilters(); apply(); }});

var allOpen=false;
document.getElementById('expand').addEventListener('click',function(){{
  allOpen=!allOpen;
  groups.forEach(function(g){{
    g.querySelector('tr.det').hidden=!allOpen; g.classList.toggle('open',allOpen); }});
  this.textContent=allOpen?'{e(t["collapse_all"])}':'{e(t["expand_all"])}'; }});

document.getElementById('sort').addEventListener('change',function(){{
  var m=this.value, tb=document.querySelector('.find');
  groups.slice().sort(function(a,b){{
    if(m==='title') return a.dataset.t.localeCompare(b.dataset.t);
    if(m==='gain') return parseFloat(b.dataset.gain)-parseFloat(a.dataset.gain);
    return parseFloat(b.dataset.sevv)-parseFloat(a.dataset.sevv);
  }}).forEach(function(g){{ tb.appendChild(g); }}); }});

/* Findings PDF: print the cover + this section as a self-contained document.
   print() MUST be called synchronously inside the click handler - browsers
   block it when the user-gesture chain is broken by a setTimeout, which is why
   the button appeared to do nothing. The class is cleared on afterprint (with
   a timer fallback for browsers that never fire it). */
function prMode(cls){{
  var b=document.body;
  ['pr-fnd','pr-sec'].forEach(function(c){{ b.classList.remove(c); }});
  if(cls) b.classList.add(cls);
}}
function prClear(){{ prMode(null); }}
window.addEventListener('afterprint',prClear);
if(window.matchMedia){{
  var mq=window.matchMedia('print');
  var h=function(m){{ if(!m.matches) prClear(); }};
  if(mq.addEventListener) mq.addEventListener('change',h);
  else if(mq.addListener) mq.addListener(h);
}}
(function(){{
  var b=document.getElementById('fndpdf'); if(!b) return;
  b.addEventListener('click',function(){{
    prMode('pr-fnd');
    // Force a synchronous style flush so the print stylesheet sees the class.
    void document.body.offsetHeight;
    try{{ window.print(); }}
    catch(err){{ prClear(); alert('{jsq(t["fnd_pdf_fail"])}'); return; }}
    setTimeout(prClear,1500);
  }});
}})();
/* Cover: dismiss on screen, remembered per browser so a returning reader is
   not stopped by it every time. Printing always restores it (CSS handles that). */
(function(){{
  var cv=document.getElementById('cover'), go=document.getElementById('cvgo');
  if(!cv||!go) return;
  var K='ssa-cover-{tenant_key}';
  try{{ if(sessionStorage.getItem(K)==='1') document.body.classList.add('nocover'); }}catch(e){{}}
  go.addEventListener('click',function(){{
    document.body.classList.add('nocover');
    try{{ sessionStorage.setItem(K,'1'); }}catch(e){{}}
    window.scrollTo(0,0);
  }});
}})();
/* ---- Export ------------------------------------------------------------
   The previous one-liner created an anchor that was never attached to the
   document; Firefox ignores a click on a detached anchor and Chrome drops the
   object URL early, so the download silently did nothing. This version
   attaches the anchor, revokes the URL afterwards, and reports failure to the
   user instead of failing quietly. */
function dlFile(name, text, mime){{
  try{{
    var blob=new Blob([text],{{type:mime+';charset=utf-8'}});
    if(navigator.msSaveBlob){{ navigator.msSaveBlob(blob,name); return true; }}
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url; a.download=name; a.style.display='none'; a.rel='noopener';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){{
      try{{ document.body.removeChild(a); URL.revokeObjectURL(url); }}catch(e){{}}
    }},2000);
    return true;
  }}catch(e){{ return false; }}
}}
function csvCell(v){{ return '"'+String(v==null?'':v).replace(/"/g,'""')+'"'; }}
function rowText(el){{ return el ? el.innerText.trim().replace(/\\s+/g,' ') : ''; }}

function collectRows(onlyFiltered, withAsg, withNote, withSteps){{
  var head=['{jsq(t["col_status"])}','{jsq(t["col_action"])}','{jsq(t["col_category"])}',
            '{jsq(t["col_product"])}','{jsq(t["col_points"])}','{jsq(t["col_max"])}',
            '{jsq(t["col_gain"])}','{jsq(t["sev_label"])}','{jsq(t["col_regressed"])}'];
  if(withAsg)   head=head.concat(['{owner_lbl}','{due_lbl}']);
  if(withNote)  head.push('{jsq(t["col_note"])}');
  if(withSteps) head.push('{jsq(t["implementation"])}');
  var out=[head];
  groups.forEach(function(g){{
    if(onlyFiltered && g.hidden) return;
    var c=g.querySelectorAll('tr.r td');
    var meta=rowText(c[1].querySelector('.fs')).split(' · ');
    var pts=rowText(c[3]).split('/');
    var box=g.querySelector('.dbox.asg');
    var id=box?box.getAttribute('data-aid'):null;
    var a=(id&&asg[id])?asg[id]:{{}};
    var r=[rowText(c[0].querySelector('.pill'))||rowText(c[0]),
           rowText(c[1].querySelector('.ft')),
           rowText(c[2]),
           (meta[1]||''),
           (pts[0]||'').trim(),
           (pts[1]||'').trim(),
           rowText(c[4]),
           rowText(c[5]),
           g.getAttribute('data-reg')==='1'?'{yes_lbl}':'{no_lbl}'];
    if(withAsg)  r=r.concat([a.owner||'', a.due||'']);
    if(withNote) r.push(rowText(g.querySelector('.dnote')));
    if(withSteps) r.push(rowText(g.querySelector('.dbox.grow p')));
    out.push(r);
  }});
  return out;
}}

var expBtn=document.getElementById('exp'), expPop=document.getElementById('exppop');
function expOpen(on){{
  expPop.hidden=!on; expBtn.setAttribute('aria-expanded',on?'true':'false');
  if(on) document.getElementById('epn').textContent=
    '('+groups.filter(function(g){{ return !g.hidden; }}).length+')';
}}
expBtn.addEventListener('click',function(ev){{ ev.stopPropagation(); expOpen(expPop.hidden); }});
expPop.addEventListener('click',function(ev){{ ev.stopPropagation(); }});
document.addEventListener('click',function(){{ if(!expPop.hidden) expOpen(false); }});
document.addEventListener('keydown',function(ev){{
  if(ev.key==='Escape'&&!expPop.hidden) expOpen(false); }});

function expOpts(){{
  return {{
    filtered: document.querySelector('input[name=epsc]:checked').value==='f',
    asg: document.getElementById('epa').checked,
    note: document.getElementById('epn2').checked,
    steps: document.getElementById('eps').checked
  }};
}}
document.getElementById('epcsv').addEventListener('click',function(){{
  var o=expOpts();
  var rows=collectRows(o.filtered,o.asg,o.note,o.steps);
  if(rows.length<2){{ alert('{jsq(t["exp_empty"])}'); return; }}
  var csv='\\ufeff'+rows.map(function(r){{ return r.map(csvCell).join(';'); }}).join('\\r\\n');
  if(!dlFile('secure-score-islemler.csv',csv,'text/csv')) alert('{jsq(t["exp_fail"])}');
  expOpen(false);
}});
document.getElementById('eppdf').addEventListener('click',function(){{
  var o=expOpts();
  expOpen(false);
  if(o.steps) groups.forEach(function(g){{
    if(!g.hidden) g.querySelector('tr.det').hidden=false; }});
  prMode(o.filtered?'pr-sec':null);
  void document.body.offsetHeight;
  try{{ window.print(); }}
  catch(err){{ prClear(); alert('{jsq(t["fnd_pdf_fail"])}'); return; }}
  setTimeout(prClear,1500);
}});

/* ---- Owner / due-date assignments -------------------------------------
   Stored per tenant in localStorage so the same report file can be reused for
   several tenants without entries bleeding across. Everything degrades to
   in-memory if storage is blocked (some browsers block it on file:// URLs),
   and CSV export always works either way. */
var ASG_KEY='ssa-assign-{tenant_key}';
var asg={{}};
try{{ asg=JSON.parse(localStorage.getItem(ASG_KEY)||'{{}}')||{{}}; }}catch(e){{ asg={{}}; }}
function asgSave(){{
  try{{ localStorage.setItem(ASG_KEY,JSON.stringify(asg)); }}catch(e){{}}
}}
function asgToday(){{
  var d=new Date(); d.setHours(0,0,0,0); return d;
}}
function asgBadge(id){{
  var esc=(window.CSS&&CSS.escape)?CSS.escape(id):String(id).replace(/["\\\\]/g,'\\\\$&');
  var b=document.querySelector('.abadge[data-abid="'+esc+'"]');
  if(!b) return;
  var a=asg[id]||{{}};
  if(!a.owner && !a.due){{ b.hidden=true; b.textContent=''; return; }}
  b.hidden=false; b.textContent='';
  if(a.owner){{
    var s=document.createElement('span'); s.className='ab-o';
    s.textContent='{owner_lbl}: '+a.owner; b.appendChild(s);
  }}
  if(a.due){{
    var late=new Date(a.due+'T00:00:00')<asgToday();
    var d=document.createElement('span');
    d.className='ab-d'+(late?' late':'');
    d.textContent='{due_lbl}: '+a.due+(late?' · {overdue_lbl}':'');
    b.appendChild(d);
  }}
}}
document.querySelectorAll('.dbox.asg').forEach(function(box){{
  var id=box.getAttribute('data-aid');
  box.querySelectorAll('.ai').forEach(function(inp){{
    var k=inp.getAttribute('data-k');
    if(asg[id]&&asg[id][k]) inp.value=asg[id][k];
    inp.addEventListener('click',function(ev){{ ev.stopPropagation(); }});
    inp.addEventListener('input',function(){{
      asg[id]=asg[id]||{{}};
      var v=inp.value.trim();
      if(v) asg[id][k]=v; else delete asg[id][k];
      if(!asg[id].owner&&!asg[id].due&&!asg[id].note) delete asg[id];
      asgSave(); asgBadge(id);
    }});
  }});
  asgBadge(id);
}});
document.getElementById('asgc').addEventListener('click',function(){{
  if(!confirm('{jsq(t["asg_confirm"])}')) return;
  asg={{}}; asgSave();
  document.querySelectorAll('.dbox.asg .ai').forEach(function(i){{ i.value=''; }});
  document.querySelectorAll('.abadge').forEach(function(b){{ b.hidden=true; b.textContent=''; }});
}});

function tog(tr){{
  var g=tr.parentNode,d=g.querySelector('tr.det');
  var open=!d.hidden; d.hidden=open; g.classList.toggle('open',!open);
}}
window.addEventListener('beforeprint',function(){{
  groups.forEach(function(g){{ if(!g.hidden) g.querySelector('tr.det').hidden=false; }}); }});
apply();
</script>
</body></html>"""


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #
def write_csv(path: str, res: Dict[str, Any], lang: str = "tr") -> None:
    t = STR.get(lang, STR["tr"])
    cols = ["id", "title", "category", "service", "status", "regressed", "score",
            "maxScore", "gap", "achievedPct", "userImpact", "note",
            "remediation", "remediationImpact", "actionUrl"]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for c in res["controls"]:
            w.writerow([c["id"], c["title"], c["category"], c["service"],
                        t[c["status"]], "yes" if c["regressed"] else "",
                        c["score"], c["maxScore"], c["gap"], c["achievedPct"],
                        c["userImpact"], c["note"], c["remediation"],
                        c["remediationImpact"], c["actionUrl"]])
        for c in res["notApplicable"]:
            w.writerow([c["id"], c["title"], c["category"], c["service"],
                        t["not_applicable"], "", "", c["maxScore"], "", "", "", "", "", "", ""])



# --------------------------------------------------------------------------- #
# Portal export comparison (accuracy proof)
# --------------------------------------------------------------------------- #
PORTAL_STATUS_MAP = {
    "to address": S_TOADDRESS,
    "completed": S_COMPLETED,
    "planned": S_PLANNED,
    "risk accepted": S_RISK,
    "third party": S_THIRD,
    "resolved through third party": S_THIRD,
    "alternate mitigation": S_ALT,
    "resolved through alternate mitigation": S_ALT,
    "regressed": S_TOADDRESS,
}


def _norm_title(text: str) -> str:
    keep = [ch.lower() for ch in str(text or "") if ch.isalnum() or ch.isspace()]
    return " ".join("".join(keep).split())


def read_portal_export(path: str) -> List[Dict[str, str]]:
    """Read a Microsoft Secure Score portal export (.xlsx or .csv).

    The .xlsx reader uses only the standard library (zipfile + xml), so no
    third-party packages are needed on the machine running the assessment.
    """
    rows: List[List[str]] = []
    if path.lower().endswith((".csv", ".tsv")):
        delim = "\t" if path.lower().endswith(".tsv") else ","
        with open(path, encoding="utf-8-sig", newline="") as fh:
            rows = [list(r) for r in csv.reader(fh, delimiter=delim)]
    else:
        import xml.etree.ElementTree as ET
        import zipfile
        ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
        with zipfile.ZipFile(path) as zf:
            shared: List[str] = []
            if "xl/sharedStrings.xml" in zf.namelist():
                root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si in root.findall(f"{ns}si"):
                    shared.append("".join(t.text or "" for t in si.iter(f"{ns}t")))
            sheets = [n for n in zf.namelist() if n.startswith("xl/worksheets/sheet")]
            if not sheets:
                raise RuntimeError("Excel dosyasinda sayfa bulunamadi")
            root = ET.fromstring(zf.read(sorted(sheets)[0]))
            for row in root.iter(f"{ns}row"):
                values: List[str] = []
                for cell in row.findall(f"{ns}c"):
                    v = cell.find(f"{ns}v")
                    text = ""
                    if cell.get("t") == "s" and v is not None:
                        idx = int(v.text or 0)
                        text = shared[idx] if 0 <= idx < len(shared) else ""
                    elif cell.get("t") == "inlineStr":
                        node = cell.find(f"{ns}is")
                        text = "".join(t.text or "" for t in node.iter(f"{ns}t")) if node is not None else ""
                    elif v is not None:
                        text = v.text or ""
                    values.append(text)
                rows.append(values)

    if not rows:
        return []
    header = [str(h).strip().lower() for h in rows[0]]

    def col(*names: str) -> Optional[int]:
        for name in names:
            if name in header:
                return header.index(name)
        return None

    i_action = col("recommended action", "action", "improvement action", "onerilen islem")
    i_status = col("status", "durum")
    i_cat = col("category", "kategori")
    i_prod = col("product", "urun", "service")
    i_rank = col("rank", "sira")
    if i_action is None or i_status is None:
        raise RuntimeError("Export dosyasinda 'Recommended action' ve 'Status' kolonlari bulunamadi")

    out = []
    for row in rows[1:]:
        def get(idx: Optional[int]) -> str:
            return str(row[idx]).strip() if idx is not None and idx < len(row) else ""
        action = get(i_action)
        if not action:
            continue
        out.append({"action": action, "status": get(i_status), "category": get(i_cat),
                    "product": get(i_prod), "rank": get(i_rank), "key": _norm_title(action)})
    return out


def compare_with_export(res: Dict[str, Any], export_rows: List[Dict[str, str]],
                        lang: str = "tr") -> Dict[str, Any]:
    t = STR.get(lang, STR["tr"])
    by_key: Dict[str, Dict[str, Any]] = {}
    for c in res["controls"]:
        by_key.setdefault(_norm_title(c["title"]), c)
        by_key.setdefault(_norm_title(c["id"]), c)

    matched, missing, mismatched = [], [], []
    export_counts: Dict[str, int] = {}
    for row in export_rows:
        mapped = PORTAL_STATUS_MAP.get(row["status"].strip().lower())
        export_counts[row["status"]] = export_counts.get(row["status"], 0) + 1
        control = by_key.get(row["key"])
        if not control:
            missing.append(row)
            continue
        matched.append((row, control))
        if mapped and control["status"] != mapped:
            mismatched.append((row, control))

    matched_keys = {_norm_title(c["title"]) for _, c in matched}
    extra = [c for c in res["controls"] if _norm_title(c["title"]) not in matched_keys]

    tool_counts: Dict[str, int] = {}
    for c in res["controls"]:
        tool_counts[t[c["status"]]] = tool_counts.get(t[c["status"]], 0) + 1

    return {"exportTotal": len(export_rows), "toolTotal": res["applicableCount"],
            "matched": len(matched), "missing": missing, "extra": extra,
            "mismatched": mismatched, "exportCounts": export_counts,
            "toolCounts": tool_counts}


def print_comparison(cmp: Dict[str, Any]) -> None:
    print()
    print("=" * 74)
    print("  PORTAL EXPORT KARSILASTIRMASI")
    print("=" * 74)
    print(f"  Export'taki islem sayisi : {cmp['exportTotal']}")
    print(f"  Aracin buldugu islem     : {cmp['toolTotal']}")
    print(f"  Eslesen                  : {cmp['matched']}")
    print(f"  Export'ta olup araçta yok: {len(cmp['missing'])}")
    print(f"  Araçta olup export'ta yok: {len(cmp['extra'])}")
    print(f"  Durum farki              : {len(cmp['mismatched'])}")
    print("-" * 74)
    print("  Export durum dagilimi    :", ", ".join(
        f"{k}={v}" for k, v in sorted(cmp["exportCounts"].items(), key=lambda kv: -kv[1])))
    print("  Arac durum dagilimi      :", ", ".join(
        f"{k}={v}" for k, v in sorted(cmp["toolCounts"].items(), key=lambda kv: -kv[1])))
    if cmp["mismatched"]:
        print("-" * 74)
        print("  Ilk 15 durum farki (export -> arac):")
        for row, control in cmp["mismatched"][:15]:
            print(f"   - {row['action'][:52]:<52} {row['status']:<12} -> {control['status']}")
    if cmp["missing"]:
        print("-" * 74)
        print("  Export'ta olup araçta bulunmayan ilk 10 islem:")
        for row in cmp["missing"][:10]:
            print(f"   - {row['action'][:60]}  [{row['status']}]")
    print("=" * 74)


# --------------------------------------------------------------------------- #
# Demo data (SYNTHETIC)
# --------------------------------------------------------------------------- #
DEMO_CONTROLS = [
    ("AdminMFAV2", "Require MFA for administrative roles", "Identity", "Entra ID", 10, 10, "Low", None),
    ("MFARegistrationV2", "Ensure all users can complete MFA", "Identity", "Entra ID", 9, 4.5, "Low", None),
    ("BlockLegacyAuthentication", "Block legacy authentication", "Identity", "Entra ID", 8, 0, "Moderate", None),
    ("PWAgePolicyNew", "Set password expiration to 'never'", "Identity", "Entra ID", 3, 3, "Low", None),
    ("SigninRiskPolicy", "Enable sign-in risk policy", "Identity", "Entra ID", 7, 0, "Moderate",
     ("Planned", "Q4 CA projesi kapsaminda planlandi", "2026-08-20T10:00:00Z", "guvenlik@contoso.com")),
    ("UserRiskPolicy", "Enable user risk policy", "Identity", "Entra ID", 7, 0, "Moderate", None),
    ("SelfServicePasswordReset", "Enable self-service password reset", "Identity", "Entra ID", 4, 4, "Low", None),
    ("OneAdmin", "Use limited administrative roles", "Identity", "Entra ID", 5, 2.5, "Low", None),
    ("PrivilegedIdentityManagement", "Enable PIM for privileged roles", "Identity", "Entra ID", 9, 0, "High", None),
    ("GuestUserReview", "Review guest user access quarterly", "Identity", "Entra ID", 3, 0, "Low", None),
    ("MDATPProtection", "Enable endpoint protection on all devices", "Device", "Defender", 10, 7, "Low", None),
    ("DeviceCompliancePolicy", "Require compliant devices for access", "Device", "Intune", 8, 0, "High", None),
    ("BitLockerEncryption", "Enable disk encryption on all endpoints", "Device", "Intune", 6, 6, "Low", None),
    ("ASRRules", "Enable attack surface reduction rules", "Device", "Defender", 7, 3.5, "Moderate", None),
    ("AutoUpdate", "Enable automatic OS updates", "Device", "Intune", 4, 4, "Low", None),
    ("SafeLinks", "Enable Safe Links policy", "Apps", "Defender for Office", 8, 8, "Low", None),
    ("SafeAttachments", "Enable Safe Attachments policy", "Apps", "Defender for Office", 8, 0, "Low", None),
    ("AntiPhishPolicy", "Configure anti-phishing protection", "Apps", "Defender for Office", 7, 3.5, "Low", None),
    ("SPOSharingPolicy", "Restrict anonymous external sharing", "Apps", "SharePoint", 6, 0, "Moderate",
     ("Ignored", "Is gereksinimi nedeniyle risk kabul edildi", "2026-07-02T08:30:00Z", "bt@contoso.com")),
    ("MailForwarding", "Block external mail auto-forwarding", "Apps", "Exchange", 5, 5, "Low", None),
    ("AuditLogEnabled", "Enable unified audit log", "Data", "Purview", 5, 5, "Low", None),
    ("DLPPolicy", "Configure DLP policies for sensitive data", "Data", "Purview", 8, 0, "Moderate", None),
    ("SensitivityLabels", "Publish sensitivity labels", "Data", "Purview", 6, 3, "Moderate", None),
    ("RetentionPolicy", "Configure retention policies", "Data", "Purview", 4, 0, "Low", None),
    ("CloudAppDiscovery", "Enable cloud app discovery", "Data", "Defender for Cloud Apps", 5, 0, "Low",
     ("ThirdParty", "Ucuncu parti CASB cozumu ile karsilaniyor", "2026-06-15T12:00:00Z", "bt@contoso.com")),
]


def build_demo_payload() -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    profiles, control_scores = [], []
    for rank, (cid, title, cat, svc, mx, got, impact, state) in enumerate(DEMO_CONTROLS, start=1):
        prof = {
            "id": cid, "title": title, "maxScore": mx, "controlCategory": cat,
            "service": svc, "tier": "Core", "actionType": "Config", "rank": rank,
            "userImpact": impact, "implementationCost": "Low",
            "threats": ["Account breach", "Data exfiltration"],
            "remediation": f"<p>Configure <b>{html.escape(title)}</b> for all in-scope users.</p>",
            "remediationImpact": "<p>Users may need to re-authenticate once.</p>",
            "actionUrl": "https://security.microsoft.com/securescore", "deprecated": False,
        }
        if state:
            st, comment, when, who = state
            prof["controlStateUpdates"] = [{"state": st, "comment": comment,
                                            "updatedDateTime": when, "updatedBy": who,
                                            "assignedTo": who}]
        profiles.append(prof)
        control_scores.append({
            "controlName": cid, "score": got, "controlCategory": cat,
            "description": title,
            "implementationStatus": "Configured" if got >= mx else "Not configured",
            "scoreInPercentage": round(got / mx * 100, 1) if mx else 0,
        })

    # Controls in the global catalogue that do NOT apply to this tenant
    for i in range(1, 9):
        profiles.append({
            "id": f"NotLicensedControl{i}", "title": f"Action for a product not licensed ({i})",
            "maxScore": 9, "controlCategory": "Apps", "service": "Other",
            "userImpact": "Low", "remediation": "<p>Requires an add-on licence.</p>",
            "actionUrl": "", "deprecated": False, "rank": 900 + i,
        })
    profiles.append({"id": "DeprecatedControl", "title": "Retired action", "maxScore": 5,
                     "controlCategory": "Apps", "deprecated": True})

    applicable_max = sum(c[4] for c in DEMO_CONTROLS)
    current = sum(c[5] for c in DEMO_CONTROLS)

    history = []
    for offset in range(11, -1, -1):
        day = dt.date(2026, 9, 11) - dt.timedelta(days=offset * 7)
        scores_snapshot = []
        for entry, spec in zip(control_scores, DEMO_CONTROLS):
            value = entry["score"]
            if offset > 0:
                # older snapshots slightly lower, and one control regressed recently
                if spec[0] == "ASRRules" and offset == 1:
                    value = 7.0
                elif value > 0 and offset > 2:
                    value = max(0.0, value - 1.0)
            scores_snapshot.append(dict(entry, score=value))
        history.append({
            "id": f"demo-{day}", "createdDateTime": f"{day}T02:00:00Z",
            "currentScore": round(sum(s["score"] for s in scores_snapshot), 1),
            "maxScore": applicable_max, "activeUserCount": 1180, "licensedUserCount": 1250,
            "averageComparativeScores": [
                {"basis": "AllTenants", "averageScore": round(applicable_max * 0.47, 1)},
                {"basis": "TotalSeats", "averageScore": round(applicable_max * 0.52, 1)}],
            "controlScores": scores_snapshot,
        })
    history.sort(key=lambda h: h["createdDateTime"], reverse=True)
    history[0]["currentScore"] = current
    tenant = {"id": "00000000-0000-0000-0000-00000000demo",
              "displayName": "DEMO TENANT (SYNTHETIC DATA — NOT A REAL TENANT)",
              "domain": "demo.onmicrosoft.com", "country": "TR"}
    return tenant, history, profiles


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #
def run_self_test() -> int:
    tenant, history, profiles = build_demo_payload()
    res = analyse(history[0], history[1], profiles, lang="tr")
    checks: List[Tuple[str, bool, str]] = []

    applicable_max = sum(c[4] for c in DEMO_CONTROLS)
    expected_cur = sum(c[5] for c in DEMO_CONTROLS)

    checks.append(("Headline score comes from the tenant snapshot",
                   abs(res["currentScore"] - expected_cur) < 0.01
                   and abs(res["maxScore"] - applicable_max) < 0.01,
                   f"{res['currentScore']}/{res['maxScore']}"))
    checks.append(("Only tenant-applicable controls are counted",
                   res["applicableCount"] == len(DEMO_CONTROLS),
                   f"{res['applicableCount']} vs {len(DEMO_CONTROLS)}"))
    checks.append(("Catalogue-only controls reported separately",
                   res["notApplicableCount"] == 8, f"{res['notApplicableCount']}"))
    checks.append(("Deprecated controls excluded everywhere",
                   all("Deprecated" not in c["id"] for c in res["controls"])
                   and all("Deprecated" not in c["id"] for c in res["notApplicable"]), "ok"))
    checks.append(("Category max reconciles with tenant max",
                   res["reconciles"] and
                   abs(sum(d["maxScore"] for d in res["categories"].values()) - applicable_max) < 0.05,
                   f"{res['catalogueMax']} vs {res['maxScore']}"))
    checks.append(("Risk-accepted control classified from admin state",
                   any(c["id"] == "SPOSharingPolicy" and c["status"] == S_RISK
                       for c in res["controls"]), "state mapping"))
    checks.append(("Third-party control classified from admin state",
                   any(c["id"] == "CloudAppDiscovery" and c["status"] == S_THIRD
                       for c in res["controls"]), "state mapping"))
    checks.append(("Planned control classified from admin state",
                   any(c["id"] == "SigninRiskPolicy" and c["status"] == S_PLANNED
                       for c in res["controls"]), "state mapping"))
    checks.append(("Admin note and date carried into the report",
                   any(c["id"] == "SPOSharingPolicy" and "risk kabul" in c["note"].lower()
                       and "2026-07-02" in c["note"] for c in res["controls"]), "notes"))
    checks.append(("Completed controls have no remaining gain",
                   all(c["gap"] == 0 for c in res["doneControls"]), "gap maths"))
    checks.append(("Open gain equals sum of open control gaps",
                   abs(res["totalGap"] - sum(c["gap"] for c in res["openControls"])) < 0.05,
                   f"{res['totalGap']}"))
    checks.append(("Closed actions excluded from open gain",
                   all(c not in res["openControls"] for c in res["closedControls"]), "grouping"))
    checks.append(("Regression detected against previous snapshot",
                   res["regressedCount"] >= 1
                   and any(c["id"] == "ASRRules" for c in res["regressed"]),
                   f"{res['regressedCount']}"))
    checks.append(("Every control lands in exactly one group",
                   len(res["openControls"]) + len(res["doneControls"]) + len(res["closedControls"])
                   == res["applicableCount"], "grouping"))
    checks.append(("Priority list sorted by descending impact severity",
                   all(res["priority"][i]["severityValue"] >= res["priority"][i + 1]["severityValue"]
                       for i in range(len(res["priority"]) - 1)), "ordering"))
    checks.append(("Every control carries a severity from the fixed set",
                   all(c["severity"] in SEV_ORDER for c in res["controls"])
                   and sum(res["sevCounts"].values()) == res["applicableCount"],
                   f"{res['sevCounts']}"))
    checks.append(("Severity rises with points, threats and regression",
                   severity_value(10, 1, ["Account Breach"], True, "Core")
                   > severity_value(1, 200, [], False, ""), "model"))
    checks.append(("Open severity counts never exceed total counts",
                   all(res["sevOpen"][k] <= res["sevCounts"][k] for k in SEV_ORDER),
                   "roll-up"))
    checks.append(("Graph service codes render as current Microsoft names",
                   product_name("AzureAD") == "Microsoft Entra ID"
                   and product_name("Azure ATP") == "Microsoft Defender for Identity"
                   and product_name("MDATP") == "Microsoft Defender for Endpoint"
                   and product_name("MIP") == "Microsoft Purview Information Protection"
                   and "Salesforce" in product_name("MDA_SF")
                   and product_name("NoSuchCode") == "NoSuchCode", "naming"))
    checks.append(("Retired brand names are modernised in prose",
                   modernise_terms("Azure AD and Azure ATP") ==
                   "Microsoft Entra ID and Microsoft Defender for Identity"
                   and modernise_terms("Microsoft Cloud App Security") ==
                   "Microsoft Defender for Cloud Apps", "naming"))
    checks.append(("Primary domain falls back to the verified list",
                   tenant_domain({"verifiedDomains": ["contoso.onmicrosoft.com"]})
                   == "contoso.onmicrosoft.com"
                   and tenant_domain({"domain": "a.com",
                                      "verifiedDomains": ["b.com"]}) == "a.com"
                   and tenant_domain({}) == "", "tenant"))
    def _cr(a: str, b: str = "#FFFFFF") -> float:
        def _l(h: str) -> float:
            h = h.lstrip("#")
            ch = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            ch = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in ch]
            return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2]
        hi, lo = sorted([_l(a), _l(b)], reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    checks.append(("Headline display tones clear WCAG AA for large text",
                   all(_cr(SEV_DISPLAY[k]) >= 3.0 for k in SEV_ORDER),
                   ", ".join(f"{k}:{_cr(SEV_DISPLAY[k]):.2f}" for k in SEV_ORDER)))
    checks.append(("Every risk band has its own display tone",
                   len(set(SEV_DISPLAY.values())) == len(SEV_ORDER)
                   and set(SEV_DISPLAY) == set(SEV_ORDER), "display palette"))
    _cover = build_html(analyse(history[0], history[1], profiles, "tr"), tenant, history,
                        "tr", {"provider": "Saglayici A.S.", "colour": "#C8102E",
                               "logo": "data:image/png;base64,AAAA"})
    checks.append(("Cover page carries customer, provider, tenant and logo",
                   'class="cover"' in _cover and "Saglayici A.S." in _cover
                   and str(tenant.get("id")) in _cover
                   and 'class="cv-logo"' in _cover, "cover"))
    _pg = build_html(analyse(history[0], history[1], profiles, "tr"), tenant, history, "tr")
    _open_n = len(analyse(history[0], history[1], profiles, "tr")["openControls"])
    checks.append(("Findings report renders one card per open action",
                   _pg.count('<article class="bulgu"') == _open_n,
                   f'{_pg.count(chr(60) + "article class=" + chr(34) + "bulgu" + chr(34))} vs {_open_n}'))
    # Count inside the findings section only - the same labels appear in the
    # per-action detail panels of section 2, which would inflate a global count.
    _fs = _pg.split('id="s-bulgu"', 1)[-1].split("</section>", 1)[0]
    checks.append(("Every finding card carries steps, rank and points",
                   _fs.count("Yapılandırma:") == _open_n
                   and _fs.count("Microsoft öncelik sırası") == _open_n,
                   f'steps {_fs.count("Yapılandırma:")}, rank '
                   f'{_fs.count("Microsoft öncelik sırası")}, cards {_open_n}'))
    _fi = _pg.split('class="panel fnd-intro"', 1)[-1].split("</article>", 1)[0]
    _res_tr = analyse(history[0], history[1], profiles, "tr")
    _sev_open = {k: sum(1 for c in _res_tr["openControls"] if c["severity"] == k)
                 for k in SEV_ORDER}
    checks.append(("Risk posture counts match the cards they describe",
                   all(f'>{_sev_open[k]}</div>' in _fi
                       for k in SEV_ORDER if _sev_open[k])
                   and sum(_sev_open.values()) == _open_n,
                   f"{_sev_open} = {_open_n}"))
    # Posture chips: one uniform treatment, plain white, no per-band exception.
    # The fills are the report owner's choice, so the check records the measured
    # contrast rather than enforcing a threshold - the number stays visible in
    # the test output, and any future fill change is reported here.
    checks.append(("Risk posture chips use one uniform white treatment",
                   all(SEV_BIG_INK[k] == "#FFFFFF" for k in SEV_ORDER)
                   and len(SEV_BIG_FILL) == len(SEV_ORDER),
                   "beyaz kontrast -> "
                   + ", ".join(f"{k}:{_cr('#FFFFFF', SEV_BIG_FILL[k]):.2f}"
                               for k in SEV_ORDER)))

    def _hue(hx: str) -> float:
        hx = hx.lstrip("#")
        r, g, b = (int(hx[i:i + 2], 16) for i in (0, 2, 4))
        mx, mn = max(r, g, b), min(r, g, b)
        if mx == mn:
            return 0.0
        if mx == r:
            h = 60 * ((g - b) / (mx - mn))
        elif mx == g:
            h = 60 * (2 + (b - r) / (mx - mn))
        else:
            h = 60 * (4 + (r - g) / (mx - mn))
        return h % 360

    checks.append(("Posture fills stay distinguishable from one another",
                   len({SEV_BIG_FILL[k] for k in SEV_ORDER}) == len(SEV_ORDER)
                   and all(abs(_hue(SEV_BIG_FILL["orta"])
                               - _hue(SEV_BIG_FILL[k])) >= 15
                           for k in ("yuksek", "dusuk")),
                   ", ".join(f"{k}:{_hue(SEV_BIG_FILL[k]):.0f}" for k in SEV_ORDER)))
    checks.append(("Findings PDF strips cover, header, nav and footer",
                   all(sel in _pg for sel in (
                       "body.pr-fnd header", "body.pr-fnd nav", "body.pr-fnd footer",
                       "body.pr-fnd .cover", "body.pr-fnd .sec:not(#s-bulgu)")),
                   "print scope"))
    checks.append(("Print is invoked in the click handler, not deferred",
                   # a setTimeout between the click and print() breaks the
                   # user-gesture chain and browsers silently block the dialog
                   "prMode('pr-fnd');" in _pg
                   and _pg.split("prMode('pr-fnd');", 1)[1].split("}}", 1)[0]
                       .find("window.print()") > 0
                   and "setTimeout(function(){ window.print()" not in _pg,
                   "gesture chain"))
    checks.append(("Findings front matter carries summary, purpose and posture",
                   "Yönetici Özeti" in _fi and "Raporun Amacı" in _fi
                   and "Genel Risk Duruşu" in _fi and 'id="fndpdf"' in _fi,
                   "front matter"))
    checks.append(("Brand colour never repaints the risk verdict",
                   # the headline numeral must stay on its risk tone even when a
                   # brand colour is supplied - a brand must not calm a red score
                   any(f'class="cv-pct" style="color:{SEV_DISPLAY[k]}"' in _cover
                       for k in SEV_ORDER)
                   and 'class="cv-pct" style="color:#C8102E"' not in _cover, "cover"))
    checks.append(("Brand colour accepts only literal hex",
                   safe_colour("#C00000", BLUE) == "#C00000"
                   and safe_colour("red;background:url(x)", BLUE) == BLUE
                   and safe_colour(None, BLUE) == BLUE, "branding"))
    checks.append(("Quick wins are low user impact and open",
                   all(c["userImpact"].lower() == "low" and c["status"] in OPEN_STATES
                       for c in res["quickWins"]), "filtering"))
    for lang in ("tr", "en"):
        page = build_html(analyse(history[0], history[1], profiles, lang), tenant, history,
                          lang, {"provider": "Test", "colour": "#0070C0"})
        checks.append((f"Dashboard renders and escapes HTML ({lang})",
                       len(page) > 8000 and "<b>Require MFA" not in page, f"{len(page)} chars"))
    # Portal export reader + comparison round-trip
    import tempfile
    status_for_export = {S_TOADDRESS: "To address", S_COMPLETED: "Completed",
                         S_PLANNED: "Planned", S_RISK: "Risk accepted",
                         S_THIRD: "Third party", S_ALT: "Resolved through alternate mitigation"}
    tmp = os.path.join(tempfile.gettempdir(), "securescore_selftest_export.csv")
    with open(tmp, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["Rank", "Recommended action", "Status", "Category", "Product"])
        for i, c in enumerate(res["controls"], start=1):
            w.writerow([i, c["title"], status_for_export[c["status"]], c["category"], c["service"]])
    parsed = read_portal_export(tmp)
    checks.append(("Portal export reader parses all rows",
                   len(parsed) == res["applicableCount"], f"{len(parsed)} rows"))
    cmp_res = compare_with_export(res, parsed, "tr")
    checks.append(("Comparison matches every action with no status drift",
                   cmp_res["matched"] == res["applicableCount"]
                   and not cmp_res["mismatched"] and not cmp_res["missing"]
                   and not cmp_res["extra"],
                   f"matched {cmp_res['matched']}, drift {len(cmp_res['mismatched'])}"))
    checks.append(("Partially scored actions stay in 'To address' like the portal",
                   all(c["status"] == S_TOADDRESS for c in res["controls"]
                       if c["partial"] and not c["note"].startswith("↓")
                       and c["status"] not in CLOSED_STATES) and res["partialCount"] >= 1,
                   f"{res['partialCount']} partial"))
    try:
        os.remove(tmp)
    except OSError:
        pass

    checks.append(("Control name stays English while Turkish name is offered",
                   all(not c.get("titleTr") or c["title"] != c["titleTr"]
                       for c in res["controls"]), "title policy"))
    checks.append(("Tenant status wording is localised",
                   localise_status("You have 1 out of 1 users with administrative roles "
                                   "that aren\u2019t registered and protected with MFA.")
                   .startswith("Yönetici rolüne sahip 1 kullanıcıdan 1")
                   and localise_status("0/1 exposed devices") == "0/1 cihaz risk altında"
                   and localise_status("current status: On") == "mevcut durum: Açık",
                   "status rules"))
    checks.append(("Unknown status wording is left untouched, not mistranslated",
                   localise_status("Some brand new Microsoft wording") ==
                   "Some brand new Microsoft wording", "fallback"))
    checks.append(("Customer name resolution follows priority order",
                   resolve_customer_name({"displayName": "X"}, "KoçSistem") == "KoçSistem"
                   and resolve_customer_name({"displayName": "Contoso"}) == "Contoso"
                   and resolve_customer_name({"domain": "acme-corp.onmicrosoft.com"}) == "Acme Corp"
                   and resolve_customer_name({"id": "abc"}) == "abc", "naming"))

    checks.append(("Legacy PowerShell date format is converted",
                   _normalise_dates("/Date(1789430400000)/") == "2026-09-15T00:00:00Z"
                   and _short_date("/Date(1789430400000)/") == "2026-09-15"
                   and _normalise_dates({"a": ["/Date(1757548800000)/"]})["a"][0].startswith("2025-09-11"),
                   "date handling"))
    checks.append(("ISO dates and ordinary strings pass through untouched",
                   _normalise_dates("2026-09-11T00:00:00Z") == "2026-09-11T00:00:00Z"
                   and _normalise_dates("Enable MFA") == "Enable MFA", "date handling"))

    checks.append(("Action links are limited to http(s) schemes",
                   'href="javascript:' not in build_html(
                       analyse(history[0], history[1],
                               [dict(p, actionUrl="javascript:alert(1)") for p in profiles],
                               "tr", history, 30), tenant, history, "tr"),
                   "link safety"))

    checks.append(("Risk bands behave",
                   risk_band(95)[0] == "dusuk" and risk_band(65)[0] == "orta"
                   and risk_band(45)[0] == "yuksek" and risk_band(10)[0] == "kritik", "banding"))
    checks.append(("Risk verdict colour always matches its own label",
                   all(risk_verdict(p)[2] == SEV_SOLID[risk_verdict(p)[0]]
                       for p in (95, 75, 50, 20)), "verdict colour"))
    checks.append(("Ink on every solid fill clears WCAG AA",
                   all(_contrast(SEV_INK[k], SEV_SOLID[k]) >= 4.5 for k in SEV_ORDER),
                   "contrast"))
    checks.append(("Severity text tones clear AA on white and on their tint",
                   all(_contrast(SEV_TEXT[k], "#FFFFFF") >= 4.5
                       and _contrast(SEV_TEXT[k], SEV_TINT[k]) >= 4.5 for k in SEV_ORDER),
                   "contrast"))

    print("SELF-TEST — analysis engine validation")
    print("=" * 74)
    failed = 0
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name:<56} {detail}")
        failed += 0 if ok else 1
    print("=" * 74)
    print(f"  {len(checks) - failed}/{len(checks)} checks passed")
    return 0 if failed == 0 else 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Microsoft 365 Secure Score assessment (read-only)")
    p.add_argument("--tenant-id", default=os.getenv("SECURESCORE_TENANT_ID"))
    p.add_argument("--client-id", default=os.getenv("SECURESCORE_CLIENT_ID"))
    p.add_argument("--client-secret", default=os.getenv("SECURESCORE_CLIENT_SECRET"))
    p.add_argument("--access-token", default=os.getenv("SECURESCORE_ACCESS_TOKEN"))
    p.add_argument("--history-days", type=int, default=30)
    p.add_argument("--out", default="./reports")
    p.add_argument("--lang", default="tr", choices=["tr", "en", "both"],
                   help="Rapor dili (varsayilan: tr). 'both' iki dilde de uretir.")
    p.add_argument("--fail-under", type=float, default=None)
    p.add_argument("--offline-input", default=None)
    p.add_argument("--logo", default=os.getenv("SECURESCORE_LOGO"),
                   help="Rapor basligina gomulecek logo dosyasi "
                        "(png/jpg/gif/svg/webp, en fazla 2 MB)")
    p.add_argument("--brand-color", default=os.getenv("SECURESCORE_BRAND_COLOR"),
                   help="Kurumsal vurgu rengi, #RRGGBB. Risk renklerini etkilemez.")
    p.add_argument("--provider", default=os.getenv("SECURESCORE_PROVIDER"),
                   help="Degerlendirmeyi hazirlayan hizmet saglayici adi")
    p.add_argument("--customer", default=os.getenv("SECURESCORE_CUSTOMER"),
                   help="Raporda gosterilecek musteri adi (varsayilan: tenant kurum adi)")
    p.add_argument("--tr-pack", default=None,
                   help="Turkce icerik paketi dosyasi (varsayilan: script yanindaki secure_score_tr.json)")
    p.add_argument("--regression-days", type=int, default=30,
                   help="Geriye gitme tespiti icin karsilastirma penceresi (gun, varsayilan 30)")
    p.add_argument("--compare-export", default=None,
                   help="Microsoft Secure Score portal export (.xlsx/.csv) ile dogrulama yap")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--self-test", action="store_true")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    if args.tr_pack:
        globals()["_TR_PACK_CACHE"] = load_translation_pack(args.tr_pack)

    os.makedirs(args.out, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    if args.demo:
        print("→ DEMO MODU: sentetik veri kullanılıyor, hiçbir tenant'a bağlanılmıyor.")
        tenant, scores, profiles = build_demo_payload()
    elif args.offline_input:
        # Windows PowerShell writes UTF-8 files with a BOM; utf-8-sig strips it
        # transparently and still reads BOM-less files correctly.
        with open(args.offline_input, encoding="utf-8-sig") as fh:
            raw = _normalise_dates(json.load(fh))
        tenant = raw.get("tenant", {})
        scores, profiles = raw["secureScores"], raw["controlProfiles"]
    else:
        if args.access_token:
            token = args.access_token
        else:
            missing = [n for n, v in (("--tenant-id", args.tenant_id),
                                      ("--client-id", args.client_id),
                                      ("--client-secret", args.client_secret)) if not v]
            if missing:
                print(f"Eksik parametre / missing: {', '.join(missing)}", file=sys.stderr)
                return 1
            print("→ Tenant'a bağlanılıyor (app-only, read-only)...")
            token = get_token_client_secret(args.tenant_id, args.client_id, args.client_secret)
        print("→ Secure Score okunuyor...")
        scores = _normalise_dates(graph_get_all("/security/secureScores", token,
                                                {"$top": str(max(1, args.history_days))}))
        scores.sort(key=lambda s: str(s.get("createdDateTime")), reverse=True)
        print("→ İyileştirme işlemleri (kontrol profilleri) okunuyor...")
        profiles = _normalise_dates(graph_get_all("/security/secureScoreControlProfiles", token))
        tenant = fetch_tenant_info(token)

    if not scores:
        print("Secure Score verisi bulunamadı. Lisans/izinleri kontrol edin.", file=sys.stderr)
        return 1

    latest = scores[0]
    previous = scores[1] if len(scores) > 1 else None
    tenant = dict(tenant or {})
    tenant["customerName"] = resolve_customer_name(tenant, args.customer)

    raw_path = os.path.join(args.out, f"securescore-raw-{stamp}.json")
    with open(raw_path, "w", encoding="utf-8") as fh:
        json.dump({"tenant": tenant, "secureScores": scores, "controlProfiles": profiles},
                  fh, indent=2, ensure_ascii=False)

    brand = {"logo": load_logo(getattr(args, "logo", None)),
             "colour": getattr(args, "brand_color", None),
             "provider": getattr(args, "provider", None)}

    langs = ["tr", "en"] if args.lang == "both" else [args.lang]
    outputs = []
    primary = analyse(latest, previous, profiles, langs[0], scores, args.regression_days)
    for lang in langs:
        res = analyse(latest, previous, profiles, lang, scores, args.regression_days)
        html_path = os.path.join(args.out, f"secure-score-dashboard-{lang}-{stamp}.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(build_html(res, tenant, scores, lang, brand))
        outputs.append(html_path)

    csv_path = os.path.join(args.out, f"secure-score-actions-{stamp}.csv")
    write_csv(csv_path, primary, langs[0])
    json_path = os.path.join(args.out, f"secure-score-assessment-{stamp}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"tenant": tenant, "assessment": primary}, fh, indent=2, ensure_ascii=False)

    r = primary
    print()
    print("=" * 74)
    print(f"  Müşteri           : {tenant.get('customerName')}")
    print(f"  Secure Score      : {r['currentScore']:.1f} / {r['maxScore']:.0f}"
          f"  ({r['achievedPct']:.1f}%)")
    print(f"  Uygulanabilir     : {r['applicableCount']} iyileştirme işlemi"
          f"   (kapsam dışı: {r['notApplicableCount']})")
    print(f"  Tamamlanan        : {r['counts'].get(S_COMPLETED, 0)}")
    print(f"  Açık              : {len(r['openControls'])}"
          f"  (yapılacak {r['counts'].get(S_TOADDRESS, 0)},"
          f" kısmen başlanmış {r['partialCount']},"
          f" planlı {r['counts'].get(S_PLANNED, 0)})")
    print(f"  Kapatılan         : {len(r['closedControls'])}"
          f"  (risk kabul {r['counts'].get(S_RISK, 0)},"
          f" 3. parti {r['counts'].get(S_THIRD, 0)},"
          f" alternatif {r['counts'].get(S_ALT, 0)})")
    if r["regressedCount"]:
        print(f"  Geriye giden      : {r['regressedCount']}")
    print(f"  Kazanılabilir puan: {r['totalGap']:.0f}")
    if langs[0] == "tr":
        tc = r.get("translatedCount", 0)
        if tc:
            print(f"  Türkçe içerik     : {tc}/{r['applicableCount']} işlem çevrildi")
        else:
            print("  Türkçe içerik     : paket bulunamadı, işlem metinleri İngilizce gösteriliyor")
    if not r["reconciles"]:
        print(f"  ! Katalog toplamı ({r['catalogueMax']:.0f}) tenant max ({r['maxScore']:.0f}) "
              f"ile birebir örtüşmüyor; başlık değerleri tenant verisinden alınmıştır.")
    print("=" * 74)
    print("  En yüksek kazançlı 5 işlem:")
    for c in r["priority"][:5]:
        print(f"   +{c['gap']:>5.1f}  {str(c['title'])[:58]}  [{c['category']}]")
    print("=" * 74)
    for path in outputs:
        print(f"  Dashboard : {path}")
    print(f"  CSV       : {csv_path}")
    print(f"  JSON      : {json_path}")
    print(f"  RAW       : {raw_path}")

    if args.compare_export:
        try:
            rows_export = read_portal_export(args.compare_export)
            comparison = compare_with_export(r, rows_export, langs[0])
            print_comparison(comparison)
            cmp_path = os.path.join(args.out, f"portal-comparison-{stamp}.json")
            with open(cmp_path, "w", encoding="utf-8") as fh:
                json.dump({"exportTotal": comparison["exportTotal"],
                           "toolTotal": comparison["toolTotal"],
                           "matched": comparison["matched"],
                           "exportCounts": comparison["exportCounts"],
                           "toolCounts": comparison["toolCounts"],
                           "missing": comparison["missing"],
                           "mismatched": [{"action": row["action"],
                                           "portalStatus": row["status"],
                                           "toolStatus": ctl["status"]}
                                          for row, ctl in comparison["mismatched"]],
                           "extra": [{"id": c["id"], "title": c["title"],
                                      "status": c["status"]} for c in comparison["extra"]]},
                          fh, indent=2, ensure_ascii=False)
            print(f"  Karsilastirma : {cmp_path}")
        except Exception as exc:  # noqa: BLE001
            print(f"Karsilastirma yapilamadi: {exc}", file=sys.stderr)

    if args.fail_under is not None and r["achievedPct"] < args.fail_under:
        print(f"\nEşik altında: {r['achievedPct']:.1f}% < {args.fail_under}%", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        print(f"HATA / ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

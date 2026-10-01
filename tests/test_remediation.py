"""Offline regression tests; no tenant or network access."""
import importlib.util
import json
import re
from pathlib import Path
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("engine", ROOT / "src/secure_score_assessment.py")
engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engine)


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.options_cache = engine._OPTIONS_PACK_CACHE
        self.translation_cache = engine._TR_PACK_CACHE

    def tearDown(self):
        engine._OPTIONS_PACK_CACHE = self.options_cache
        engine._TR_PACK_CACHE = self.translation_cache

    def test_unseen_generic_control_and_narrow_match(self):
        control = {"id": "scid_future", "remediation": (
            "Within Microsoft 365 security, go to Vulnerability management > Recommendations, "
            "read the relevant security recommendation and choose remediation or exception options."),
            "remediationImpact": "Unknown"}
        engine.apply_translations([control], {})
        self.assertEqual(control["remediationCoverage"], "generic")
        self.assertIn("Devices > Misconfigurations", control["remediation"])
        self.assertEqual(control["remediationImpact"], "Bilinmiyor")
        self.assertIsNone(engine.translate_generic_remediation("Go to Recommendations and disable MFA."))

    def test_missing_translation_and_impact(self):
        control = {"id": "future", "remediation": "Configure a new Microsoft setting.",
                   "remediationImpact": "None"}
        engine.apply_translations([control], {})
        self.assertEqual(control["remediationCoverage"], "missing")
        self.assertEqual(control["remediation"],
                         "Güncel uygulama adımları için ilgili Microsoft Secure Score önerisini açın.")
        self.assertNotIn("aşağıdaki", control["remediation"].lower())
        self.assertEqual(control["remediationOriginal"], "Configure a new Microsoft setting.")
        self.assertEqual(control["remediationImpact"], "Yok")

    def render(self, lang="tr", generic_device=False):
        tenant, scores, profiles = engine.build_demo_payload()
        profiles[0]["remediation"] = "<p>Untranslated source &amp; reference.</p>"
        if generic_device:
            old_id = profiles[1]["id"]
            profiles[1].update({
                "id": "scid_87", "title": "Disable Solicited Remote Assistance",
                "controlCategory": "Device", "remediation": (
                    "Within Microsoft 365 security, go to Vulnerability management > Recommendations, "
                    "read the relevant security recommendation and choose remediation or exception options."),
                "remediationImpact": "Untranslated original impact reference.",
            })
            for snapshot in scores:
                for control in snapshot["controlScores"]:
                    if control["controlName"] == old_id:
                        control["controlName"] = "scid_87"
                        control["controlCategory"] = "Device"
        result = engine.analyse(scores[0], scores[1], profiles, lang, scores)
        return engine.build_html(result, tenant, scores, lang)

    def test_original_sections_absent_in_all_report_and_print_markup(self):
        engine._TR_PACK_CACHE = {}
        rendered = self.render(generic_device=True)
        self.assertIn("Güncel uygulama adımları için ilgili Microsoft Secure Score önerisini açın.", rendered)
        self.assertNotIn("Untranslated source &amp; reference.", rendered)
        self.assertNotIn("Untranslated original impact reference.", rendered)
        for report in (rendered, self.render("en", generic_device=True)):
            self.assertNotIn("Özgün Microsoft metni", report)
            self.assertNotIn("Özgün Microsoft etki metni", report)
            self.assertNotIn("original-guidance", report)
            self.assertIn("@media print", report)

    def test_options_shared_escaped_and_english_not_injected(self):
        engine._OPTIONS_PACK_CACHE = {
            "scid_87": {
                "title": "Disable Solicited Remote Assistance",
                "options": [{"label": "<script>GPO</script>",
                             "steps": ["Set <unsafe> & verify."],
                             "applicability": "Pilot only",
                             "verification": "Read effective setting",
                             "sourceUrls": ["javascript:alert(1)", "https://learn.microsoft.com/example"]}],
                "notes": "Reviewed static guidance",
            }}
        rendered = self.render(generic_device=True)
        self.assertIn("&lt;script&gt;GPO&lt;/script&gt;", rendered)
        self.assertNotIn("<script>GPO</script>", rendered)
        self.assertNotIn("javascript:alert(1)", rendered)
        self.assertGreaterEqual(rendered.count("Set &lt;unsafe&gt; &amp; verify."), 2)
        self.assertIn('<h5 class="remediation-heading">İyileştirme Seçenekleri</h5>', rendered)
        self.assertNotIn("<h5>Remediation options</h5>", rendered)
        self.assertNotIn("<b>Kaynaklar:</b>", rendered)
        self.assertNotIn("Reviewed static guidance", self.render("en", generic_device=True))

    def test_white_cells_and_print_borders(self):
        rendered = self.render()
        self.assertIn(".bulgu .b-t td", rendered)
        self.assertIn("background:#fff;border:1px solid #A9B3BF", rendered)
        self.assertIn("background:#fff!important;border:1px solid #A9B3BF!important", rendered)
        self.assertNotIn(".b-t tr:last-child th,.b-t tr:last-child td{border-bottom:0}", rendered)
        self.assertIn("#FFC000", rendered)

    def test_pack_coverage_and_asset_parity(self):
        pack = json.loads((ROOT / "src/secure_score_tr.json").read_text())
        entries = pack["controls"]
        self.assertEqual(len(entries), 460)
        self.assertEqual(sum(bool(v.get("title")) for v in entries.values()), 120)
        self.assertEqual(sum(v.get("remediationTranslationKind") == "generic-device-redirect"
                             for v in entries.values()), 184)
        self.assertEqual(sum(v.get("remediationTranslationKind") == "source-unavailable"
                             for v in entries.values()), 1)
        self.assertTrue(all(v.get("remediation") for v in entries.values()))
        for filename in ("secure_score_tr.json", "secure_score_assessment.py", "remediation_options_tr.json"):
            self.assertEqual((ROOT / "src" / filename).read_bytes(),
                             (ROOT / "module/SecureScoreLens/assets" / filename).read_bytes())

    def test_scid87_reviewed_options(self):
        engine._OPTIONS_PACK_CACHE = None
        entry = engine.load_remediation_options()["scid_87"]
        text = json.dumps(entry, ensure_ascii=False)
        self.assertIn("fAllowToGetHelp", text)
        self.assertIn("REG_DWORD", text)
        self.assertIn("Disabled", text)
        self.assertGreaterEqual(len(entry["options"]), 3)
        self.assertIn("https://learn.microsoft.com/", text)
        self.assertTrue(set(engine.load_remediation_options()).issubset(
            set(engine.load_translation_pack())))
        self.assertIn("assets/remediation_options_tr.json",
                      (ROOT / "module/SecureScoreLens/SecureScoreLens.psd1").read_text())

    def test_source_revision_is_not_silently_overlaid(self):
        control = {"id": "changed", "remediation": "New source instructions.",
                   "remediationImpact": "", "remediationSourceSha256": "new"}
        engine.apply_translations([control], {"changed": {
            "remediation": "Eski yönerge.", "remediationSourceSha256": "old"}})
        self.assertEqual(control["remediationCoverage"], "missing")

    def test_missing_pack_is_cached_and_harmless(self):
        saved_file = engine.__file__
        try:
            engine.__file__ = str(ROOT / "tests/not-present/engine.py")
            engine._OPTIONS_PACK_CACHE = None
            first = engine.load_remediation_options()
            self.assertEqual(first, {})
            self.assertIs(first, engine.load_remediation_options())
            self.assertEqual(engine.load_translation_pack(str(ROOT / "tests/not-present.json")), {})
        finally:
            engine.__file__ = saved_file

    def test_normal_guidance_has_no_missing_options_boilerplate(self):
        rendered = self.render()
        self.assertNotIn("GPO, Intune veya registry", rendered)
        self.assertNotIn("paketi bulunmuyor", rendered)
        self.assertNotIn('class="reviewed-options"', rendered)
        pack = engine.load_translation_pack()
        self.assertIn(engine.html.escape(engine.modernise_terms(
            pack["mfaregistrationv2"]["remediation"])), rendered)

    def test_options_require_device_exact_title_and_actual_redirect(self):
        engine._OPTIONS_PACK_CACHE = None
        entry = engine.load_remediation_options()["scid_87"]
        control = {"id": "scid_87", "title": entry["title"], "category": "Device",
                   "remediationOriginal": (
                       "Within Microsoft 365 security, go to Vulnerability management > Recommendations, "
                       "read the relevant security recommendation and choose remediation or exception options.")}
        self.assertTrue(engine.reviewed_options_match(control, entry))
        self.assertFalse(engine.reviewed_options_match(dict(control, title="Different control"), entry))
        self.assertFalse(engine.reviewed_options_match(dict(control, category="Identity"), entry))
        self.assertFalse(engine.reviewed_options_match(
            dict(control, remediationOriginal="Follow native Secure Score instructions."), entry))

    def test_nonredirect_with_catalogue_id_does_not_get_options(self):
        tenant, scores, profiles = engine.build_demo_payload()
        old_id = profiles[1]["id"]
        profiles[1].update(id="scid_87", title="Disable Solicited Remote Assistance",
                           controlCategory="Device", remediation="Native recommendation, not a redirect.")
        for snapshot in scores:
            for control in snapshot["controlScores"]:
                if control["controlName"] == old_id:
                    control["controlName"] = "scid_87"
                    control["controlCategory"] = "Device"
        result = engine.analyse(scores[0], scores[1], profiles, "tr", scores)
        control = next(c for c in result["controls"] if c["id"] == "scid_87")
        self.assertEqual(control["remediationOptions"], {})
        self.assertEqual(control["remediationCoverage"], "missing")
        self.assertIn("Güncel uygulama adımları için", control["remediation"])
        self.assertNotIn('class="reviewed-options"', engine.build_html(result, tenant, scores, "tr"))

    def test_original_audit_metadata_is_retained_not_exported_to_html(self):
        control = {"id": "future", "remediation": "PRIVATE_ORIGINAL_REMEDIATION",
                   "remediationImpact": "PRIVATE_ORIGINAL_IMPACT"}
        engine.apply_translations([control], {})
        self.assertEqual(control["remediationOriginal"], "PRIVATE_ORIGINAL_REMEDIATION")
        self.assertEqual(control["remediationImpactOriginal"], "PRIVATE_ORIGINAL_IMPACT")
        self.assertNotIn("özgün", control["remediation"].lower())

    def test_csv_excludes_original_guidance_and_impact_audit_fields(self):
        _, scores, profiles = engine.build_demo_payload()
        engine._TR_PACK_CACHE = {}
        profiles[1]["remediation"] = "ORIGINAL_GUIDANCE_AUDIT_ONLY"
        profiles[1]["remediationImpact"] = "ORIGINAL_IMPACT_AUDIT_ONLY"
        result = engine.analyse(scores[0], scores[1], profiles, "tr", scores)
        opened = mock_open()
        with patch("builtins.open", opened):
            engine.write_csv("synthetic-export.csv", result, "tr")
        written = "".join(call.args[0] for call in opened().write.call_args_list)
        self.assertNotIn("ORIGINAL_GUIDANCE_AUDIT_ONLY", written)
        self.assertNotIn("ORIGINAL_IMPACT_AUDIT_ONLY", written)
        self.assertIn("Güncel uygulama adımları için", written)

    def test_cards_have_no_translation_provenance_or_date_boilerplate(self):
        engine._TR_PACK_CACHE = {}
        engine._OPTIONS_PACK_CACHE = None
        rendered = self.render(generic_device=True)
        cards = [match.group(0) for match in re.finditer(
            r'<div class="dbox grow">.*?</div>|<article class="bulgu".*?</article>', rendered, re.S)]
        for fragment in cards:
            for forbidden in ("guidance-coverage", "Türkçe uygulama metni",
                              "Türkçe portal yönlendirmesi", "Kaynak inceleme tarihi",
                              "Kaynak incelemeli yerel içerik", "fn-gap",
                              "Bu madde için ek açıklama/etki", "Etki metninin Türkçe",
                              "portalın canlı içeriği veya otomatik API çıktısı"):
                self.assertNotIn(forbidden, fragment)
        self.assertEqual(rendered.count('class="guidance-method-note"'), 1)
        self.assertEqual(rendered.count('class="fi-scope"'), 1)
        self.assertIn("33/184", rendered)
        self.assertIn("151 kontrol", rendered)
        self.assertIn("bu rapor tarafından doğrulanmamıştır", rendered)
        self.assertIn(engine.STR["tr"]["fnd_scope_note"], rendered)

    def test_options_heading_and_structured_subheadings_are_prominent(self):
        rendered = self.render(generic_device=True)
        self.assertIn('<h5 class="remediation-heading">İyileştirme Seçenekleri</h5>', rendered)
        self.assertIn(".reviewed-options .remediation-heading{font-size:16px;font-weight:800", rendered)
        self.assertIn("text-transform:none;letter-spacing:normal", rendered)
        self.assertIn("border-left:3px solid", rendered)
        self.assertIn('<h6 class="guidance-subheading">Yapılandırma</h6>', rendered)
        self.assertIn("<b>Ortam bağımlılığı:</b>", rendered)
        self.assertIn("<b>Doğrulama:</b>", rendered)

    def test_material_caveats_remain_and_document_links_use_labels(self):
        engine._OPTIONS_PACK_CACHE = None
        rendered = self.render(generic_device=True)
        self.assertIn("Remote Assistance davetiyle çalışan destek akışı kapanır", rendered)
        self.assertIn("merkezi GPO veya MDM ilkesi tarafından geri yazılabilir", rendered)
        self.assertIn("Windows 10 version 1703", rendered)
        self.assertIn("REG_DWORD", rendered)
        self.assertIn("Microsoft Learn — RemoteAssistance — Policy CSP", rendered)
        self.assertNotIn("Kaynak: https://", rendered)
        entry = engine.load_remediation_options()["scid_4001"]
        self.assertIn("tüm Allow ACE", entry["changeCaveat"])
        for option in engine.load_remediation_options()["scid_87"]["options"]:
            self.assertEqual(option["verifiedDate"], "2026-10-01")
            self.assertTrue(option["applicability"])

    def test_unavailable_source_is_truthful_and_never_blank(self):
        control = {"id": "new_empty", "remediation": "", "remediationImpact": ""}
        engine.apply_translations([control], {})
        self.assertEqual(control["remediationCoverage"], "unavailable")
        self.assertEqual(control["remediation"], "Microsoft bu öneri için uygulama adımı sağlamamıştır.")
        self.assertNotIn("Yapılandırın", control["remediation"])

    def test_dependency_and_verification_content_is_shared_across_views(self):
        engine._TR_PACK_CACHE = {"mfaregistrationv2": {
            "remediation": "Pilot kapsamda onaylı öneriyi uygulayın.",
            "bagimlilik": "DEPENDENCY_PILOT_ONLY", "dogrulama": "VERIFY_EFFECTIVE_SETTING",
        }}
        rendered = self.render()
        self.assertEqual(rendered.count("DEPENDENCY_PILOT_ONLY"), 2)
        self.assertEqual(rendered.count("VERIFY_EFFECTIVE_SETTING"), 2)
        self.assertIn('<h6 class="guidance-subheading">Ortam bağımlılığı</h6>', rendered)
        self.assertIn('<h6 class="guidance-subheading">Doğrulama</h6>', rendered)


if __name__ == "__main__":
    unittest.main()

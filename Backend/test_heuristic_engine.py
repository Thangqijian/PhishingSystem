import unittest

from heuristic_engine import run_rules


class HeuristicEngineTests(unittest.TestCase):
    def test_pop_ad_campaign_url_is_high_risk_even_without_browser_context(self):
        url = (
            "https://stake.ac/?c=KE2orCKI&offer=PropPopMal"
            "&utm_source=propellerads&utm_medium=cpc"
            "&utm_campaign=km_Propeller_Pop_Malaysia_mobile_pop"
            "&utm_term=prop_pop&utm_content=crypto_sports"
            "&clickId=YUugWb4v5Z5wuwUWon2T6b"
        )

        result = run_rules(url)

        self.assertIn("ad_popup_campaign", result["rule_scores"])
        self.assertGreaterEqual(result["heuristic_risk"], 0.75)

    def test_normal_marketing_utm_url_is_not_treated_as_pop_ad_campaign(self):
        url = (
            "https://example.com/article"
            "?utm_source=newsletter&utm_medium=email&utm_campaign=summer"
        )

        result = run_rules(url)

        self.assertNotIn("ad_popup_campaign", result["rule_scores"])


if __name__ == "__main__":
    unittest.main()

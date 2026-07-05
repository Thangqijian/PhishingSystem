import unittest

from risk_policy import apply_navigation_context


class RiskPolicyTests(unittest.TestCase):
    def test_unexpected_cross_domain_tab_is_a_high_risk_behavior_signal(self):
        self.assertEqual(
            apply_navigation_context(
                27.4,
                {"unexpected_cross_domain_tab": True},
            ),
            85.0,
        )

    def test_normal_navigation_keeps_the_calculated_score(self):
        self.assertEqual(apply_navigation_context(27.4, {}), 27.4)


if __name__ == "__main__":
    unittest.main()

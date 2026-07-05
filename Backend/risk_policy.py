DECEPTIVE_REDIRECT_MIN_SCORE = 85.0


def apply_navigation_context(score, navigation_context=None):
    """Apply explainable browser-behavior signals after URL risk scoring."""
    adjusted_score = max(0.0, min(float(score), 100.0))
    context = navigation_context if isinstance(navigation_context, dict) else {}

    if context.get("unexpected_cross_domain_tab"):
        adjusted_score = max(adjusted_score, DECEPTIVE_REDIRECT_MIN_SCORE)

    return round(adjusted_score, 1)

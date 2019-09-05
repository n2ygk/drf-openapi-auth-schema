# imports of optional packages

try:
    from oauth2_provider.contrib.rest_framework.authentication import OAuth2Authentication
    from oauth2_provider.contrib.rest_framework.permissions import TokenMatchesOASRequirements
except ImportError:  # pragma: no cover
    OAuth2Authentication = None
    TokenMatchesOASRequirements = None

# DRF 3.9+ has native boolean conditions now.
# But older code may use rest_condition (or other packages).
try:
    from rest_condition import Condition
except ImportError:
    Condition = None

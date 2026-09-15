"""Negative controls for secret scanning: none of these lines contain a secret."""
import os
import uuid

# tg-negative: NEG-SECRET-001 | Secret read from environment
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
# tg-negative: NEG-SECRET-002 | Placeholder value
OPENAI_API_KEY = "<YOUR_OPENAI_API_KEY>"
# tg-negative: NEG-SECRET-003 | Template variable reference
AWS_SECRET_ACCESS_KEY = "${AWS_SECRET_ACCESS_KEY}"
# tg-negative: NEG-SECRET-004 | Empty password with secret injected at runtime
DB_PASSWORD = ""
# tg-negative: NEG-SECRET-005 | [soft] SHA-256 checksum of a release artifact (high entropy, not a secret)
RELEASE_TARBALL_SHA256 = "a79ebc752a632e806762d05ad57333e3cb9bae22bdf591aa542281071b0214a3"
# tg-negative: NEG-SECRET-006 | [soft] Git commit SHA (high entropy, not a secret)
BUILD_COMMIT = "4f78c4391dc5ad79ea71a52fcf878c5c1053ce1e"
# tg-negative: NEG-SECRET-007 | Random UUID generated at runtime
REQUEST_ID = str(uuid.uuid4())
# tg-negative: NEG-SECRET-008 | Password field name only, no value
PASSWORD_FIELD_NAME = "password"

def login(username: str, password: str) -> bool:
    """Basic test-only username/password check."""
    # tg-expect: SAST-001 | medium | CWE-798 | Hard-coded password compared in authentication logic
    return username == "admin" and password == "password123"

def login(username: str, password: str) -> bool:
    """Basic test-only username/password check."""
    return username == "admin" and password == "password123"

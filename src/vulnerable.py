# Intentional security-test fixture. Do not copy this pattern into production.
def unsafe_query(user_input):
    # tg-expect: SAST-002 | medium | CWE-89 | SQL statement built by string concatenation
    return "SELECT * FROM users WHERE name = '" + user_input + "'"

# Intentional security-test fixture. Do not copy this pattern into production.
def unsafe_query(user_input):
    return "SELECT * FROM users WHERE name = '" + user_input + "'"

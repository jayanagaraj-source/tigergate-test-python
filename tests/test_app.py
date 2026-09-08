from src.app import login


def test_login():
    assert login("admin", "password123")
    assert not login("admin", "wrong-password")

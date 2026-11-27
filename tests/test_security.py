from core import security


def test_hash_password_is_not_plain_text_and_verifies():
    password_hash = security.hash_password("Exemplo@2026")

    assert password_hash != "Exemplo@2026"
    assert security.verify_password("Exemplo@2026", password_hash)
    assert not security.verify_password("outra-senha", password_hash)


def test_generated_reset_code_has_six_digits():
    code = security.generate_reset_code()

    assert len(code) == security.RESET_CODE_LENGTH
    assert code.isdigit()


def test_reset_code_matches_only_for_the_same_student_and_secret():
    stored = security.hash_reset_code("123456", "12345", "secret")

    assert security.reset_code_matches("123456", "12345", "secret", stored)
    assert not security.reset_code_matches("654321", "12345", "secret", stored)
    assert not security.reset_code_matches("123456", "99999", "secret", stored)
    assert not security.reset_code_matches("123456", "12345", "other", stored)

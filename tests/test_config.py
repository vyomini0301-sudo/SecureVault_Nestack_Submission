import pytest

from config import positive_int


def test_positive_int_accepts_valid_value(monkeypatch):
    monkeypatch.setenv("TEST_SETTING", "10")
    assert positive_int("TEST_SETTING", 5) == 10


def test_positive_int_rejects_zero(monkeypatch):
    monkeypatch.setenv("TEST_SETTING", "0")

    with pytest.raises(ValueError):
        positive_int("TEST_SETTING", 5)


def test_positive_int_rejects_negative(monkeypatch):
    monkeypatch.setenv("TEST_SETTING", "-1")

    with pytest.raises(ValueError):
        positive_int("TEST_SETTING", 5)


def test_positive_int_rejects_value_above_maximum(monkeypatch):
    monkeypatch.setenv("TEST_SETTING", "17")

    with pytest.raises(ValueError):
        positive_int("TEST_SETTING", 12, maximum=16)


def test_positive_int_rejects_invalid_integer(monkeypatch):
    monkeypatch.setenv("TEST_SETTING", "abc")

    with pytest.raises(ValueError):
        positive_int("TEST_SETTING", 5)

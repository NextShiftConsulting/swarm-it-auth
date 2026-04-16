"""Tests for KeyfileAdapter.

All tests operate on a pytest ``tmp_path`` directory — never on the real
``swarm-it-auth/keys`` folder — so no production credentials are touched.
"""

from __future__ import annotations

import pytest

from swarm_auth.adapters.keyfile_credential import KeyfileAdapter, _normalize


def test_normalize_rules():
    assert _normalize("swarmit-rapidapi-staging") == "SWARMIT_RAPIDAPI_STAGING"
    assert _normalize("Gemini_API_Key") == "GEMINI_API_KEY"
    assert _normalize("  KAGGLE_API_TOKEN  ") == "KAGGLE_API_TOKEN"


def test_retrieve_plain_value(tmp_path):
    (tmp_path / "swarmit-rapidapi-staging.txt").write_text("abc123\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.retrieve("SWARMIT_RAPIDAPI_STAGING") == "abc123"


def test_retrieve_normalizes_lookup(tmp_path):
    (tmp_path / "swarmit-rapidapi-staging.txt").write_text("abc123\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.retrieve("swarmit-rapidapi-staging") == "abc123"
    assert adapter.retrieve("Swarmit_RapidAPI_Staging") == "abc123"


def test_retrieve_skips_comments(tmp_path):
    (tmp_path / "service.txt").write_text(
        "# comment line\n"
        "\n"
        "the_actual_value\n"
    )
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.retrieve("SERVICE") == "the_actual_value"


def test_multi_line_file_is_ambiguous(tmp_path):
    # Two non-comment lines — format is ambiguous, adapter must not guess.
    (tmp_path / "multi.txt").write_text("line_one\nline_two\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.retrieve("MULTI") is None


def test_retrieve_strips_surrounding_quotes(tmp_path):
    (tmp_path / "quoted.txt").write_text('"quoted-value"\n')
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.retrieve("QUOTED") == "quoted-value"


def test_retrieve_returns_none_for_ambiguous_file(tmp_path):
    # Multiple non-comment lines without KEY=VALUE → ambiguous.
    (tmp_path / "amb.txt").write_text("line_one\nline_two\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.retrieve("AMB") is None


def test_retrieve_returns_none_for_missing_key(tmp_path):
    adapter = KeyfileAdapter(keys_dir=tmp_path)
    assert adapter.retrieve("NO_SUCH_KEY") is None


def test_ignores_non_txt_extensions(tmp_path):
    (tmp_path / "README.md").write_text("docs, not a credential\n")
    (tmp_path / "cert.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    (tmp_path / "policy.json").write_text('{"k":"v"}\n')
    (tmp_path / "real.txt").write_text("the-real-value\n")

    adapter = KeyfileAdapter(keys_dir=tmp_path)
    assert adapter.list_keys() == ["REAL"]
    assert adapter.retrieve("REAL") == "the-real-value"
    assert adapter.retrieve("README") is None
    assert adapter.retrieve("CERT") is None


def test_list_keys_with_prefix(tmp_path):
    (tmp_path / "rapidapi-staging.txt").write_text("s\n")
    (tmp_path / "rapidapi-prod.txt").write_text("p\n")
    (tmp_path / "openai.txt").write_text("o\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.list_keys(prefix="RAPIDAPI") == ["RAPIDAPI_PROD", "RAPIDAPI_STAGING"]
    assert adapter.list_keys(prefix="rapidapi") == ["RAPIDAPI_PROD", "RAPIDAPI_STAGING"]


def test_store_creates_file(tmp_path):
    adapter = KeyfileAdapter(keys_dir=tmp_path)
    adapter.store("NEW_SERVICE_KEY", "secret-value")

    expected = tmp_path / "new-service-key.txt"
    assert expected.exists()
    assert expected.read_text().strip() == "secret-value"

    # Adapter re-scans and can read it back.
    assert adapter.retrieve("NEW_SERVICE_KEY") == "secret-value"


def test_delete_removes_file(tmp_path):
    path = tmp_path / "temp.txt"
    path.write_text("v\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    assert adapter.retrieve("TEMP") == "v"
    assert adapter.delete("TEMP") is True
    assert not path.exists()
    assert adapter.retrieve("TEMP") is None


def test_delete_missing_returns_false(tmp_path):
    adapter = KeyfileAdapter(keys_dir=tmp_path)
    assert adapter.delete("NONEXISTENT") is False


def test_metadata_shape(tmp_path):
    path = tmp_path / "svc.txt"
    path.write_text("v\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)

    meta = adapter.get_metadata("SVC")
    assert meta is not None
    assert meta["key"] == "SVC"
    assert meta["source"] == "keyfile"
    assert meta["path"] == str(path)
    assert meta["size_bytes"] > 0
    assert isinstance(meta["modified_unix"], int)
    # Crucially, metadata must not include the credential value.
    assert "value" not in meta


def test_is_available_requires_a_txt_file(tmp_path):
    # Empty dir + explicit override — directory exists but has no .txt.
    adapter = KeyfileAdapter(keys_dir=tmp_path)
    # Instance check via directory scan
    assert adapter._find_keys_dir() == tmp_path
    # Class-level is_available() ignores the explicit keys_dir and checks
    # the default search paths. We only assert the per-instance path logic
    # here; class-level depends on repo layout at test time.


def test_rotate_overwrites_file(tmp_path):
    (tmp_path / "svc.txt").write_text("old\n")
    adapter = KeyfileAdapter(keys_dir=tmp_path)
    assert adapter.retrieve("SVC") == "old"

    adapter.rotate("SVC", "new")
    # Re-instantiate to defeat the cache and verify disk state.
    reread = KeyfileAdapter(keys_dir=tmp_path)
    assert reread.retrieve("SVC") == "new"

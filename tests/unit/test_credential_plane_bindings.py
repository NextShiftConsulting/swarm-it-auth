"""ADR-026 Rule 8 — plane bindings + generic `swarm-auth run` primitive.

Covers: correct logical name -> expected backing reference; unknown name fails
closed; plaintext secret bodies resolve; the child subprocess receives injected
vars and stdin; the parent environment is unchanged afterward; values never leak.
"""

from __future__ import annotations

import os
import sys

import pytest

from swarm_auth.bindings import BINDINGS, SecretBinding, get_binding
from swarm_auth.adapters.aws_credential import AWSSecretsAdapter
from swarm_auth.cli import run as run_cli

SECRET_VALUE = "s3cr3t-NEVER-LOG-abc123"


# --- bindings registry ------------------------------------------------------

def test_bound_logical_names_map_to_expected_backing():
    assert get_binding("CLOUDFLARE_DEPLOY_TOKEN").backing == "cloudflare/api-token"
    nxt = get_binding("COMMERCE_INTERNAL_KEY_NEXT")
    assert nxt.backing.endswith("swarmit/internal-service-key-next-7hZbMN")
    assert all(b.plaintext for b in BINDINGS.values())


def test_unknown_logical_name_is_unbound():
    assert get_binding("NOPE_NOT_A_BINDING") is None


def test_registry_contains_no_values():
    # The registry carries names/purpose only, never a credential value.
    for b in BINDINGS.values():
        assert SECRET_VALUE not in (b.backing + b.purpose)


# --- AWS adapter uses the binding + handles plaintext ----------------------

class _FakeSMClient:
    class exceptions:
        class ResourceNotFoundException(Exception):
            pass

    def __init__(self, expect_secret_id, body):
        self._expect = expect_secret_id
        self._body = body
        self.asked = None

    def get_secret_value(self, SecretId):
        self.asked = SecretId
        if SecretId != self._expect:
            raise self.exceptions.ResourceNotFoundException()
        return {"SecretString": self._body}


def _adapter_with(client):
    a = object.__new__(AWSSecretsAdapter)  # bypass boto3 __init__
    a._prefix = "swarm-it/"
    a._client = client
    return a


def test_retrieve_bound_name_uses_exact_backing_and_returns_plaintext():
    b = get_binding("CLOUDFLARE_DEPLOY_TOKEN")
    client = _FakeSMClient(expect_secret_id=b.backing, body=SECRET_VALUE)
    adapter = _adapter_with(client)
    assert adapter.retrieve("CLOUDFLARE_DEPLOY_TOKEN") == SECRET_VALUE
    assert client.asked == "cloudflare/api-token"  # NOT swarm-it/CLOUDFLARE_DEPLOY_TOKEN


def test_retrieve_unbound_name_uses_prefix_and_json_envelope():
    client = _FakeSMClient(expect_secret_id="swarm-it/OPENAI_API_KEY",
                           body='{"value": "json-wrapped"}')
    adapter = _adapter_with(client)
    assert adapter.retrieve("OPENAI_API_KEY") == "json-wrapped"


# --- generic `swarm-auth run` primitive -------------------------------------

@pytest.fixture
def fake_plane(monkeypatch):
    table = {"COMMERCE_INTERNAL_KEY_NEXT": SECRET_VALUE, "CLOUDFLARE_DEPLOY_TOKEN": "cf-tok"}
    monkeypatch.setattr(run_cli, "_resolve", lambda name: table.get(name))
    return table


def test_run_injects_env_into_child_and_leaves_parent_unchanged(fake_plane, capfd):
    assert "TOOL_TOKEN" not in os.environ
    # Child prints only whether the var is present, never the value.
    child = "import os; print('HAS' if os.environ.get('TOOL_TOKEN')=='cf-tok' else 'MISS')"
    rc = run_cli.main(["--env", "TOOL_TOKEN=CLOUDFLARE_DEPLOY_TOKEN", "--",
                       sys.executable, "-c", child])
    out, err = capfd.readouterr()
    assert rc == 0
    assert "HAS" in out
    assert "TOOL_TOKEN" not in os.environ           # parent env unchanged
    assert "cf-tok" not in out and "cf-tok" not in err  # value never leaked


def test_run_delivers_stdin_secret_without_leaking(fake_plane, capfd):
    # Child reports the LENGTH of stdin, never the content.
    child = "import sys; d=sys.stdin.read(); print('LEN', len(d))"
    rc = run_cli.main(["--stdin", "COMMERCE_INTERNAL_KEY_NEXT", "--",
                       sys.executable, "-c", child])
    out, err = capfd.readouterr()
    assert rc == 0
    assert f"LEN {len(SECRET_VALUE)}" in out
    assert SECRET_VALUE not in out and SECRET_VALUE not in err


def test_run_fails_closed_on_unknown_name(fake_plane, capfd):
    ran_marker = "SHOULD_NOT_RUN"
    rc = run_cli.main(["--env", "X=NO_SUCH_CREDENTIAL", "--",
                       sys.executable, "-c", f"print('{ran_marker}')"])
    out, err = capfd.readouterr()
    assert rc == 3
    assert ran_marker not in out          # command must NOT have run
    assert "did not resolve" in err
    assert "NO_SUCH_CREDENTIAL" in err     # names the logical name


def test_run_requires_a_command(fake_plane, capfd):
    rc = run_cli.main(["--env", "X=CLOUDFLARE_DEPLOY_TOKEN"])
    _, err = capfd.readouterr()
    assert rc == 2
    assert "no command" in err


def test_run_does_not_forward_unrelated_operator_secrets(fake_plane, capfd, monkeypatch):
    # An unrelated credential sitting in the operator shell must NOT reach the child.
    monkeypatch.setenv("UNRELATED_API_KEY", "leaky-operator-secret-xyz")
    child = ("import os; "
             "print('LEAK' if os.environ.get('UNRELATED_API_KEY') else 'CLEAN')")
    rc = run_cli.main(["--env", "TOOL_TOKEN=CLOUDFLARE_DEPLOY_TOKEN", "--",
                       sys.executable, "-c", child])
    out, err = capfd.readouterr()
    assert rc == 0
    assert "CLEAN" in out
    assert "leaky-operator-secret-xyz" not in out and "leaky-operator-secret-xyz" not in err


def test_run_inherit_named_var_passes_it_through(fake_plane, capfd, monkeypatch):
    monkeypatch.setenv("MY_REGION", "us-east-1")
    child = "import os; print('R=' + os.environ.get('MY_REGION', 'none'))"
    rc = run_cli.main(["--inherit", "MY_REGION", "--", sys.executable, "-c", child])
    out, _ = capfd.readouterr()
    assert rc == 0
    assert "R=us-east-1" in out


def test_run_inherit_all_opts_into_full_env(fake_plane, capfd, monkeypatch):
    monkeypatch.setenv("BROAD_VAR", "present")
    child = "import os; print('B=' + os.environ.get('BROAD_VAR', 'none'))"
    rc = run_cli.main(["--inherit-all", "--", sys.executable, "-c", child])
    out, _ = capfd.readouterr()
    assert rc == 0
    assert "B=present" in out


def test_run_preserves_child_exit_code(fake_plane):
    rc = run_cli.main(["--", sys.executable, "-c", "import sys; sys.exit(7)"])
    assert rc == 7

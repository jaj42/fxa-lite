# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""`fxa-lite account …` — the only way an account is meant to come into being."""

from __future__ import annotations

import json

import pytest

from fxa_lite.cli import main
from fxa_lite.db import open_database

PASSWORD = "correct horse battery staple"


def add(config_file, email: str, password: str) -> int:
    return main(["account", "add", "-c", str(config_file), email, "--password", password])


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "fxa.toml"
    path.write_text(
        'public_url = "http://localhost:9000"\n'
        "[paths]\n"
        'database = "fxa.sqlite"\n'
        'signing_key = "signing-key.json"\n'
    )
    return path


def test_add_list_remove(config_file, capsys) -> None:
    assert add(config_file, "bob@example.com", PASSWORD) == 0
    assert "created bob@example.com" in capsys.readouterr().out

    assert main(["account", "list", "-c", str(config_file)]) == 0
    assert "bob@example.com" in capsys.readouterr().out

    assert main(["account", "remove", "-f", "-c", str(config_file), "bob@example.com"]) == 0
    assert "deleted" in capsys.readouterr().out

    assert main(["account", "list", "-c", str(config_file)]) == 0
    assert "no accounts" in capsys.readouterr().out


def test_add_rejects_a_duplicate(config_file, capsys) -> None:
    add(config_file, "bob@example.com", PASSWORD)
    capsys.readouterr()
    with pytest.raises(SystemExit) as caught:
        add(config_file, "BOB@example.com", PASSWORD)
    assert caught.value.code == 1
    assert "already exists" in capsys.readouterr().err


def test_add_rejects_a_short_password(config_file, capsys) -> None:
    """The password is the Sync encryption key; eight characters is not enough
    for something that never gets rotated."""
    assert add(config_file, "bob@example.com", "short") == 1
    assert "at least" in capsys.readouterr().err


def test_remove_reports_an_unknown_account(config_file, capsys) -> None:
    assert main(["account", "remove", "-f", "-c", str(config_file), "nobody@example.com"]) == 1
    assert "no such account" in capsys.readouterr().err


def test_a_cli_account_can_sign_in(config_file) -> None:
    """The CLI and `/account/create` must produce byte-identical account rows,
    or an account added on the server could not sign in from a browser."""
    from conformance.client import get_credentials
    from fxa_lite import accounts

    add(config_file, "bob@example.com", PASSWORD)
    database = open_database(config_file.parent / "fxa.sqlite")
    try:
        credentials = get_credentials("bob@example.com", PASSWORD)
        account, _ = accounts.authenticate(
            database, email="bob@example.com", auth_pw=credentials.auth_pw
        )
        assert account.email == "bob@example.com"
    finally:
        database.close()


def test_serve_refuses_without_a_signing_key(config_file, capsys) -> None:
    assert main(["serve", "-c", str(config_file)]) == 1
    assert "keygen" in capsys.readouterr().err


def test_keygen_then_serve_finds_the_key(config_file, capsys, monkeypatch) -> None:
    assert main(["keygen", "-c", str(config_file)]) == 0
    key = json.loads((config_file.parent / "signing-key.json").read_text())
    assert key["kty"] == "RSA"

    served = {}

    def fake_run(app, **kwargs):
        served.update(kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)
    assert main(["serve", "-c", str(config_file), "--port", "9999"]) == 0
    assert served["port"] == 9999

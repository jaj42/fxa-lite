import json
import stat
from pathlib import Path

import pytest

from fxa_lite import cli
from fxa_lite.crypto import jose


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "fxa.toml").write_text(
        'public_url = "http://localhost:9000"\n\n[paths]\nsigning_key = "keys/signing.json"\n'
    )
    return tmp_path


def test_keygen_writes_a_usable_private_jwk(project: Path, capsys) -> None:
    assert cli.main(["keygen", "--config", str(project / "fxa.toml")]) == 0

    destination = project / "keys" / "signing.json"
    jwk = json.loads(destination.read_text())
    key = jose.jwk_to_private_key(jwk)

    assert key.key_size == 2048
    assert jwk["kid"] == jose.key_id(key.public_key())
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] in capsys.readouterr().out


def test_keygen_key_file_is_not_world_readable(project: Path) -> None:
    cli.main(["keygen", "--config", str(project / "fxa.toml")])

    mode = (project / "keys" / "signing.json").stat().st_mode
    assert stat.S_IMODE(mode) & 0o077 == 0


def test_keygen_refuses_to_clobber(project: Path, capsys) -> None:
    config = str(project / "fxa.toml")
    cli.main(["keygen", "--config", config])
    original = (project / "keys" / "signing.json").read_text()

    assert cli.main(["keygen", "--config", config]) == 1
    assert (project / "keys" / "signing.json").read_text() == original
    assert "--force" in capsys.readouterr().err
    assert not list((project / "keys").glob("*.tmp"))

    assert cli.main(["keygen", "--config", config, "--force"]) == 0
    assert (project / "keys" / "signing.json").read_text() != original


def test_keygen_output_overrides_config(tmp_path: Path) -> None:
    destination = tmp_path / "elsewhere.json"

    assert cli.main(["keygen", "--output", str(destination)]) == 0
    assert json.loads(destination.read_text())["kty"] == "RSA"


def test_keygen_reports_a_bad_config(tmp_path: Path, capsys) -> None:
    (tmp_path / "fxa.toml").write_text("public_url = 3\n")

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["keygen", "--config", str(tmp_path / "fxa.toml")])

    assert exit_info.value.code == 2
    assert "config error" in capsys.readouterr().err


def test_version(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])

    assert exit_info.value.code == 0
    assert "fxa-lite" in capsys.readouterr().out

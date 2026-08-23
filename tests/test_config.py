import re
import textwrap
from pathlib import Path

import pytest

from fxa_lite import config


def write(tmp_path: Path, body: str, name: str = "fxa.toml") -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return path


def test_defaults(tmp_path: Path) -> None:
    cfg = config.load(write(tmp_path, 'public_url = "http://localhost:9000"'))

    assert cfg.listen == config.ListenConfig("127.0.0.1", 9000)
    assert cfg.ttl.access_token == 6 * 3600
    assert cfg.ttl.authorization_code == 900
    assert cfg.ttl.tokenserver_token == 3600
    assert cfg.paths.database == tmp_path / "fxa.sqlite"
    assert cfg.paths.signing_key == tmp_path / "signing-key.json"
    assert cfg.paths.retired_key is None
    assert cfg.tokenserver_shared_secret is None
    assert cfg.source == tmp_path / "fxa.toml"


def test_full_config(tmp_path: Path) -> None:
    cfg = config.load(
        write(
            tmp_path,
            """
            public_url = "https://accounts.example.org/"
            tokenserver_shared_secret = "s3kr1t"

            [listen]
            host = "0.0.0.0"
            port = 8443

            [paths]
            database = "state/fxa.sqlite"
            signing_key = "/etc/fxa/signing-key.json"
            retired_key = "state/retired.json"

            [ttl]
            access_token = 3600
            authorization_code = 300
            tokenserver_token = 1800
            """,
        )
    )

    assert cfg.public_url == "https://accounts.example.org"
    assert cfg.listen == config.ListenConfig("0.0.0.0", 8443)
    assert cfg.paths.database == tmp_path / "state" / "fxa.sqlite"
    assert cfg.paths.signing_key == Path("/etc/fxa/signing-key.json")
    assert cfg.paths.retired_key == tmp_path / "state" / "retired.json"
    assert cfg.ttl == config.TtlConfig(3600, 300, 1800)
    assert cfg.tokenserver_shared_secret == "s3kr1t"


def test_url_helper() -> None:
    cfg = config.from_dict({"public_url": "https://accounts.example.org"})

    assert cfg.url() == "https://accounts.example.org"
    assert cfg.url("/v1/jwks") == "https://accounts.example.org/v1/jwks"
    assert cfg.url("token/1.0/sync/1.5") == "https://accounts.example.org/token/1.0/sync/1.5"


@pytest.mark.parametrize(
    "body, message",
    [
        ("", "missing required key public_url"),
        ('public_url = "localhost:9000"', "absolute http(s) URL"),
        ('public_url = "ftp://example.org"', "absolute http(s) URL"),
        ('public_url = "https://x.org/?a=b"', "query string"),
        ('public_url = "https://x.org"\npublik_url = 1', "unknown key(s) in config: publik_url"),
        ('public_url = "https://x.org"\n[listen]\nport = 0', "listen.port out of range"),
        ('public_url = "https://x.org"\n[listen]\nport = true', "listen.port must be int"),
        ('public_url = "https://x.org"\n[listen]\nhost = 1', "listen.host must be str"),
        ('public_url = "https://x.org"\n[listen]\nhostname = "x"', "unknown key(s) in [listen]"),
        ('public_url = "https://x.org"\n[ttl]\naccess_token = 0', "ttl.access_token must be"),
        ('public_url = "https://x.org"\ntokenserver_shared_secret = ""', "non-empty string"),
        ('public_url = "https://x.org"\nlisten = 3', "[listen] must be a table"),
        ("public_url = [", "invalid TOML"),
    ],
)
def test_rejects_bad_config(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(config.ConfigError, match=re.escape(message)):
        config.load(write(tmp_path, body))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(config.ConfigError, match="cannot read config"):
        config.load(tmp_path / "nope.toml")


def test_example_config_is_valid() -> None:
    cfg = config.load(Path(__file__).resolve().parents[1] / "fxa.example.toml")

    assert cfg.public_url == "http://localhost:9000"

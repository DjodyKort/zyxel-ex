""".env support: which file is used, and how its values rank against flags and env vars."""

from __future__ import annotations

from pathlib import Path

from fake_gateway import FakeGateway, zyx

from zyxel_ex.cli import find_env_file


def _env_file(directory: Path, **values: str) -> Path:
    path = directory / ".env"
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    return path


def test_env_file_supplies_the_settings(tmp_path: Path) -> None:
    gw = FakeGateway(tables={"nat": []})
    env = _env_file(tmp_path, ZY_HOST="gw", ZY_USER="admin", ZY_PASS="s3cret")
    result = zyx(gw, "--env-file", str(env), "nat", "list")
    assert result.exit_code == 0, result.output
    assert gw.logins == 1


def test_env_file_can_be_named_by_variable(tmp_path: Path) -> None:
    gw = FakeGateway(tables={"nat": []})
    env = _env_file(tmp_path, ZY_PASS="s3cret")
    result = zyx(gw, "nat", "list", env={"ZY_ENV_FILE": str(env)})
    assert result.exit_code == 0, result.output


def test_flag_beats_environment_beats_env_file(tmp_path: Path) -> None:
    env = _env_file(tmp_path, ZY_PASS="from-file")
    by_variable = FakeGateway(password="from-env")
    assert zyx(by_variable, "--env-file", str(env), "nat", "list", env={"ZY_PASS": "from-env"}).exit_code == 0
    by_flag = FakeGateway(password="from-flag")
    result = zyx(
        by_flag, "--env-file", str(env), "--password", "from-flag", "nat", "list", env={"ZY_PASS": "x"}
    )
    assert result.exit_code == 0, result.output


def test_env_file_sets_sha512(tmp_path: Path) -> None:
    gw = FakeGateway(sha512=True, tables={"nat": []})
    env = _env_file(tmp_path, ZY_PASS="s3cret", ZY_SHA512="true")
    assert zyx(gw, "--env-file", str(env), "nat", "list").exit_code == 0


def test_find_env_file_prefers_the_working_directory(tmp_path: Path) -> None:
    cwd, home = tmp_path / "project", tmp_path / "home"
    cwd.mkdir()
    assert find_env_file(cwd, home) is None
    user_file = home / ".config" / "zyxel-ex" / ".env"
    user_file.parent.mkdir(parents=True)
    user_file.touch()
    assert find_env_file(cwd, home) == user_file
    project_file = _env_file(cwd)
    assert find_env_file(cwd, home) == project_file

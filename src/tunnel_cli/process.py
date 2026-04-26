import os
import signal
import subprocess
from datetime import UTC, datetime
from typing import Any

import click
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .config import read_json_file, write_json_file
from .paths import log_path, state_path


class TunnelProcessState(BaseModel):
    model_config = ConfigDict(frozen=True)

    pid: int = Field(gt=0)
    log_file: str
    command: list[str]
    tunnel_id: str
    started_at: str

    @field_validator("log_file", "tunnel_id", "started_at", mode="before")
    @classmethod
    def strip_required_string(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("must be a non-empty string")
        return value.strip()


def load_state() -> TunnelProcessState | None:
    raw = read_json_file(state_path())
    if raw is None:
        return None
    try:
        return TunnelProcessState.model_validate(raw)
    except ValidationError as exc:
        raise click.ClickException(f"invalid process state in {state_path()}: {exc}") from exc


def save_state(state: TunnelProcessState) -> None:
    write_json_file(state_path(), state.model_dump())


def clear_state() -> None:
    path = state_path()
    if path.exists():
        path.unlink()


def process_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def state_process_is_running(state: TunnelProcessState) -> bool:
    if not process_is_running(state.pid):
        return False

    try:
        completed = subprocess.run(
            ["ps", "-p", str(state.pid), "-o", "command="],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False

    command_line = completed.stdout.strip()
    return "cloudflared" in command_line and state.tunnel_id in command_line


def start_tunnel_process(command: list[str], tunnel_id: str) -> TunnelProcessState:
    log_file = log_path()
    log_file.parent.mkdir(parents=True, exist_ok=True)
    handle = log_file.open("ab")
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise click.ClickException(f"command not found: {command[0]}") from exc
    finally:
        handle.close()

    state = TunnelProcessState(
        pid=process.pid,
        log_file=str(log_file),
        command=command,
        tunnel_id=tunnel_id,
        started_at=datetime.now(UTC).isoformat(),
    )
    save_state(state)
    return state


def stop_tunnel_process(state: TunnelProcessState) -> bool:
    if not state_process_is_running(state):
        clear_state()
        return False

    try:
        os.kill(state.pid, signal.SIGTERM)
    except ProcessLookupError:
        clear_state()
        return False

    clear_state()
    return True

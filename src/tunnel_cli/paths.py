from pathlib import Path


def tunnel_home() -> Path:
    return Path.home() / ".tunnel"


def config_path() -> Path:
    return tunnel_home() / "config.json"


def cloudflared_config_path() -> Path:
    return tunnel_home() / "cloudflared.yml"


def cloudflared_credentials_path() -> Path:
    return tunnel_home() / "cloudflared-credentials.json"


def credentials_path() -> Path:
    return tunnel_home() / "credentials.json"


def state_path() -> Path:
    return tunnel_home() / "state.json"


def log_path() -> Path:
    return tunnel_home() / "cloudflared.log"

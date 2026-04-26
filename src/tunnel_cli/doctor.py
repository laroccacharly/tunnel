import socket
from pathlib import Path

import click

from .cloudflared import run_command_output
from .config import TunnelConfig
from .paths import config_path, credentials_path

Check = tuple[str, bool, str]


def check_tcp_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def cloudflare_tunnel_check(tunnel_id: str) -> Check:
    try:
        run_command_output(["cloudflared", "tunnel", "info", tunnel_id])
        return "cloudflare-tunnel", True, tunnel_id
    except click.ClickException as exc:
        return "cloudflare-tunnel", False, str(exc)


def public_dns_check(hostname: str) -> Check:
    try:
        return "public-dns", bool(socket.getaddrinfo(hostname, 443)), hostname
    except OSError as exc:
        return "public-dns", False, str(exc)


def checks_for(config: TunnelConfig) -> list[Check]:
    return [
        ("config-file", config_path().exists(), str(config_path())),
        ("credentials-file", credentials_path().exists(), str(credentials_path())),
        ("cloudflared-config", Path(config.cloudflared_config).exists(), config.cloudflared_config),
        ("cloudflared-credentials", Path(config.cloudflared_credentials).exists(), config.cloudflared_credentials),
        ("local-service", check_tcp_port(config.service_host, config.service_port), config.service_url),
        cloudflare_tunnel_check(config.tunnel_id),
        public_dns_check(config.hostname),
    ]

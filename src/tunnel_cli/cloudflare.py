import base64
import secrets
from dataclasses import dataclass
from typing import Any

import click
import requests

API_BASE_URL = "https://api.cloudflare.com/client/v4"


@dataclass(frozen=True)
class Account:
    id: str
    name: str


@dataclass(frozen=True)
class Zone:
    id: str
    name: str
    account_id: str
    account_name: str


@dataclass(frozen=True)
class CloudflareTunnel:
    id: str
    name: str


class CloudflareClient:
    def __init__(self, api_token: str):
        self.api_token = api_token

    def request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = requests.request(
                method,
                f"{API_BASE_URL}{path}",
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                },
                json=json_body,
                params=params,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise click.ClickException(f"Cloudflare request failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise click.ClickException(f"Cloudflare returned non-JSON response: HTTP {response.status_code}") from exc

        if response.ok and payload.get("success") is True:
            return payload

        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            messages: list[str] = []
            for error in errors:
                if isinstance(error, dict) and isinstance(error.get("message"), str):
                    messages.append(error["message"])
            if messages:
                raise click.ClickException("; ".join(messages))

        raise click.ClickException(f"Cloudflare request failed: HTTP {response.status_code}")

    def verify_token(self, account_id: str | None = None) -> None:
        if account_id is None:
            self.request("GET", "/user/tokens/verify")
            return

        self.request("GET", f"/accounts/{account_id}/tokens/verify")

    def list_accounts(self) -> list[Account]:
        payload = self.request("GET", "/accounts", params={"per_page": 50})
        result = payload.get("result")
        if not isinstance(result, list):
            raise click.ClickException("Cloudflare accounts response was not a list")

        accounts: list[Account] = []
        for item in result:
            if not isinstance(item, dict):
                continue
            account_id = item.get("id")
            name = item.get("name")
            if isinstance(account_id, str) and isinstance(name, str):
                accounts.append(Account(id=account_id, name=name))
        return accounts

    def list_zones(self) -> list[Zone]:
        payload = self.request("GET", "/zones", params={"per_page": 50})
        result = payload.get("result")
        if not isinstance(result, list):
            raise click.ClickException("Cloudflare zones response was not a list")

        zones: list[Zone] = []
        for item in result:
            if not isinstance(item, dict):
                continue
            zone_id = item.get("id")
            zone_name = item.get("name")
            account = item.get("account")
            if not isinstance(zone_id, str) or not isinstance(zone_name, str):
                continue
            if not isinstance(account, dict):
                continue
            account_id = account.get("id")
            account_name = account.get("name")
            if isinstance(account_id, str) and isinstance(account_name, str):
                zones.append(Zone(zone_id, zone_name, account_id, account_name))
        return zones

    def list_tunnels(self, account_id: str) -> list[CloudflareTunnel]:
        payload = self.request("GET", f"/accounts/{account_id}/cfd_tunnel", params={"is_deleted": "false"})
        result = payload.get("result")
        if not isinstance(result, list):
            raise click.ClickException("Cloudflare tunnels response was not a list")

        tunnels: list[CloudflareTunnel] = []
        for item in result:
            if not isinstance(item, dict):
                continue
            tunnel_id = item.get("id")
            name = item.get("name")
            if isinstance(tunnel_id, str) and isinstance(name, str):
                tunnels.append(CloudflareTunnel(id=tunnel_id, name=name))
        return tunnels

    def get_or_create_tunnel(self, account_id: str, tunnel_name: str) -> CloudflareTunnel:
        for tunnel in self.list_tunnels(account_id):
            if tunnel.name == tunnel_name:
                return tunnel

        secret = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        payload = self.request(
            "POST",
            f"/accounts/{account_id}/cfd_tunnel",
            json_body={"name": tunnel_name, "tunnel_secret": secret},
        )
        result = payload.get("result")
        if not isinstance(result, dict):
            raise click.ClickException("Cloudflare tunnel create response was not an object")

        tunnel_id = result.get("id")
        name = result.get("name")
        if not isinstance(tunnel_id, str) or not isinstance(name, str):
            raise click.ClickException("Cloudflare tunnel create response was missing id/name")
        return CloudflareTunnel(id=tunnel_id, name=name)

    def configure_tunnel(self, account_id: str, tunnel_id: str, hostname: str, service_url: str) -> None:
        self.request(
            "PUT",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json_body={
                "config": {
                    "ingress": [
                        {"hostname": hostname, "service": service_url},
                        {"service": "http_status:404"},
                    ]
                }
            },
        )

    def upsert_dns_cname(self, zone_id: str, hostname: str, tunnel_id: str) -> None:
        target = f"{tunnel_id}.cfargotunnel.com"
        payload = self.request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": "CNAME", "name": hostname, "per_page": 50},
        )
        result = payload.get("result")
        if not isinstance(result, list):
            raise click.ClickException("Cloudflare DNS records response was not a list")

        record_payload = {
            "type": "CNAME",
            "name": hostname,
            "content": target,
            "ttl": 1,
            "proxied": True,
        }
        for item in result:
            if not isinstance(item, dict):
                continue
            record_id = item.get("id")
            if isinstance(record_id, str):
                self.request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", json_body=record_payload)
                return

        self.request("POST", f"/zones/{zone_id}/dns_records", json_body=record_payload)

    def tunnel_status(self, account_id: str, tunnel_id: str) -> dict[str, Any]:
        payload = self.request("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise click.ClickException("Cloudflare tunnel status response was not an object")
        return result

    def tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        payload = self.request("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token")
        result = payload.get("result")
        if not isinstance(result, str) or not result:
            raise click.ClickException("Cloudflare tunnel token response was missing token")
        return result

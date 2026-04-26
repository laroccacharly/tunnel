import json
from dataclasses import dataclass
from typing import Any

import click
import requests

API_BASE_URL = "https://api.cloudflare.com/client/v4"


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

    def _raise_v4_error(self, method: str, path: str, response: requests.Response, payload: dict[str, Any]) -> None:
        status = response.status_code
        lines: list[str] = [
            f"Cloudflare API {method} {path} failed (HTTP {status}).",
        ]
        ray = response.headers.get("cf-ray")
        if ray:
            lines.append(f"cf-ray: {ray} (quote this if you contact Cloudflare support)")
        if status in (401, 403) and "/cfd_tunnel" in path:
            lines.append(
                "Hint: Tunnels are account-scoped. Zone API permissions (DNS Read/Write, Zone Read, "
                "Settings, etc.) do not apply to /accounts/.../cfd_tunnel/... — you need a separate line on "
                "the token for this account, e.g. Account → Cloudflare Tunnel → Edit (and Read, if offered). "
                "That is why `tunnel init` can still work (DNS) while `tunnel delete` fails here."
            )
            lines.append(
                "Workaround: if `cloudflared tunnel login` works on this machine, run: "
                "`cloudflared tunnel delete` with your tunnel name (uses cert.pem, not the API token)."
            )
        elif status in (401, 403):
            lines.append(
                "Hint: The API token in ~/.tunnel/credentials.json may be wrong, expired, or lack "
                "permission for this call (e.g. Account for tunnels, Zone for DNS)."
            )

        errors = payload.get("errors")
        if isinstance(errors, list) and status not in (401, 403) and any(
            isinstance(e, dict) and isinstance(e.get("message"), str) and "auth" in e["message"].lower()
            for e in errors
        ):
            lines.append(
                "Hint: Message mentions authentication. Verify the API token in ~/.tunnel/credentials.json is "
                "valid; tunnel delete needs permission to remove tunnels (e.g. Account/Cloudflare Tunnel/Edit) "
                "in addition to DNS permissions used during init."
            )
        if isinstance(errors, list) and errors:
            lines.append("errors:")
            for i, err in enumerate(errors, start=1):
                if not isinstance(err, dict):
                    lines.append(f"  {i}. {err!r}")
                    continue
                code = err.get("code")
                msg = err.get("message")
                doc = err.get("documentation_url")
                chain = err.get("error_chain")
                parts: list[str] = []
                if code is not None:
                    parts.append(f"code={code!r}")
                if isinstance(msg, str) and msg:
                    parts.append(f"message={msg!r}")
                if isinstance(doc, str) and doc:
                    parts.append(f"doc={doc}")
                if parts:
                    lines.append(f"  {i}. " + ", ".join(parts))
                for key, val in err.items():
                    if key in {"code", "message", "documentation_url", "error_chain"}:
                        continue
                    if val is not None and val != []:
                        lines.append(f"      {key}: {val!r}")
                if isinstance(chain, list) and chain:
                    try:
                        chain_text = json.dumps(chain, indent=2)[:3000]
                    except (TypeError, ValueError):
                        chain_text = repr(chain)[:3000]
                    lines.append("      error_chain:\n" + "\n".join("        " + line for line in chain_text.splitlines()))

        messages = payload.get("messages")
        if isinstance(messages, list) and messages and messages is not errors:
            lines.append("messages:")
            for message in messages:
                if isinstance(message, dict):
                    lines.append("  " + json.dumps(message, default=str)[:2000])
                else:
                    lines.append(f"  {message!r}")

        if payload.get("success") is not None:
            lines.append(f"success field in body: {payload.get('success')!r}")
        try:
            body_preview = json.dumps(payload, indent=2, default=str)[:8000]
        except (TypeError, ValueError):
            body_preview = repr(payload)[:8000]
        lines.append("full JSON body:")
        lines.append(body_preview)

        raise click.ClickException("\n".join(lines))

    def _response_json_or_raise(self, method: str, path: str, response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            raw = (response.text or "")[:4000]
            extra = f" cf-ray={response.headers.get('cf-ray')!r}" if response.headers.get("cf-ray") else ""
            raise click.ClickException(
                f"Cloudflare API {method} {path} returned non-JSON (HTTP {response.status_code}){extra}:\n{raw}"
            ) from None

    def _parse_v4_response(self, method: str, path: str, response: requests.Response) -> dict[str, Any]:
        payload = self._response_json_or_raise(method, path, response)
        if not isinstance(payload, dict):
            raise click.ClickException(
                f"Cloudflare API {method} {path} returned JSON that was not an object: {type(payload).__name__!r}\n"
                f"Raw: {str(payload)[:2000]!r}"
            )
        if response.ok and payload.get("success") is True:
            return payload
        self._raise_v4_error(method, path, response, payload)
        raise AssertionError

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
            raise click.ClickException(f"Network error calling Cloudflare API {method} {path}: {exc}") from exc

        return self._parse_v4_response(method, path, response)

    def result_list(self, method: str, path: str, *, params: dict[str, Any] | None = None, label: str) -> list[Any]:
        result = self.request(method, path, params=params).get("result")
        if not isinstance(result, list):
            raise click.ClickException(f"Cloudflare {label} response was not a list")
        return result

    def dns_records(self, zone_id: str, hostname: str) -> list[Any]:
        return self.result_list(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": "CNAME", "name": hostname, "per_page": 50},
            label="DNS records",
        )

    def verify_token(self, account_id: str | None = None) -> None:
        if account_id is None:
            self.request("GET", "/user/tokens/verify")
            return

        self.request("GET", f"/accounts/{account_id}/tokens/verify")

    def list_zones(self) -> list[Zone]:
        zones: list[Zone] = []
        for item in self.result_list("GET", "/zones", params={"per_page": 50}, label="zones"):
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
        tunnels: list[CloudflareTunnel] = []
        for item in self.result_list(
            "GET",
            f"/accounts/{account_id}/cfd_tunnel",
            params={"is_deleted": "false"},
            label="tunnels",
        ):
            if not isinstance(item, dict):
                continue
            tunnel_id = item.get("id")
            name = item.get("name")
            if isinstance(tunnel_id, str) and isinstance(name, str):
                tunnels.append(CloudflareTunnel(id=tunnel_id, name=name))
        return tunnels

    def upsert_dns_cname(self, zone_id: str, hostname: str, tunnel_id: str) -> None:
        target = f"{tunnel_id}.cfargotunnel.com"
        record_payload = {
            "type": "CNAME",
            "name": hostname,
            "content": target,
            "ttl": 1,
            "proxied": True,
        }
        for item in self.dns_records(zone_id, hostname):
            if not isinstance(item, dict):
                continue
            record_id = item.get("id")
            if isinstance(record_id, str):
                self.request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", json_body=record_payload)
                return

        self.request("POST", f"/zones/{zone_id}/dns_records", json_body=record_payload)

    @staticmethod
    def _normalize_dns_target(value: str) -> str:
        return value.rstrip(".").lower()

    def delete_dns_cname_to_tunnel(self, zone_id: str, hostname: str, tunnel_id: str) -> int:
        target = self._normalize_dns_target(f"{tunnel_id}.cfargotunnel.com")
        removed = 0
        for item in self.dns_records(zone_id, hostname):
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            record_id = item.get("id")
            if not isinstance(content, str) or not isinstance(record_id, str):
                continue
            if self._normalize_dns_target(content) != target:
                continue
            self.request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
            removed += 1
        return removed

from typing import Any

import click

from .cloudflare import CloudflareClient

WAF_CUSTOM_PHASE = "http_request_firewall_custom"


def waf_custom_entrypoint(client: CloudflareClient, zone_id: str) -> dict[str, Any]:
    return client.request(
        "GET",
        f"/zones/{zone_id}/rulesets/phases/{WAF_CUSTOM_PHASE}/entrypoint",
    )["result"]


def add_waf_custom_rule(
    client: CloudflareClient,
    zone_id: str,
    *,
    description: str,
    expression: str,
    action: str,
) -> dict[str, Any]:
    ruleset = waf_custom_entrypoint(client, zone_id)
    ruleset_id = ruleset.get("id")
    if not isinstance(ruleset_id, str) or not ruleset_id:
        raise click.ClickException("WAF custom rules: entrypoint response missing ruleset id")
    return client.request(
        "POST",
        f"/zones/{zone_id}/rulesets/{ruleset_id}/rules",
        json_body={"description": description, "expression": expression, "action": action},
    )["result"]


def delete_waf_custom_rule(
    client: CloudflareClient, zone_id: str, ruleset_id: str, rule_id: str
) -> dict[str, Any]:
    return client.request(
        "DELETE",
        f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
    )["result"]

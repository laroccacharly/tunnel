import json
import sys
from typing import Any

import click

from .cloudflare import CloudflareClient
from .config import require_config, require_credentials
from . import waf

# (api_value, short label, one-line, longer explanation)
CHALLENGE_STYLES: tuple[tuple[str, str, str, str], ...] = (
    (
        "managed_challenge",
        "Balanced (recommended)",
        "Cloudflare picks the check. Often a short page or a checkbox; many real visitors pass quickly.",
        "Default for most sites. This is the usual “check you’re human” experience people associate with Cloudflare.",
    ),
    (
        "js_challenge",
        "Silent / background",
        "Runs a check in the browser without a big form. Can block simple bots and non-browsers (e.g. some API clients).",
        "Often no full-page interstitial, but not ideal if you need every API or script to hit your origin unchanged.",
    ),
    (
        "interactive_challenge",
        "Strict / explicit",
        "Asks the visitor to complete a stronger test when Cloudflare is unsure. More friction, better bot blocking.",
        "Use if you need the strongest on-page check and can tolerate more steps for real users.",
    ),
)

# (key, short label, one-line, longer)
SCOPE_CHOICES: tuple[tuple[str, str, str, str], ...] = (
    (
        "tunnel_host",
        "Only this tunnel’s hostname",
        "Only the URL you configured for this tunnel (other subdomains on the zone are unchanged by this rule).",
        "Best default: your tunneled app is protected; the rest of the domain is left to your other settings.",
    ),
    (
        "whole_zone",
        "All traffic to this site on Cloudflare",
        "The check can run for any request to this domain that goes through Cloudflare, not just the tunnel host.",
        "Stronger and broader. Use when you want the same visitor check for the whole site.",
    ),
    (
        "custom",
        "Custom (advanced)",
        "You type a rule in Cloudflare’s rule language. Only if you know what you’re doing.",
        "Wrong expressions can block or check the wrong traffic. Prefer 1) or 2) unless you have a specific need.",
    ),
)

_GROUP_HELP = (
    "Add or remove a visitor check in Cloudflare in front of your app (on Cloudflare’s network, not in your code). "
    "This is the “prove you’re not a bot” or quick verification step visitors sometimes see. "
    "Your API token must be allowed to change security rules for this domain."
)


def _tty() -> bool:
    return click.get_text_stream("stdin").isatty()


def _action_short(api: str) -> str:
    for a, short, _, _ in CHALLENGE_STYLES:
        if a == api:
            return short
    return api


def _parse_rules_from_entrypoint(entry: dict[str, Any]) -> list[dict[str, Any]]:
    raw = entry.get("rules")
    if not isinstance(raw, list):
        return []
    return [r for r in raw if isinstance(r, dict)]


def _rule_lines(rule: dict[str, Any], *, max_expr: int = 70) -> list[str]:
    action = str(rule.get("action") or "")
    desc = (rule.get("description") or "").strip()
    expr = (rule.get("expression") or "").strip()
    en = rule.get("enabled", True) is not False
    out: list[str] = []
    if action == "execute":
        out.append("Kind: links to another ruleset (removing it changes which rules run — be sure before deleting)")
    elif action in {s[0] for s in CHALLENGE_STYLES}:
        out.append(f"Kind: visitor check — {_action_short(action)}")
    elif action:
        out.append(f"Kind: {action} (see Cloudflare Security → WAF for details)")
    if not en:
        out.append("Status: currently disabled in Cloudflare")
    if desc:
        out.append(f"Name in dashboard: {desc}")
    if expr:
        shown = expr if len(expr) <= max_expr else expr[: max_expr - 1] + "…"
        out.append(f"Match: {shown}")
    if not out:
        out.append("(no details)")
    return out


def _print_challenge_styles() -> None:
    click.echo("How should Cloudflare verify visitors?")
    for i, (_api, short, one, more) in enumerate(CHALLENGE_STYLES, start=1):
        click.echo(f"  {i}) {short}")
        click.echo(f"     {one}")
        click.echo(f"     {more}")
    click.echo()


def _print_scope_choices() -> None:
    click.echo("What traffic should this apply to?")
    for i, (_key, short, one, more) in enumerate(SCOPE_CHOICES, start=1):
        click.echo(f"  {i}) {short}")
        click.echo(f"     {one}")
        click.echo(f"     {more}")
    click.echo()


def _scope_to_expression(
    scope_key: str,
    config_hostname: str,
    custom_expression: str | None,
) -> str:
    if scope_key == "tunnel_host":
        return f'http.host eq "{config_hostname}"'
    if scope_key == "whole_zone":
        return "true"
    if scope_key == "custom":
        if not (custom_expression or "").strip():
            raise click.ClickException("Custom scope needs a non-empty expression.")
        return (custom_expression or "").strip()
    raise click.ClickException(f"unknown scope: {scope_key!r}")


def _pick_style_interactive() -> str:
    _print_challenge_styles()
    n = len(CHALLENGE_STYLES)
    choice = click.prompt(
        f"Choose 1–{n}",
        type=click.IntRange(1, n),
        default=1,
        show_default=True,
    )
    return CHALLENGE_STYLES[choice - 1][0]


def _pick_scope_interactive() -> tuple[str, str | None]:
    _print_scope_choices()
    n = len(SCOPE_CHOICES)
    choice = click.prompt(
        f"Choose 1–{n}",
        type=click.IntRange(1, n),
        default=1,
        show_default=True,
    )
    key = SCOPE_CHOICES[choice - 1][0]
    if key == "custom":
        expr = click.prompt(
            "Rule expression (Cloudflare’s language). If unsure, cancel (Ctrl+C) and pick option 1 or 2 instead.",
            type=str,
        )
        return key, expr
    return key, None


def _resolve_action(
    action_flag: str | None,
    *,
    interactive: bool,
) -> str:
    if action_flag:
        for api, _, _, _ in CHALLENGE_STYLES:
            if api == action_flag.lower():
                return api
        raise click.ClickException(
            f"Unknown action {action_flag!r}. Use one of: " + ", ".join(s[0] for s in CHALLENGE_STYLES)
        )
    if interactive and _tty():
        return _pick_style_interactive()
    return "managed_challenge"


def _resolve_expression(
    config_hostname: str,
    expression_opt: str | None,
    *,
    scope_flag: str | None,
    interactive: bool,
) -> tuple[str, str]:
    """Returns (expression, human summary line)."""
    if expression_opt is not None and expression_opt.strip():
        expr = expression_opt.strip()
        return expr, f"Custom match: {expr[:120]}{'…' if len(expr) > 120 else ''}"

    if scope_flag is not None:
        sk = scope_flag.lower().replace("-", "_")
        if sk in ("tunnel", "tunnel_host", "host", "1"):
            return _scope_to_expression("tunnel_host", config_hostname, None), "Only this tunnel’s hostname"
        if sk in ("zone", "whole_zone", "all", "2"):
            return _scope_to_expression("whole_zone", config_hostname, None), "Entire site on this domain (all requests)"
        if sk in ("custom", "3"):
            raise click.ClickException("Use --expression with --scope custom, or set scope interactively.")
        raise click.ClickException(
            f"Unknown --scope {scope_flag!r}. Use: tunnel, whole_zone, or custom (or run without flags)."
        )

    if interactive and _tty():
        key, custom = _pick_scope_interactive()
        if key == "custom" and not custom:
            raise click.ClickException("Custom expression was empty.")
        scope_desc = SCOPE_CHOICES[[c[0] for c in SCOPE_CHOICES].index(key)][1]
        return _scope_to_expression(key, config_hostname, custom), scope_desc

    expr = _scope_to_expression("tunnel_host", config_hostname, None)
    return expr, f"Only hostname https://{config_hostname}/ (default)"


def _print_add_summary(
    *,
    zone_name: str,
    config_hostname: str,
    action: str,
    expression: str,
    match_summary: str,
) -> None:
    click.echo("")
    click.echo("Next step: add one rule in Cloudflare")
    click.echo("  (This does not change your app code. It’s like a switch in the Cloudflare control panel.)")
    click.echo("")
    click.echo(f"  Site (zone):     {zone_name}")
    click.echo(f"  Visitor check:   {_action_short(action)}")
    click.echo(f"  Applies when:     {match_summary}")
    click.echo("  Tech detail:      only requests that match the rule are affected")
    short_expr = expression if len(expression) < 100 else expression[:97] + "…"
    click.echo(f"  Rule (advanced):  {short_expr}")
    click.echo("")


def _add_impl(
    *,
    expression_opt: str | None,
    description: str | None,
    action_flag: str | None,
    scope_flag: str | None,
    yes: bool,
) -> None:
    config = require_config()
    credentials = require_credentials()
    in_terminal = _tty()
    if not in_terminal and not yes:
        click.echo(
            "Not in a terminal. Either run this from an interactive shell to use the guided prompts,\n"
            "or add --yes to create a rule with defaults and no questions. Examples:\n"
            "  tunnel challenge add --yes\n"
            "  tunnel challenge add --yes --action managed_challenge\n"
            "  tunnel challenge add --yes --scope tunnel_host --action js_challenge",
            file=sys.stderr,
        )
        raise click.ClickException("add --yes required when stdin is not a TTY")

    if expression_opt is not None and not expression_opt.strip():
        raise click.ClickException("expression must not be empty when set")

    can_prompt = in_terminal and not yes
    action_interactive = can_prompt and not action_flag
    scope_interactive = can_prompt and expression_opt is None and scope_flag is None

    if can_prompt:
        click.echo("")
        click.echo("Add a visitor check (in Cloudflare, not in your project code)")
        click.echo("Cloudflare can show a short check before a request reaches your tunneled app. "
            "You can undo this with: tunnel challenge remove")
        click.echo("")

    action = _resolve_action(action_flag, interactive=action_interactive)
    expression, match_summary = _resolve_expression(
        config.hostname,
        expression_opt,
        scope_flag=scope_flag,
        interactive=scope_interactive,
    )
    if expression_opt is not None:
        match_summary = "Custom match (see rule text below)"

    desc = (description or "").strip() or f"tunnel-cli: {_action_short(action)} for {config.hostname}"

    if can_prompt:
        _print_add_summary(
            zone_name=config.zone_name,
            config_hostname=config.hostname,
            action=action,
            expression=expression,
            match_summary=match_summary,
        )
        click.confirm("Add this rule in Cloudflare now?", default=True, abort=True)
    else:
        click.echo(
            f"Adding rule: {_action_short(action)} · {match_summary} · {desc!r}"
        )

    client = CloudflareClient(credentials.api_token)
    result = waf.add_waf_custom_rule(
        client,
        config.zone_id,
        description=desc,
        expression=expression,
        action=action,
    )

    click.echo("")
    click.echo("Done. Cloudflare will use this rule for new requests (usually within a few seconds).")
    click.echo("  List rules:  tunnel challenge list")
    click.echo("  Remove one:  tunnel challenge remove   (picks from a list)")
    if in_terminal and not yes:
        click.echo("")
        show = click.confirm("Show raw API response (for debugging)?", default=False)
        if show:
            click.echo(json.dumps(result, indent=2, sort_keys=True))


def _remove_pick_interactive(rules: list[dict[str, Any]], zone_name: str) -> str | None:
    with_id = [r for r in rules if isinstance(r.get("id"), str) and r.get("id")]
    if not with_id:
        click.echo(f"No removable rules in this list for {zone_name!r}.")
        click.echo("  (Other products may add rules in the Cloudflare dashboard under Security.)")
        return None
    click.echo("")
    click.echo("Remove a visitor check (this only changes Cloudflare, not your code)")
    click.echo(f"Domain: {zone_name}")
    click.echo("Pick a rule to remove, or 0 to cancel.\n")
    for i, rule in enumerate(with_id, start=1):
        rid = str(rule.get("id"))
        rid_show = f"{rid[:18]}…" if len(rid) > 20 else rid
        click.echo(f"  [{i}]  id {rid_show}")
        for line in _rule_lines(rule):
            click.echo(f"       {line}")
        click.echo("")
    n = len(with_id)
    pick = click.prompt(
        "Number to remove (0 = cancel)",
        type=click.IntRange(0, n),
        default=0,
    )
    if pick == 0:
        return None
    rid = with_id[pick - 1].get("id")
    if not isinstance(rid, str) or not rid:
        raise click.ClickException("internal error: selected rule has no id")
    return rid


def _remove_impl(rule_id: str | None, *, yes: bool) -> None:
    config = require_config()
    credentials = require_credentials()
    client = CloudflareClient(credentials.api_token)
    entry = waf.waf_custom_entrypoint(config.zone_id)
    ruleset_id = entry.get("id")
    if not isinstance(ruleset_id, str) or not ruleset_id:
        raise click.ClickException("Could not read the ruleset from Cloudflare. Check your token permissions.")
    rules = _parse_rules_from_entrypoint(entry)

    to_remove: str | None = rule_id.strip() if rule_id and rule_id.strip() else None

    if to_remove is None:
        if not _tty():
            raise click.ClickException(
                "Not in a terminal. Pass the rule id:  tunnel challenge remove <id>   (see `tunnel challenge list`)"
            )
        picked = _remove_pick_interactive(rules, config.zone_name)
        if picked is None:
            click.echo("Cancelled.")
            return
        if not yes:
            r = next((x for x in rules if x.get("id") == picked), None)
            click.echo("")
            if r:
                for line in _rule_lines(r):
                    click.echo(f"  {line}")
            if not click.confirm("Remove this rule from Cloudflare?", default=False):
                click.echo("Cancelled.")
                return
        to_remove = picked
    else:
        if not any(isinstance(r, dict) and r.get("id") == to_remove for r in rules):
            raise click.ClickException(
                f"No rule with id {to_remove!r} in this domain’s list. Run: tunnel challenge list"
            )
        if not yes and _tty():
            r = next((x for x in rules if x.get("id") == to_remove), None)
            if r:
                click.echo("")
                click.echo("You’re about to delete this rule from Cloudflare:")
                for line in _rule_lines(r or {}):
                    click.echo(f"  {line}")
                click.confirm("Remove it?", default=False, abort=True)

    waf.delete_waf_custom_rule(client, config.zone_id, ruleset_id, to_remove)
    click.echo("")
    click.echo("Removed. New visitors won’t be affected by that rule anymore.")


@click.group(
    name="challenge",
    help=_GROUP_HELP,
)
def challenge_group() -> None:
    pass


@challenge_group.command(
    "add",
    help="Add a visitor check in Cloudflare (interactive by default: explains choices).",
)
@click.option(
    "--expression",
    "-e",
    "expression_opt",
    default=None,
    help="Advanced: full rule match text. If set, skips the “which traffic” wizard.",
)
@click.option("--description", "-d", default=None, help="Optional label in the Cloudflare dashboard.")
@click.option(
    "--action",
    "-a",
    "action_flag",
    default=None,
    type=str,
    help="Skip prompt: " + " | ".join(f"{i+1}={s[0]}" for i, s in enumerate(CHALLENGE_STYLES)),
)
@click.option(
    "--scope",
    default=None,
    type=click.Choice(
        [c[0] for c in SCOPE_CHOICES] + ["tunnel", "whole_zone", "all", "host"],
        case_sensitive=False,
    ),
    help="Skip prompt: tunnel_host = only this tunnel; whole_zone = entire domain; custom needs --expression.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="No prompts: defaults (balanced check, only this tunnel’s hostname) and no confirmation or JSON offer.",
)
def challenge_add(
    expression_opt: str | None,
    description: str | None,
    action_flag: str | None,
    scope: str | None,
    yes: bool,
) -> None:
    if scope in ("tunnel", "host", "all"):
        scope_norm = "tunnel_host" if scope in ("tunnel", "host") else "whole_zone"
    else:
        scope_norm = scope
    _add_impl(
        expression_opt=expression_opt,
        description=description,
        action_flag=action_flag,
        scope_flag=scope_norm,
        yes=yes,
    )


@challenge_group.command(
    "list",
    help="Show custom security rules for this domain in plain language, or --json for full detail.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Print the full entrypoint JSON (what the API returns).",
)
def challenge_list(as_json: bool) -> None:
    config = require_config()
    credentials = require_credentials()
    client = CloudflareClient(credentials.api_token)
    entry = waf.waf_custom_entrypoint(client, config.zone_id)
    if as_json:
        click.echo(json.dumps(entry, indent=2, sort_keys=True))
        return
    rules = _parse_rules_from_entrypoint(entry)
    click.echo(f"Custom rules at Cloudflare for: {config.zone_name}")
    click.echo("  (These run at the edge before traffic reaches your tunnel / origin.)")
    click.echo("")
    if not rules:
        click.echo("  (none in this list)")
        click.echo("")
        return
    for i, rule in enumerate(rules, start=1):
        rid = rule.get("id") or "?"
        click.echo(f"  {i}. id: {rid}")
        for line in _rule_lines(rule):
            click.echo(f"     {line}")
        click.echo("")


@challenge_group.command(
    "remove",
    help="Remove a visitor-check rule. No id = interactive list; or pass a rule id from `tunnel challenge list`.",
)
@click.argument("rule_id", required=False, default=None)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip the “are you sure?” step (after you pick a number, or when you pass a rule id).",
)
def challenge_remove(rule_id: str | None, yes: bool) -> None:
    _remove_impl(rule_id, yes=yes)

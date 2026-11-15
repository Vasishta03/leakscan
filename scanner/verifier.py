"""Live verification of detected secrets.

Each check is a single read-only request to the provider's own API (see
ENDPOINTS for exactly what is sent where). Returns "LIVE", "REVOKED", or
None when the result can't be determined (network error, rate limit,
unsupported pair-only secrets).
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
from typing import Callable, Optional

import requests

from scanner import __version__
from scanner.engine import Finding

_session = requests.Session()
_session.headers["User-Agent"] = f"leakscan/{__version__} (+https://github.com/Vasishta03/leakscan)"
_TIMEOUT: float = 5
_MIN_INTERVAL: float = 0.1
_cache: dict[tuple, Optional[str]] = {}
_rate_lock = threading.Lock()
_last_request = [0.0]

_UUID_RE = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")


def configure(timeout: Optional[float] = None, min_interval: Optional[float] = None) -> None:
    global _TIMEOUT, _MIN_INTERVAL
    if timeout is not None:
        _TIMEOUT = timeout
    if min_interval is not None:
        _MIN_INTERVAL = min_interval


def _throttle() -> None:
    with _rate_lock:
        wait = _last_request[0] + _MIN_INTERVAL - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_request[0] = time.monotonic()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# secret_type -> (service, url, headers builder). Status 200 = LIVE, 401/403 = REVOKED.
BEARER_CHECKS: dict[str, tuple[str, str, Callable[[str], dict]]] = {
    "GitHub Personal Token": ("github", "https://api.github.com/user", _bearer),
    "GitHub OAuth Token": ("github", "https://api.github.com/user", _bearer),
    "GitHub App Token": ("github", "https://api.github.com/user", _bearer),
    "GitHub Fine-Grained Token": ("github", "https://api.github.com/user", _bearer),
    "GitLab Personal Token": ("gitlab", "https://gitlab.com/api/v4/user", lambda t: {"PRIVATE-TOKEN": t}),
    "Stripe Live Secret Key": ("stripe", "https://api.stripe.com/v1/account", _bearer),
    "Stripe Restricted Key": ("stripe", "https://api.stripe.com/v1/balance", _bearer),
    "OpenAI API Key": ("openai", "https://api.openai.com/v1/models", _bearer),
    "OpenAI Project Key": ("openai", "https://api.openai.com/v1/models", _bearer),
    "Anthropic API Key": ("anthropic", "https://api.anthropic.com/v1/models",
                          lambda t: {"x-api-key": t, "anthropic-version": "2023-06-01"}),
    "HuggingFace Token": ("huggingface", "https://huggingface.co/api/whoami-v2", _bearer),
    "SendGrid API Key": ("sendgrid", "https://api.sendgrid.com/v3/user/profile", _bearer),
    "NPM Access Token": ("npm", "https://registry.npmjs.org/-/npm/v1/user", _bearer),
    "Replicate API Token": ("replicate", "https://api.replicate.com/v1/account", lambda t: {"Authorization": f"Token {t}"}),
    "Sentry Auth Token": ("sentry", "https://sentry.io/api/0/", _bearer),
    "Vercel Token": ("vercel", "https://api.vercel.com/v2/user", _bearer),
    "Groq API Key": ("groq", "https://api.groq.com/openai/v1/models", _bearer),
    "Pinecone API Key": ("pinecone", "https://api.pinecone.io/indexes", lambda t: {"Api-Key": t}),
    "Notion API Key": ("notion", "https://api.notion.com/v1/users/me",
                       lambda t: {"Authorization": f"Bearer {t}", "Notion-Version": "2022-06-28"}),
    "Postmark Server Token": ("postmark", "https://api.postmarkapp.com/server",
                              lambda t: {"X-Postmark-Server-Token": t, "Accept": "application/json"}),
    "Mistral API Key": ("mistral", "https://api.mistral.ai/v1/models", _bearer),
    "Together AI API Key": ("together", "https://api.together.xyz/v1/models", _bearer),
    "Fireworks API Key": ("fireworks", "https://api.fireworks.ai/inference/v1/models", _bearer),
    "DeepSeek API Key": ("deepseek", "https://api.deepseek.com/models", _bearer),
    "xAI API Key": ("xai", "https://api.x.ai/v1/api-key", _bearer),
    "Cerebras API Key": ("cerebras", "https://api.cerebras.ai/v1/models", _bearer),
    "OpenRouter API Key": ("openrouter", "https://openrouter.ai/api/v1/key", _bearer),
    "Perplexity API Key": ("perplexity", "https://api.perplexity.ai/models", _bearer),
    "Netlify Access Token": ("netlify", "https://api.netlify.com/api/v1/user", _bearer),
    "Render API Key": ("render", "https://api.render.com/v1/owners?limit=1", _bearer),
    "Neon API Key": ("neon", "https://console.neon.tech/api/v2/users/me", _bearer),
    "Resend API Key": ("resend", "https://api.resend.com/domains", _bearer),
    "Airtable Personal Access Token": ("airtable", "https://api.airtable.com/v0/meta/whoami", _bearer),
    "Heroku API Key": ("heroku", "https://api.heroku.com/account",
                       lambda t: {"Authorization": f"Bearer {t}", "Accept": "application/vnd.heroku+json; version=3"}),
    "Figma Personal Token": ("figma", "https://api.figma.com/v1/me", lambda t: {"X-Figma-Token": t}),
    "Brevo API Key": ("brevo", "https://api.brevo.com/v3/account", lambda t: {"api-key": t, "Accept": "application/json"}),
    "DigitalOcean Token": ("digitalocean", "https://api.digitalocean.com/v2/account", _bearer),
    "Docker Hub Token": ("dockerhub", "https://hub.docker.com/v2/access-tokens?page_size=1", _bearer),
    "PostHog Personal API Key": ("posthog", "https://us.posthog.com/api/users/@me/", _bearer),
    "Mapbox Secret Token": ("mapbox", "https://api.mapbox.com/tokens/v2?access_token={token}", lambda t: {}),
}

_EXTRACTORS: dict[str, re.Pattern] = {
    "GitHub Personal Token": re.compile(r"ghp_[A-Za-z0-9]+"),
    "GitHub OAuth Token": re.compile(r"gho_[A-Za-z0-9]+"),
    "GitHub App Token": re.compile(r"(?:ghu|ghs)_[A-Za-z0-9]+"),
    "GitHub Fine-Grained Token": re.compile(r"github_pat_[A-Za-z0-9_]+"),
    "GitLab Personal Token": re.compile(r"glpat-[A-Za-z0-9\-_]+"),
    "Stripe Live Secret Key": re.compile(r"sk_live_[A-Za-z0-9]+"),
    "Stripe Restricted Key": re.compile(r"rk_live_[A-Za-z0-9]+"),
    "OpenAI API Key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "OpenAI Project Key": re.compile(r"sk-proj-[A-Za-z0-9\-_]+"),
    "Anthropic API Key": re.compile(r"sk-ant-[A-Za-z0-9\-_]+"),
    "HuggingFace Token": re.compile(r"hf_[A-Za-z0-9]+"),
    "SendGrid API Key": re.compile(r"SG\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "Slack Bot Token": re.compile(r"xoxb-[A-Za-z0-9\-]+"),
    "Slack User Token": re.compile(r"xoxp-[A-Za-z0-9\-]+"),
    "NPM Access Token": re.compile(r"npm_[A-Za-z0-9]+"),
    "Replicate API Token": re.compile(r"r8_[A-Za-z0-9]+"),
    "Telegram Bot Token": re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Twilio Auth Token": re.compile(r"[0-9a-f]{32}"),
    "AWS Access Key ID": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "Sentry Auth Token": re.compile(r"sntry[su]_[A-Za-z0-9+/=_]+"),
    "Datadog API Key": re.compile(r"[a-f0-9]{32}"),
    "Vercel Token": re.compile(r"vercel_[A-Za-z0-9]+"),
    "Cohere API Key": re.compile(r"[A-Za-z0-9]{40}"),
    "Groq API Key": re.compile(r"gsk_[A-Za-z0-9]{52}"),
    "Pinecone API Key": _UUID_RE,
    "Notion API Key": re.compile(r"(?:secret|ntn)_[A-Za-z0-9]{43}"),
    "Linear API Key": re.compile(r"lin_api_[A-Za-z0-9]{40}"),
    "Mailgun API Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "Postmark Server Token": _UUID_RE,
    "Cloudflare API Token": re.compile(r"[A-Za-z0-9_-]{40}"),
    "Railway API Token": _UUID_RE,
    "Supabase Service Key": re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}"),
    "Azure AD Client Secret": re.compile(r"[A-Za-z0-9_~.\-]{34,40}"),
    "Mistral API Key": re.compile(r"[A-Za-z0-9]{32}"),
    "Together AI API Key": re.compile(r"tgp_v1_[A-Za-z0-9_\-]{43}|[a-f0-9]{64}"),
    "Fireworks API Key": re.compile(r"fw_[A-Za-z0-9]{24}"),
    "DeepSeek API Key": re.compile(r"sk-[a-f0-9]{32}"),
    "xAI API Key": re.compile(r"xai-[A-Za-z0-9]{80}"),
    "Cerebras API Key": re.compile(r"csk-[a-z0-9]{48}"),
    "OpenRouter API Key": re.compile(r"sk-or-v1-[a-f0-9]{64}"),
    "Perplexity API Key": re.compile(r"pplx-[A-Za-z0-9]{48}"),
    "Netlify Access Token": re.compile(r"nfp_[A-Za-z0-9]{36}"),
    "Render API Key": re.compile(r"rnd_[A-Za-z0-9]{32}"),
    "Neon API Key": re.compile(r"napi_[a-z0-9]{64}"),
    "Resend API Key": re.compile(r"re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}"),
    "Airtable Personal Access Token": re.compile(r"pat[A-Za-z0-9]{14}\.[a-f0-9]{64}"),
    "Heroku API Key": re.compile(r"HRKU-[A-Za-z0-9_\-]{58,60}"),
    "Figma Personal Token": re.compile(r"figd_[A-Za-z0-9_\-]{40}"),
    "Brevo API Key": re.compile(r"xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}"),
    "DigitalOcean Token": re.compile(r"dop_v1_[a-f0-9]{64}"),
    "Docker Hub Token": re.compile(r"dckr_pat_[A-Za-z0-9_\-]{27}"),
    "PostHog Personal API Key": re.compile(r"phx_[A-Za-z0-9]{43}"),
    "Mapbox Secret Token": re.compile(r"sk\.eyJ[A-Za-z0-9+/=._-]+"),
}

SPECIAL_SERVICES = {
    "Slack Bot Token": "slack", "Slack User Token": "slack", "Telegram Bot Token": "telegram",
    "Google API Key": "google", "Datadog API Key": "datadog", "Cohere API Key": "cohere",
    "Linear API Key": "linear", "Mailgun API Key": "mailgun", "Cloudflare API Token": "cloudflare",
    "Railway API Token": "railway", "Supabase Service Key": "supabase", "Azure AD Client Secret": "azure",
    "Twilio Auth Token": "twilio", "AWS Access Key ID": "aws",
}

# Human-readable "what is sent where" table, used by the docs generator.
ENDPOINTS: dict[str, str] = {
    **{name: f"GET {url.split('?')[0]}" for name, (_, url, _) in BEARER_CHECKS.items()},
    "Slack Bot Token": "POST https://slack.com/api/auth.test",
    "Slack User Token": "POST https://slack.com/api/auth.test",
    "Telegram Bot Token": "GET https://api.telegram.org/bot<token>/getMe",
    "Google API Key": "GET https://maps.googleapis.com/maps/api/geocode/json (address=test)",
    "Datadog API Key": "GET https://api.datadoghq.com/api/v1/validate",
    "Cohere API Key": "POST https://api.cohere.ai/v1/check-api-key",
    "Linear API Key": "POST https://api.linear.app/graphql ({ viewer { id } })",
    "Mailgun API Key": "GET https://api.mailgun.net/v3/domains",
    "Cloudflare API Token": "GET https://api.cloudflare.com/client/v4/user/tokens/verify",
    "Railway API Token": "POST https://backboard.railway.app/graphql/v2 (query { me { id } })",
    "Supabase Service Key": "none (JWT role and expiry decoded locally)",
    "Azure AD Client Secret": "POST https://login.microsoftonline.com/common/oauth2/v2.0/token (placeholder client_id)",
    "Twilio Auth Token": "none (needs the account SID pair)",
    "AWS Access Key ID": "none (needs the secret key pair)",
}


def service_of(secret_type: str) -> Optional[str]:
    if secret_type in BEARER_CHECKS:
        return BEARER_CHECKS[secret_type][0]
    return SPECIAL_SERVICES.get(secret_type)


def services() -> list[str]:
    return sorted({s for s in (service_of(t) for t in _EXTRACTORS) if s})


def _extract(finding: Finding) -> Optional[str]:
    from scanner.patterns import by_name
    rule = by_name().get(finding.secret_type)
    if rule is not None and rule.regex.groups:
        m = rule.regex.search(finding.matched_value)
        if m and m.group(1):
            return m.group(1)
    pat = _EXTRACTORS.get(finding.secret_type)
    if pat:
        m = pat.search(finding.matched_value)
        return m.group(0) if m else None
    return finding.matched_value


def _get(url: str, headers: dict) -> Optional[requests.Response]:
    _throttle()
    try:
        return _session.get(url, headers=headers, timeout=_TIMEOUT)
    except Exception:
        return None


def _post(url: str, headers: dict, json: dict) -> Optional[requests.Response]:
    _throttle()
    try:
        return _session.post(url, headers=headers, json=json, timeout=_TIMEOUT)
    except Exception:
        return None


def _post_form(url: str, data: dict) -> Optional[requests.Response]:
    _throttle()
    try:
        return _session.post(url, data=data, timeout=_TIMEOUT)
    except Exception:
        return None


def _get_basic(url: str, auth: tuple) -> Optional[requests.Response]:
    _throttle()
    try:
        return _session.get(url, auth=auth, timeout=_TIMEOUT)
    except Exception:
        return None


def _status(r: Optional[requests.Response]) -> Optional[str]:
    if r is None:
        return None
    if r.status_code == 200:
        return "LIVE"
    if r.status_code in (401, 403):
        return "REVOKED"
    return None


def _json_flag(r: Optional[requests.Response], getter: Callable[[dict], object]) -> Optional[str]:
    if r is None:
        return None
    try:
        return "LIVE" if getter(r.json()) else "REVOKED"
    except Exception:
        return _status(r)


def _decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        segment = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except Exception:
        return None


def _check_jwt_role(token: str, expected_role: str) -> Optional[str]:
    payload = _decode_jwt_payload(token)
    if payload is None or payload.get("role") != expected_role:
        return None
    exp = payload.get("exp")
    if exp is not None and exp < time.time():
        return "REVOKED"
    return "LIVE"


def verify(finding: Finding) -> Optional[str]:
    cache_key = (finding.secret_type, finding.matched_value)
    if cache_key in _cache:
        return _cache[cache_key]
    result = _do_verify(finding)
    _cache[cache_key] = result
    return result


def _do_verify(finding: Finding) -> Optional[str]:
    token = _extract(finding)
    if not token:
        return None
    t = finding.secret_type

    if t in BEARER_CHECKS:
        _, url, headers = BEARER_CHECKS[t]
        return _status(_get(url.replace("{token}", token), headers(token)))

    if t in ("Slack Bot Token", "Slack User Token"):
        r = _post("https://slack.com/api/auth.test",
                  {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, {})
        return _json_flag(r, lambda d: d.get("ok"))

    if t == "Telegram Bot Token":
        return _json_flag(_get(f"https://api.telegram.org/bot{token}/getMe", {}), lambda d: d.get("ok"))

    if t == "Google API Key":
        r = _get(f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={token}", {})
        if r is None:
            return None
        try:
            data = r.json()
        except Exception:
            return None
        status = data.get("status", "")
        if status in ("OK", "ZERO_RESULTS"):
            return "LIVE"
        if status == "REQUEST_DENIED":
            msg = data.get("error_message", "").lower()
            return "LIVE" if "not authorized" in msg or "enable" in msg else "REVOKED"
        return None

    if t == "Datadog API Key":
        return _json_flag(_get("https://api.datadoghq.com/api/v1/validate", {"DD-API-KEY": token}),
                          lambda d: d.get("valid"))

    if t == "Cohere API Key":
        return _json_flag(_post("https://api.cohere.ai/v1/check-api-key", _bearer(token), {}),
                          lambda d: d.get("valid"))

    if t == "Linear API Key":
        r = _post("https://api.linear.app/graphql", {"Authorization": token, "Content-Type": "application/json"},
                  {"query": "{ viewer { id } }"})
        return _json_flag(r, lambda d: (d.get("data") or {}).get("viewer"))

    if t == "Mailgun API Key":
        return _status(_get_basic("https://api.mailgun.net/v3/domains", ("api", token)))

    if t == "Cloudflare API Token":
        return _json_flag(_get("https://api.cloudflare.com/client/v4/user/tokens/verify", _bearer(token)),
                          lambda d: d.get("success"))

    if t == "Railway API Token":
        r = _post("https://backboard.railway.app/graphql/v2",
                  {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                  {"query": "query { me { id } }"})
        return _json_flag(r, lambda d: (d.get("data") or {}).get("me"))

    if t == "Supabase Service Key":
        return _check_jwt_role(token, expected_role="service_role")

    if t == "Azure AD Client Secret":
        # AAD validates the secret before the client_id, so AADSTS7000215 means
        # a bad secret and AADSTS700016 (unknown client) means it was accepted.
        r = _post_form("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            "client_id": "00000000-0000-0000-0000-000000000000",
            "client_secret": token,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        if r is None:
            return None
        try:
            err = r.json().get("error_description", "")
        except Exception:
            return None
        if "AADSTS7000215" in err:
            return "REVOKED"
        if "AADSTS700016" in err:
            return "LIVE"
        return None

    return None


def can_verify(finding: Finding) -> bool:
    return finding.secret_type in _EXTRACTORS

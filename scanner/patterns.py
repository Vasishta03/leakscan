from __future__ import annotations

import base64
import json
import re
import sys
import time
import zlib
from dataclasses import dataclass
from typing import Callable, Optional

Validator = Callable[[str], Optional[bool]]


@dataclass
class Pattern:
    name: str
    regex: re.Pattern
    severity: str
    description: str
    id: str = ""
    confidence: float = 0.9
    path: Optional[re.Pattern] = None
    validate: Optional[Validator] = None
    strict: bool = False
    exclude_path: Optional[re.Pattern] = None

    def applies_to(self, filepath: str) -> bool:
        fp = filepath.replace("\\", "/")
        if self.exclude_path is not None and self.exclude_path.search(fp):
            return False
        return self.path is None or bool(self.path.search(fp))


if sys.version_info >= (3, 11):
    import re._constants as _sc
    import re._parser as _sp
else:  # pragma: no cover
    import sre_constants as _sc  # type: ignore[no-redef]
    import sre_parse as _sp  # type: ignore[no-redef]


def required_literals(regex: re.Pattern) -> Optional[frozenset[str]]:
    """Lowercase substrings, at least one of which must appear in any match.

    Derived from the regex parse tree; None when no such literal exists.
    Used to skip rules cheaply before running the full regex.
    """
    try:
        tree = _sp.parse(regex.pattern, regex.flags & ~re.UNICODE)
    except Exception:
        return None
    best = _seq(list(tree))  # type: ignore[call-overload]
    return frozenset(best) if best else None


def _score_alts(alts: frozenset[str]) -> int:
    return min(len(a) for a in alts)


def _seq(items: list) -> Optional[frozenset[str]]:
    best: Optional[frozenset[str]] = None
    run = ""

    def offer(c: Optional[frozenset[str]]) -> None:
        nonlocal best
        if c and _score_alts(c) >= 2 and (best is None or _score_alts(c) > _score_alts(best)):
            best = c

    for op, av in items:
        if op is _sc.LITERAL:
            run += chr(av).lower()
            continue
        offer(frozenset([run]) if run else None)
        run = ""
        if op is _sc.SUBPATTERN:
            offer(_seq(list(av[-1])))
        elif op is _sc.BRANCH:
            alts = [_seq(list(b)) for b in av[1]]
            if all(alts):
                offer(frozenset().union(*alts))  # type: ignore[arg-type]
        elif op in (_sc.MAX_REPEAT, _sc.MIN_REPEAT) and av[0] >= 1:
            offer(_seq(list(av[2])))
    offer(frozenset([run]) if run else None)
    return best


_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b62(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = _B62[r] + s
    return s.rjust(6, "0")


def github_checksum_ok(token: str) -> Optional[bool]:
    body = token.split("_", 1)[-1]
    if len(body) != 36:
        return None
    return _b62(zlib.crc32(body[:30].encode())) == body[30:]


def luhn_ok(value: str) -> Optional[bool]:
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _b64json(segment: str) -> Optional[dict]:
    try:
        data = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def jwt_claims(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _b64json(parts[0])
    if header is None or "alg" not in header:
        return None
    return _b64json(parts[1]) or {}


def jwt_ok(token: str) -> Optional[bool]:
    return jwt_claims(token) is not None


def jwt_expired(token: str) -> bool:
    claims = jwt_claims(token) or {}
    exp = claims.get("exp")
    return isinstance(exp, (int, float)) and exp < time.time()


_AWS_B32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def aws_key_id_ok(value: str) -> Optional[bool]:
    return set(value[4:]) <= _AWS_B32


def _p(id: str, name: str, pattern: str, severity: str, description: str, *,
       flags: int = 0, path: Optional[str] = None, validate: Optional[Validator] = None,
       strict: bool = False, confidence: float = 0.9, exclude_path: Optional[str] = None) -> Pattern:
    return Pattern(
        name=name,
        regex=re.compile(pattern, flags),
        severity=severity,
        description=description,
        id=id,
        confidence=confidence,
        path=re.compile(path, re.IGNORECASE) if path else None,
        exclude_path=re.compile(exclude_path, re.IGNORECASE) if exclude_path else None,
        validate=validate,
        strict=strict,
    )


def _ctx(id: str, name: str, keyword: str, body: str, severity: str, description: str,
         **kw) -> Pattern:
    """A keyword-anchored rule: `<keyword>...<sep><secret>` where the secret
    has no distinctive prefix of its own."""
    regex = (
        rf"(?i)(?:{keyword})[\w.\-]{{0,25}}['\"]?\s*(?::=|=>|[=:])\s*['\"]?"
        rf"({body})(?![A-Za-z0-9])"
    )
    kw.setdefault("confidence", 0.75)
    return _p(id, name, regex, severity, description, **kw)


_ENVFILE = r"(?:^|/)(?:\.env(?:\.[\w.-]+)?|[\w.-]+\.env)$"
_YAML = r"\.ya?ml$"
_SECRET_NAME = r"\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)\w*"

PATTERNS: list[Pattern] = [
    # Private keys and cloud root credentials
    _p("LS-AWS-001", "AWS Access Key ID",
       r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA|ASIA)[A-Z0-9]{16}\b",
       "CRITICAL", "AWS access key ID", validate=aws_key_id_ok),
    _p("LS-AWS-002", "AWS Secret Access Key",
       r"(?i)aws(?:.{0,30})?['\"\s]([0-9a-zA-Z/+]{40})(?![0-9a-zA-Z/+])",
       "CRITICAL", "AWS secret access key", confidence=0.75),
    _p("LS-GCP-001", "GCP Service Account",
       r'"type"\s*:\s*"service_account"',
       "CRITICAL", "GCP service account JSON"),
    _p("LS-KEY-001", "RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "CRITICAL", "RSA private key (PKCS#1)"),
    _p("LS-KEY-002", "EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "CRITICAL", "EC private key"),
    _p("LS-KEY-003", "PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "CRITICAL", "PGP private key block"),
    _p("LS-KEY-004", "OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "CRITICAL", "OpenSSH private key"),
    _p("LS-KEY-005", "PKCS8 Private Key", r"-----BEGIN PRIVATE KEY-----", "CRITICAL", "PKCS#8 unencrypted private key"),
    _p("LS-KEY-006", "PKCS8 Encrypted Key", r"-----BEGIN ENCRYPTED PRIVATE KEY-----", "CRITICAL", "PKCS#8 encrypted private key"),
    _p("LS-KEY-007", "DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "CRITICAL", "DSA private key"),
    _p("LS-AZ-001", "Azure Storage Key",
       r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==",
       "CRITICAL", "Azure storage account connection string"),

    # Source control and CI
    _p("LS-GH-001", "GitHub Personal Token", r"\bghp_[0-9a-zA-Z]{36}\b", "HIGH",
       "GitHub personal access token", validate=github_checksum_ok, strict=True),
    _p("LS-GH-002", "GitHub OAuth Token", r"\bgho_[0-9a-zA-Z]{36}\b", "HIGH",
       "GitHub OAuth token", validate=github_checksum_ok, strict=True),
    _p("LS-GH-003", "GitHub App Token", r"\b(?:ghu|ghs)_[0-9a-zA-Z]{36}\b", "HIGH",
       "GitHub app/server token", validate=github_checksum_ok, strict=True),
    _p("LS-GH-004", "GitHub Refresh Token", r"\bghr_[0-9a-zA-Z]{76}\b", "HIGH", "GitHub refresh token"),
    _p("LS-GH-005", "GitHub Fine-Grained Token", r"\bgithub_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}\b", "HIGH",
       "GitHub fine-grained personal access token"),
    _p("LS-GL-001", "GitLab Personal Token", r"glpat-[A-Za-z0-9\-_]{20}", "HIGH", "GitLab personal access token"),
    _p("LS-GL-002", "GitLab CI Token", r"glcbt-[A-Za-z0-9\-_]{20}", "HIGH", "GitLab CI/CD token"),
    _p("LS-GL-003", "GitLab Runner Token", r"\bglrt-[A-Za-z0-9\-_]{20}\b", "HIGH", "GitLab runner authentication token"),
    _p("LS-GL-004", "GitLab Deploy Token", r"\bgldt-[A-Za-z0-9\-_]{20}\b", "HIGH", "GitLab deploy token"),
    _p("LS-BB-001", "Bitbucket App Password", r"\bATBB[A-Za-z0-9_=.\-]{28,}\b", "HIGH", "Bitbucket app password"),
    _p("LS-CI-001", "CircleCI Personal Token", r"\bCCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}\b", "HIGH", "CircleCI personal API token"),
    _p("LS-CI-002", "Buildkite Agent Token", r"\bbkua_[a-f0-9]{40}\b", "HIGH", "Buildkite user API token"),
    _p("LS-CI-003", "SonarQube Token", r"\bsq[pau]_[a-f0-9]{40}\b", "HIGH", "SonarQube/SonarCloud token"),

    # Payments
    _p("LS-STRIPE-001", "Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "HIGH", "Stripe live secret key"),
    _p("LS-STRIPE-002", "Stripe Live Publishable", r"pk_live_[0-9a-zA-Z]{24,}", "HIGH", "Stripe live publishable key"),
    _p("LS-STRIPE-003", "Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24,}", "MEDIUM", "Stripe test secret key"),
    _p("LS-STRIPE-004", "Stripe Restricted Key", r"\brk_live_[0-9a-zA-Z]{24,}\b", "HIGH", "Stripe live restricted key"),
    _p("LS-STRIPE-005", "Stripe Webhook Secret", r"\bwhsec_[A-Za-z0-9]{32,}\b", "HIGH", "Stripe webhook signing secret"),
    _p("LS-SQ-001", "Square Access Token", r"EAAAl[A-Za-z0-9_\-]{60}", "HIGH", "Square access token"),
    _p("LS-SQ-002", "Square OAuth Token", r"sq0(?:atp|csp)-[A-Za-z0-9\-_]{22,43}", "HIGH", "Square OAuth token"),
    _p("LS-PAY-001", "PayPal Client Secret",
       r"(?i)paypal(?:.{0,20})?client[_-]?secret\s*[=:]\s*['\"]?(E[A-Za-z0-9_-]{79})['\"]?",
       "HIGH", "PayPal client secret", confidence=0.75),
    _p("LS-PAY-002", "Razorpay Key ID", r"rzp_(?:live|test)_[A-Za-z0-9]{14,}", "HIGH", "Razorpay API key ID"),
    _p("LS-PAY-003", "Flutterwave Secret Key", r"FLWSECK-[a-f0-9]{32}-X", "HIGH", "Flutterwave secret key"),
    _p("LS-PAY-004", "Braintree Access Token",
       r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}", "HIGH", "Braintree production access token"),
    _p("LS-PAY-005", "Shippo API Token", r"\bshippo_(?:live|test)_[a-f0-9]{40}\b", "HIGH", "Shippo API token"),
    _p("LS-PAY-006", "Coinbase Access Token", r"(?i)coinbase(?:.{0,20})?['\"]([A-Za-z0-9]{64})['\"]",
       "HIGH", "Coinbase API access token", confidence=0.75),
    _p("LS-PAY-007", "Finicity App Key", r"(?i)finicity(?:.{0,20})?['\"]([a-f0-9]{32})['\"]",
       "HIGH", "Finicity application key", confidence=0.75),
    _p("LS-PII-001", "Credit Card Number",
       r"(?i)(?:card|credit|cc[_-]?(?:num|number|no)?|\bpan\b|visa|mastercard|amex|payment)[^\n]{0,40}?"
       r"\b((?:4[0-9]{3}|5[1-5][0-9]{2}|2[2-7][0-9]{2}|3[47][0-9]{2}|6011)(?:[ -]?[0-9]{4}){2}[ -]?[0-9]{3,4})\b",
       "MEDIUM", "Payment card number (Luhn-validated)", validate=luhn_ok, strict=True, confidence=0.6),

    # Messaging and email
    _p("LS-TWILIO-001", "Twilio Account SID", r"\bAC[0-9a-fA-F]{32}\b", "HIGH", "Twilio account SID"),
    _p("LS-TWILIO-002", "Twilio Auth Token", r"(?i)twilio(?:.{0,20})?['\"][0-9a-f]{32}['\"]", "HIGH",
       "Twilio auth token", confidence=0.75),
    _p("LS-TWILIO-003", "Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b", "HIGH", "Twilio API key SID", confidence=0.6),
    _p("LS-SG-001", "SendGrid API Key", r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}", "HIGH", "SendGrid API key"),
    _p("LS-SLACK-001", "Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", "HIGH", "Slack bot token"),
    _p("LS-SLACK-002", "Slack User Token", r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}", "HIGH", "Slack user token"),
    _p("LS-SLACK-003", "Slack Webhook",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "HIGH", "Slack incoming webhook URL"),
    _p("LS-SLACK-004", "Slack App Token", r"xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+", "MEDIUM", "Slack app-level token"),
    _p("LS-SLACK-005", "Slack Config Token", r"\bxoxe\.xox[bp]-\d-[A-Za-z0-9]{140,}\b", "HIGH", "Slack configuration token"),
    _p("LS-SLACK-006", "Slack Legacy Token", r"\bxox[aor]-(?:\d+-){2,3}[A-Za-z0-9]{24,}\b", "HIGH", "Slack legacy workspace token"),
    _p("LS-MAIL-001", "Mailgun API Key", r"\bkey-[0-9a-zA-Z]{32}\b", "HIGH", "Mailgun API key"),
    _p("LS-MAIL-002", "Mailchimp API Key", r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", "HIGH", "Mailchimp API key"),
    _p("LS-MAIL-003", "Postmark Server Token",
       r"(?i)postmark(?:.{0,20})?['\"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]",
       "HIGH", "Postmark server API token", confidence=0.75),
    _p("LS-MAIL-004", "Resend API Key", r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b", "HIGH", "Resend API key"),
    _p("LS-MAIL-005", "Brevo API Key", r"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b", "HIGH", "Brevo (Sendinblue) API key"),
    _p("LS-MAIL-006", "MailerSend API Token", r"\bmlsn\.[a-f0-9]{64}\b", "HIGH", "MailerSend API token"),
    _p("LS-TG-001", "Telegram Bot Token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "HIGH", "Telegram bot token"),
    _p("LS-DISCORD-001", "Discord Bot Token",
       r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}", "HIGH", "Discord bot token"),
    _p("LS-DISCORD-002", "Discord Webhook",
       r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9._-]{60,}", "HIGH", "Discord webhook URL"),
    _p("LS-TEAMS-001", "Microsoft Teams Webhook",
       r"https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]{36}@[a-f0-9-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9-]{36}",
       "HIGH", "Microsoft Teams incoming webhook URL"),
    _p("LS-TELNYX-001", "Telnyx API Key", r"\bKEY[0-9A-F]{32}_[A-Za-z0-9]{22}\b", "HIGH", "Telnyx API v2 key"),

    # AI and ML providers
    _p("LS-AI-001", "Anthropic API Key", r"sk-ant-[0-9a-zA-Z\-_]{40,}", "HIGH", "Anthropic API key"),
    _p("LS-AI-002", "OpenAI API Key", r"\bsk-[0-9a-zA-Z]{48}\b", "HIGH", "OpenAI legacy API key"),
    _p("LS-AI-003", "OpenAI Project Key", r"sk-proj-[A-Za-z0-9\-_]{100,}", "HIGH", "OpenAI project-scoped API key"),
    _p("LS-AI-004", "HuggingFace Token", r"\bhf_[a-zA-Z0-9]{34,}\b", "HIGH", "HuggingFace API token"),
    _p("LS-AI-005", "Replicate API Token", r"\br8_[A-Za-z0-9]{37,40}\b", "HIGH", "Replicate API token"),
    _p("LS-AI-006", "Cohere API Key", r"(?i)cohere(?:.{0,20})?['\"]([A-Za-z0-9]{40})['\"]", "HIGH",
       "Cohere API key", confidence=0.75),
    _p("LS-AI-007", "Groq API Key", r"\bgsk_[A-Za-z0-9]{52}\b", "HIGH", "Groq API key"),
    _p("LS-AI-008", "Pinecone API Key",
       r"(?i)pinecone(?:.{0,20})?['\"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]",
       "HIGH", "Pinecone API key", confidence=0.75),
    _ctx("LS-AI-009", "Mistral API Key", "mistral", r"[A-Za-z0-9]{32}", "HIGH", "Mistral AI API key"),
    _ctx("LS-AI-010", "Together AI API Key", "together", r"(?:tgp_v1_[A-Za-z0-9_\-]{43}|[a-f0-9]{64})", "HIGH",
         "Together AI API key"),
    _p("LS-AI-011", "Fireworks API Key", r"\bfw_[A-Za-z0-9]{24}\b", "HIGH", "Fireworks AI API key", confidence=0.8),
    _p("LS-AI-012", "Perplexity API Key", r"\bpplx-[A-Za-z0-9]{48}\b", "HIGH", "Perplexity API key"),
    _ctx("LS-AI-013", "DeepSeek API Key", "deepseek", r"sk-[a-f0-9]{32}", "HIGH", "DeepSeek API key"),
    _p("LS-AI-014", "xAI API Key", r"\bxai-[A-Za-z0-9]{80}\b", "HIGH", "xAI (Grok) API key"),
    _ctx("LS-AI-015", "Weights & Biases API Key", "wandb|weights_?and_?biases", r"[a-f0-9]{40}", "HIGH",
         "Weights & Biases API key"),
    _ctx("LS-AI-016", "Comet API Key", "comet", r"[A-Za-z0-9]{25}", "HIGH", "Comet ML API key"),
    _ctx("LS-AI-017", "Kaggle API Key", "kaggle", r"[a-f0-9]{32}", "HIGH", "Kaggle API key"),
    _p("LS-AI-018", "Modal Token Secret", r"\bas-[A-Za-z0-9]{22}\b", "HIGH", "Modal token secret", confidence=0.6),
    _p("LS-AI-019", "Cerebras API Key", r"\bcsk-[a-z0-9]{48}\b", "HIGH", "Cerebras API key"),
    _p("LS-AI-020", "OpenRouter API Key", r"\bsk-or-v1-[a-f0-9]{64}\b", "HIGH", "OpenRouter API key"),
    _p("LS-AI-021", "LangSmith API Key", r"\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b", "HIGH", "LangSmith API key"),
    _p("LS-AI-022", "Voyage AI API Key", r"\bpa-[A-Za-z0-9_\-]{43}\b", "HIGH", "Voyage AI API key", confidence=0.7),
    _p("LS-AI-023", "HuggingFace Org Token", r"\bapi_org_[A-Za-z0-9]{34}\b", "HIGH", "HuggingFace organization token"),
    _ctx("LS-AI-024", "ElevenLabs API Key", "elevenlabs|xi[_-]?api", r"(?:sk_)?[a-f0-9]{32,48}", "HIGH",
         "ElevenLabs API key"),
    _ctx("LS-AI-025", "AssemblyAI API Key", "assemblyai|assembly_ai", r"[a-f0-9]{32}", "HIGH", "AssemblyAI API key"),
    _ctx("LS-AI-026", "Deepgram API Key", "deepgram", r"[a-f0-9]{40}", "HIGH", "Deepgram API key"),
    _ctx("LS-AI-027", "Azure OpenAI Key", "azure_?openai|aoai", r"[a-f0-9]{32}", "HIGH", "Azure OpenAI API key"),

    # Cloud, hosting and infrastructure
    _p("LS-GCP-002", "Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "MEDIUM", "Google API key"),
    _p("LS-GCP-003", "Google OAuth Client Secret", r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b", "HIGH", "Google OAuth client secret"),
    _p("LS-GCP-004", "Google OAuth Access Token", r"\bya29\.[A-Za-z0-9_\-]{30,}\b", "HIGH", "Google OAuth access token"),
    _p("LS-GCP-005", "Firebase Config", r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}", "MEDIUM", "Firebase server key"),
    _p("LS-GCP-006", "Firebase Admin SDK Key",
       r'"client_email"\s*:\s*"firebase-adminsdk-[a-z0-9]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com"',
       "CRITICAL", "Firebase Admin SDK service account"),
    _p("LS-AZ-002", "Azure AD Client Secret",
       r"(?i)(?:azure|aad)(?:.{0,20})?client[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9_~.\-]{34,40})['\"]?",
       "CRITICAL", "Azure AD application client secret", confidence=0.75),
    _p("LS-AZ-003", "Azure SAS Token",
       r"(?i)[?&]sv=\d{4}-\d{2}-\d{2}&[^\s'\"]*sig=[A-Za-z0-9%+/]{40,}(?:%3D|=)?", "HIGH",
       "Azure shared access signature URL"),
    _ctx("LS-AZ-004", "Azure DevOps PAT", "azure_?devops|ado_?pat|vsts", r"[a-z0-9]{52}", "HIGH",
         "Azure DevOps personal access token"),
    _p("LS-ALI-001", "Alibaba Cloud Access Key", r"\bLTAI[A-Za-z0-9]{12,20}\b", "CRITICAL", "Alibaba Cloud AccessKey ID"),
    _p("LS-TENCENT-001", "Tencent Cloud Secret ID", r"\bAKID[A-Za-z0-9]{32}\b", "CRITICAL", "Tencent Cloud SecretId"),
    _p("LS-SCW-001", "Scaleway Access Key", r"\bSCW[A-Z0-9]{17}\b", "HIGH", "Scaleway access key", confidence=0.7),
    _p("LS-YC-001", "Yandex Cloud API Key", r"\bAQVN[A-Za-z0-9_\-]{35,38}\b", "HIGH", "Yandex Cloud API key"),
    _p("LS-DO-001", "DigitalOcean Token", r"\bdop_v1_[a-f0-9]{64}\b", "HIGH", "DigitalOcean personal access token"),
    _p("LS-DO-002", "DigitalOcean OAuth Token", r"\bdoo_v1_[a-f0-9]{64}\b", "HIGH", "DigitalOcean OAuth token"),
    _p("LS-CF-001", "Cloudflare Global Key", r"(?i)cloudflare(?:.{0,20})?['\"]([0-9a-f]{37})['\"]",
       "HIGH", "Cloudflare global API key", confidence=0.75),
    _p("LS-CF-002", "Cloudflare API Token",
       r"(?i)cloudflare(?:.{0,20})?api[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9_-]{40})['\"]?",
       "HIGH", "Cloudflare scoped API token", confidence=0.75),
    _p("LS-CF-003", "Cloudflare Origin CA Key", r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b", "HIGH", "Cloudflare Origin CA key"),
    _p("LS-VERCEL-001", "Vercel Token", r"\bvercel_[A-Za-z0-9]{24,}\b", "HIGH", "Vercel access token"),
    _p("LS-NETLIFY-001", "Netlify Access Token", r"\bnfp_[A-Za-z0-9]{36}\b", "HIGH", "Netlify personal access token"),
    _p("LS-RENDER-001", "Render API Key", r"\brnd_[A-Za-z0-9]{32}\b", "HIGH", "Render API key"),
    _p("LS-HEROKU-001", "Heroku API Key", r"\bHRKU-[A-Za-z0-9_\-]{58,60}\b", "HIGH", "Heroku platform API key"),
    _ctx("LS-HEROKU-002", "Heroku Legacy API Key", "heroku",
         r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "HIGH", "Heroku legacy API key"),
    _p("LS-FLY-001", "Fly.io API Token", r"fm2_[A-Za-z0-9+/_=-]{60,}", "HIGH", "Fly.io macaroon API token"),
    _p("LS-RAILWAY-001", "Railway API Token",
       r"(?i)railway(?:.{0,20})?['\"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]",
       "HIGH", "Railway project API token", confidence=0.75),
    _p("LS-DENO-001", "Deno Deploy Token", r"\bdd[pw]_[A-Za-z0-9]{36}\b", "HIGH", "Deno Deploy access token"),
    _p("LS-EXPO-001", "Expo Access Token", r"expo_[A-Za-z0-9_\-]{35,}", "HIGH", "Expo access token"),
    _p("LS-TF-001", "Terraform Cloud Token", r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,}", "HIGH",
       "Terraform Cloud token"),
    _p("LS-VAULT-001", "Vault Service Token", r"\bhvs\.[A-Za-z0-9_-]{90,}", "HIGH", "HashiCorp Vault service token"),
    _p("LS-VAULT-002", "Vault Batch Token", r"\bhvb\.[A-Za-z0-9_-]{130,}", "HIGH", "HashiCorp Vault batch token"),
    _p("LS-PULUMI-001", "Pulumi Access Token", r"\bpul-[a-f0-9]{40}\b", "HIGH", "Pulumi access token"),
    _p("LS-TS-001", "Tailscale Key", r"\btskey-(?:auth|api|client|webhook)-[A-Za-z0-9]{8,}-[A-Za-z0-9]{16,}\b", "HIGH",
       "Tailscale auth/API key"),
    _ctx("LS-NGROK-001", "ngrok Authtoken", "ngrok", r"[0-9A-Za-z]{24,27}_[0-9A-Za-z]{17,21}", "HIGH", "ngrok authtoken"),
    _p("LS-DOCKER-001", "Docker Hub Token", r"\bdckr_pat_[A-Za-z0-9_\-]{27}\b", "HIGH", "Docker Hub personal access token"),
    _p("LS-DOCKER-002", "Docker Config Auth",
       r'"auths"\s*:\s*\{[^}]*"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"', "HIGH", "Docker registry credentials in config.json"),
    _p("LS-K8S-001", "Kubernetes Service Account Token",
       r"eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
       "CRITICAL", "Kubernetes service account JWT (RS256)", validate=jwt_ok),
    _p("LS-WG-001", "WireGuard Private Key",
       r"(?im)^(?:PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/]{43}=\s*$", "CRITICAL", "WireGuard private/preshared key"),
    _p("LS-AGE-001", "Age Secret Key", r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}", "CRITICAL",
       "Age encryption secret key"),
    _p("LS-1P-001", "1Password Service Account Token", r"\bops_eyJ[A-Za-z0-9+/=_\-]{250,}", "CRITICAL",
       "1Password service account token"),
    _p("LS-DOPPLER-001", "Doppler Token", r"\bdp\.(?:st|pt|ct|sa|scim|audit)\.[A-Za-z0-9_-]{40,}", "HIGH",
       "Doppler service token"),
    _p("LS-INFISICAL-001", "Infisical Token", r"\bst\.[a-f0-9]{8}\.[a-f0-9]{32}\.[a-f0-9]{16}\b", "HIGH",
       "Infisical service token"),

    # Databases and data platforms
    _p("LS-DB-001", "Database URL",
       r"(?i)(?:mongodb|postgres|mysql|redis|amqp|elasticsearch)://[^\s'\"]+:[^\s'\"@]+@",
       "MEDIUM", "Database/broker URL with credentials", confidence=0.7),
    _p("LS-DB-002", "MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+",
       "CRITICAL", "MongoDB connection string with embedded credentials"),
    _p("LS-DB-003", "PostgreSQL Connection String", r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+",
       "CRITICAL", "PostgreSQL connection string with embedded credentials"),
    _p("LS-DB-004", "MySQL Connection String", r"mysql://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+",
       "CRITICAL", "MySQL connection string with embedded credentials"),
    _p("LS-DB-005", "Redis Connection String", r"rediss?://[^\s'\"]*:[^\s'\"@]+@[^\s'\"]+",
       "HIGH", "Redis connection string with embedded password"),
    _p("LS-DB-006", "Snowflake Connection String", r"(?i)snowflake://[^\s'\"/:]+:[^\s'\"@]+@[^\s'\"]+",
       "CRITICAL", "Snowflake connection string with embedded credentials"),
    _ctx("LS-DB-007", "Snowflake Password", "snowflake[_-]?(?:password|pwd)", r"[^\s'\"]{8,64}", "HIGH",
         "Snowflake account password"),
    _p("LS-DB-008", "Databricks Token", r"\bdapi[a-f0-9]{32}(?:-\d)?\b", "HIGH", "Databricks personal access token"),
    _p("LS-DB-009", "Supabase Service Key",
       r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}",
       "HIGH", "Supabase service role JWT key", validate=jwt_ok),
    _p("LS-DB-010", "Supabase API Key", r"\bsbp_[a-f0-9]{40}\b", "HIGH", "Supabase project API key"),
    _p("LS-DB-011", "PlanetScale Token", r"pscale_tkn_[A-Za-z0-9_-]{32,}", "HIGH", "PlanetScale database token"),
    _p("LS-DB-012", "PlanetScale OAuth Token", r"pscale_oauth_[A-Za-z0-9_-]{32,}", "HIGH", "PlanetScale OAuth token"),
    _p("LS-DB-013", "PlanetScale Password", r"pscale_pw_[A-Za-z0-9_-]{32,}", "HIGH", "PlanetScale password"),
    _p("LS-DB-014", "Neon API Key", r"\bnapi_[a-z0-9]{64}\b", "HIGH", "Neon API key"),
    _ctx("LS-DB-015", "Upstash Redis Token", "upstash", r"A[A-Za-z0-9_\-]{50,}=?", "HIGH", "Upstash REST token"),
    _ctx("LS-DB-016", "Turso Auth Token", "turso|libsql", r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
         "HIGH", "Turso/libSQL database auth token", validate=jwt_ok),
    _p("LS-DB-017", "Airtable Personal Access Token", r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", "HIGH",
       "Airtable personal access token"),
    _p("LS-DB-018", "Elastic Cloud API Key",
       r"(?i)(?:elastic|es)[_-]?(?:cloud[_-]?)?api[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9+/]{20,}={0,2})['\"]?",
       "HIGH", "Elastic Cloud API key", confidence=0.75),
    _ctx("LS-ALGOLIA-001", "Algolia Admin Key", "algolia", r"[a-f0-9]{32}", "HIGH", "Algolia admin API key"),

    # Identity and auth providers
    _ctx("LS-OKTA-001", "Okta API Token", "okta", r"00[A-Za-z0-9_\-]{40}", "HIGH", "Okta API token"),
    _ctx("LS-AUTH0-001", "Auth0 Client Secret", r"auth0[\w.\-]{0,20}secret", r"[A-Za-z0-9_\-]{64}", "HIGH",
         "Auth0 application client secret"),
    _ctx("LS-CLERK-001", "Clerk Secret Key", "clerk", r"sk_(?:live|test)_[A-Za-z0-9]{40,}", "HIGH", "Clerk secret key"),
    _p("LS-JWT-001", "JWT Token", r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "MEDIUM",
       "JWT token", validate=jwt_ok, strict=True, confidence=0.6),

    # Package registries
    _p("LS-NPM-001", "NPM Access Token", r"\bnpm_[A-Za-z0-9]{36}\b", "HIGH", "NPM access token"),
    _p("LS-PYPI-001", "PyPI API Token", r"pypi-[A-Za-z0-9_\-]{97,}", "HIGH", "PyPI API token"),
    _p("LS-RUBYGEMS-001", "RubyGems API Key", r"\brubygems_[a-f0-9]{48}\b", "HIGH", "RubyGems API key"),
    _p("LS-NUGET-001", "NuGet API Key", r"\boy2[a-z0-9]{43}\b", "HIGH", "NuGet API key"),
    _p("LS-CLOJARS-001", "Clojars Deploy Token", r"\bCLOJARS_[a-z0-9]{60}\b", "HIGH", "Clojars deploy token"),
    _p("LS-JFROG-001", "JFrog API Key", r"\bAKCp[A-Za-z0-9]{69}\b", "HIGH", "JFrog Artifactory API key"),
    _p("LS-NPMRC-001", "npmrc Auth Token", r"(?i)_auth(?:Token)?\s*=\s*['\"]?([A-Za-z0-9+/=_\-]{20,})",
       "HIGH", "Registry auth token in .npmrc", path=r"(?:^|/)\.npmrc$"),
    _p("LS-PYPIRC-001", "pypirc Password", r"(?i)^\s*password\s*[=:]\s*(\S{8,})",
       "HIGH", "Password in .pypirc", path=r"(?:^|/)\.pypirc$"),
    _p("LS-NETRC-001", "netrc Password", r"(?i)\bpassword\s+(\S{6,})",
       "HIGH", "Password in .netrc", path=r"(?:^|/)[._]netrc$"),

    # Productivity, observability and SaaS
    _p("LS-SHOPIFY-001", "Shopify Access Token", r"\bshpat_[a-fA-F0-9]{32}\b", "HIGH", "Shopify private access token"),
    _p("LS-SHOPIFY-002", "Shopify Shared Secret", r"\bshpss_[a-fA-F0-9]{32}\b", "HIGH", "Shopify shared secret"),
    _p("LS-SHOPIFY-003", "Shopify Custom App Token", r"\bshp(?:ca|pa)_[a-fA-F0-9]{32}\b", "HIGH",
       "Shopify custom/partner app token"),
    _p("LS-DROPBOX-001", "Dropbox Token", r"\bsl\.[A-Za-z0-9_-]{135}", "HIGH", "Dropbox access token"),
    _p("LS-NOTION-001", "Notion API Key", r"\b(?:secret|ntn)_[A-Za-z0-9]{43}\b", "HIGH", "Notion integration token"),
    _p("LS-LINEAR-001", "Linear API Key", r"\blin_api_[A-Za-z0-9]{40}\b", "HIGH", "Linear API key"),
    _p("LS-ATLASSIAN-001", "Atlassian API Token", r"ATATT3[A-Za-z0-9_\-=]{180,}", "HIGH", "Jira/Atlassian API token"),
    _p("LS-FIGMA-001", "Figma Personal Token", r"\bfigd_[A-Za-z0-9_\-]{40}\b", "HIGH", "Figma personal access token"),
    _p("LS-HUBSPOT-001", "HubSpot Private App Token", r"\bpat-(?:na|eu)1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
       "HIGH", "HubSpot private app access token"),
    _p("LS-TYPEFORM-001", "Typeform Token", r"\btfp_[A-Za-z0-9_\-]{44}_[A-Za-z0-9_\-]{14}\b", "HIGH",
       "Typeform personal access token"),
    _p("LS-CONTENTFUL-001", "Contentful Token", r"\bCFPAT-[A-Za-z0-9_\-]{43}\b", "HIGH", "Contentful personal access token"),
    _p("LS-POSTMAN-001", "Postman API Key", r"PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}", "HIGH", "Postman API key"),
    _p("LS-README-001", "ReadMe API Key", r"\brdme_[a-z0-9]{70}\b", "HIGH", "ReadMe API key"),
    _p("LS-PREFECT-001", "Prefect API Key", r"\bpnu_[A-Za-z0-9]{36}\b", "HIGH", "Prefect Cloud API key"),
    _p("LS-ADAFRUIT-001", "Adafruit IO Key", r"\baio_[A-Za-z0-9]{28}\b", "HIGH", "Adafruit IO key"),
    _p("LS-MAPBOX-001", "Mapbox Token", r"pk\.eyJ[A-Za-z0-9+/=._-]{40,}\.[A-Za-z0-9_-]{20,}", "HIGH", "Mapbox access token"),
    _p("LS-MAPBOX-002", "Mapbox Secret Token", r"\bsk\.eyJ[A-Za-z0-9+/=._-]{40,}\.[A-Za-z0-9_-]{20,}", "HIGH",
       "Mapbox secret access token"),
    _p("LS-TWITTER-001", "Twitter Bearer Token", r"AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{40,}", "HIGH",
       "Twitter/X bearer token"),
    _p("LS-FB-001", "Facebook Access Token", r"\bEAA[CD][A-Za-z0-9]{90,}\b", "HIGH", "Facebook/Meta access token"),
    _p("LS-TWITCH-001", "Twitch Client Secret",
       r"(?i)twitch(?:.{0,20})?client.?secret\s*[=:]\s*['\"]?([a-z0-9]{30})['\"]?", "HIGH", "Twitch client secret",
       confidence=0.75),
    _p("LS-NR-001", "New Relic API Key", r"\bNRAK-[A-Z0-9]{27}\b", "HIGH", "New Relic API key"),
    _p("LS-NR-002", "New Relic License Key", r"\b[A-Za-z0-9]{36}NRAL\b", "HIGH", "New Relic license key"),
    _p("LS-DD-001", "Datadog API Key",
       r"(?i)(?:dd|datadog)(?:_|-)?api(?:_|-)?key\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", "HIGH", "Datadog API key",
       confidence=0.75),
    _p("LS-DD-002", "Datadog App Key",
       r"(?i)(?:dd|datadog)(?:_|-)?app(?:_|-)?key\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?", "HIGH",
       "Datadog application key", confidence=0.75),
    _p("LS-GRAFANA-001", "Grafana Service Token", r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}", "HIGH",
       "Grafana service account token"),
    _p("LS-GRAFANA-002", "Grafana Cloud Token", r"glc_[A-Za-z0-9+/]{32,}={0,2}", "HIGH", "Grafana Cloud API token"),
    _p("LS-SENTRY-001", "Sentry Auth Token", r"\bsntry[su]_[A-Za-z0-9+/=_]{38,}", "HIGH", "Sentry auth token"),
    _p("LS-SENTRY-002", "Sentry DSN", r"https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.(?:[a-z]+\.)?sentry\.io/[0-9]+",
       "MEDIUM", "Sentry DSN (may contain private key)"),
    _p("LS-DYNATRACE-001", "Dynatrace API Token", r"\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b", "HIGH", "Dynatrace API token"),
    _ctx("LS-PD-001", "PagerDuty API Key", "pagerduty", r"[a-zA-Z0-9_+\-]{20}", "HIGH", "PagerDuty API key"),
    _p("LS-POSTHOG-001", "PostHog Personal API Key", r"\bphx_[A-Za-z0-9]{43}\b", "HIGH", "PostHog personal API key"),
    _p("LS-LD-001", "LaunchDarkly Access Token",
       r"\bapi-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b", "HIGH", "LaunchDarkly API access token",
       confidence=0.7),
    _ctx("LS-SNYK-001", "Snyk API Token", "snyk",
         r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "HIGH", "Snyk API token"),

    # Infrastructure-as-code, CI and container files
    _p("LS-IAC-001", "Dockerfile Secret",
       rf"(?im)^\s*(?:ENV|ARG)\s+{_SECRET_NAME}(?:\s*=\s*|\s+)['\"]?([^\s'\"$]{{6,}})",
       "HIGH", "Secret baked into a Dockerfile ENV/ARG",
       path=r"(?:^|/)(?:[\w.-]*Dockerfile[\w.-]*|Containerfile)$", confidence=0.8),
    _p("LS-IAC-002", "Env File Secret",
       rf"(?i)^\s*(?:export\s+)?{_SECRET_NAME}\s*=\s*['\"]?([^\s'\"$#{{}}<>]{{8,}})",
       "MEDIUM", "Secret assigned in a .env file", path=_ENVFILE, confidence=0.7),
    _p("LS-IAC-003", "Terraform State Secret",
       r'"(?:password|secret|access_key|secret_key|token|private_key|client_secret)"\s*:\s*"([^"]{6,})"',
       "CRITICAL", "Sensitive value in a Terraform state file", path=r"\.tfstate(?:\.backup)?$"),
    _p("LS-IAC-004", "Terraform Variable Secret",
       r'(?i)^\s*\w*(?:password|secret|token|api_key|access_key)\w*\s*=\s*"([^"$]{6,})"',
       "HIGH", "Secret in a Terraform .tfvars file", path=r"\.tfvars(?:\.json)?$", confidence=0.8),
    _p("LS-IAC-005", "Kubernetes Secret Data",
       r"(?i)^\s+[\w.\-]*(?:password|passwd|token|secret|api[_-]?key|\.key)[\w.\-]*:\s+['\"]?([A-Za-z0-9+/]{12,}={0,2})['\"]?\s*$",
       "HIGH", "Base64 secret value in a Kubernetes manifest or Helm values file",
       path=r"(?:k8s|kube|manifests?|charts?|helm|deploy)[^/]*/.*\.ya?ml$|(?:^|/)values[\w.-]*\.ya?ml$|secrets?\.ya?ml$",
       confidence=0.7),
    _p("LS-IAC-006", "GitHub Actions Hardcoded Secret",
       r"(?i)^\s+\w*(?:TOKEN|SECRET|PASSWORD|API_?KEY)\w*:\s*['\"]?(?!\$\{\{)([^\s'\"#]{8,})",
       "HIGH", "Literal secret in a GitHub Actions workflow instead of ${{ secrets.* }}",
       path=r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", confidence=0.8),
    _p("LS-IAC-007", "Compose File Secret",
       r"(?i)^\s*-?\s*\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*[=:]\s*['\"]?(?!\$\{)([^\s'\"#]{6,})",
       "HIGH", "Literal secret in a docker-compose environment block",
       path=r"(?:^|/)(?:docker-)?compose[\w.-]*\.ya?ml$", confidence=0.8),
    _p("LS-IAC-008", "Htpasswd Hash", r"^[\w.\-]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\})[^\s]{20,}$",
       "MEDIUM", "Password hash in an htpasswd file", path=r"(?:^|/)\.?htpasswd$"),

    # Generic and contextual
    _p("LS-GEN-001", "Generic API Key",
       r"(?i)(?:api_key|apikey|api-key)\s*[=:]\s*['\"]?([0-9a-zA-Z\-_]{16,})['\"]?",
       "MEDIUM", "Generic API key assignment", confidence=0.5),
    _p("LS-GEN-002", "Generic Secret",
       r"(?i)(?:secret|secret_key|client_secret)\s*[=:]\s*['\"]?([0-9a-zA-Z\-_]{16,})['\"]?",
       "MEDIUM", "Generic secret assignment", confidence=0.5),
    _p("LS-GEN-003", "Generic Password",
       r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
       "MEDIUM", "Hardcoded password", confidence=0.5),
    _p("LS-GEN-004", "Bearer Token", r"(?i)bearer\s+([a-zA-Z0-9\-_\.]{20,})", "MEDIUM", "Bearer token in header",
       confidence=0.5),
    _p("LS-GEN-005", "Basic Auth in URL", r"https?://[a-zA-Z0-9._\-]+:([a-zA-Z0-9._\-]{4,})@", "MEDIUM",
       "Basic auth credentials in URL", confidence=0.6),
    _p("LS-GEN-006", "Private Key File Path",
       r"(?i)(?:identity_file|private_key(?:_file)?)\s*[=:]\s*['\"]?([~\/][^\s'\"]+\.pem)['\"]?",
       "MEDIUM", "SSH/TLS private key file path in config", confidence=0.5),
    _p("LS-GEN-007", "PEM Certificate", r"-----BEGIN CERTIFICATE-----", "LOW", "PEM-encoded X.509 certificate",
       confidence=0.4, exclude_path=r"(?:^|/)(?:etc/ssl|etc/pki|usr/share/ca-certificates|usr/local/share/ca-certificates"
       r"|certifi|ca-certificates|ca-bundle|cacert)"),
    _p("LS-CRYPTO-001", "Ethereum Private Key",
       r"(?i)(?:eth|ethereum|wallet|private)[\w.\-]{0,20}(?:key|secret)['\"]?\s*[=:]\s*['\"]?(0x[a-f0-9]{64})\b",
       "CRITICAL", "Ethereum/EVM wallet private key", confidence=0.8),
]

ENTROPY_RULE_ID = "LS-ENTROPY-001"
ENTROPY_RULE_NAME = "High Entropy String"


_INDEX: dict[str, dict[str, Pattern]] = {}


def by_id() -> dict[str, Pattern]:
    if len(_INDEX.get("id", ())) != len(PATTERNS):
        _INDEX["id"] = {p.id: p for p in PATTERNS}
    return _INDEX["id"]


def by_name() -> dict[str, Pattern]:
    if len(_INDEX.get("name", ())) != len(PATTERNS):
        _INDEX["name"] = {p.name: p for p in PATTERNS}
    return _INDEX["name"]

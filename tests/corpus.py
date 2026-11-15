"""Positive and negative fixtures for every rule.

Values are generated at import time so the repository never contains
literal token-shaped strings. Each entry: rule_id -> (positive, negative, path).
"""
from __future__ import annotations

import base64
import json
import random
import string
import zlib

_rng = random.Random(1337)
ALNUM = string.ascii_letters + string.digits
HEXL = "0123456789abcdef"
LOWER = string.ascii_lowercase + string.digits
UPPER = string.ascii_uppercase + string.digits
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def R(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def H(n: int) -> str:
    return R(n, HEXL)


def L(n: int) -> str:
    return R(n, LOWER)


def U(n: int) -> str:
    return R(n, UPPER)


def UUID() -> str:
    return f"{H(8)}-{H(4)}-{H(4)}-{H(4)}-{H(12)}"


def gh(prefix: str) -> str:
    from scanner.patterns import _b62
    body = R(30)
    return f"{prefix}_{body}{_b62(zlib.crc32(body.encode()))}"


def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def jwt(header: dict, payload: dict) -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.{R(43, ALNUM + '-_')}"


def luhn_number(prefix: str, length: int) -> str:
    digits = [int(c) for c in prefix] + [_rng.randrange(10) for _ in range(length - len(prefix) - 1)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return "".join(map(str, digits)) + str((10 - total % 10) % 10)


HS256 = {"alg": "HS256", "typ": "JWT"}
RS256 = {"alg": "RS256", "kid": "k" + R(12)}
FUTURE = {"sub": "svc", "role": "service_role", "exp": 4102444800}

_card = luhn_number("4539", 16)
_bad_card = _card[:-1] + str((int(_card[-1]) + 1) % 10)
_gh_bad = gh("ghp")[:-1] + ("A" if not gh("ghp").endswith("A") else "B")

CORPUS: dict[str, tuple[str, str, str | None]] = {
    "LS-AWS-001": (f"AWS_ACCESS_KEY_ID=AKIA{R(16, B32)}", f"AWS_ACCESS_KEY_ID=AKIA{R(12, B32)}", None),
    "LS-AWS-002": (f'aws_secret_access_key = "{R(40, ALNUM + "/+")}"', 'aws_region = "us-east-1"', None),
    "LS-GCP-001": ('{"type": "service_account", "project_id": "p"}', '{"type": "authorized_user"}', None),
    "LS-KEY-001": ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PUBLIC KEY-----", None),
    "LS-KEY-002": ("-----BEGIN EC PRIVATE KEY-----", "-----BEGIN EC PARAMETERS-----", None),
    "LS-KEY-003": ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----BEGIN PGP PUBLIC KEY BLOCK-----", None),
    "LS-KEY-004": ("-----BEGIN OPENSSH PRIVATE KEY-----", "ssh-ed25519 AAAAC3Nza user@host", None),
    "LS-KEY-005": ("-----BEGIN PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----", None),
    "LS-KEY-006": ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN ENCRYPTED MESSAGE-----", None),
    "LS-KEY-007": ("-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN DSA PARAMETERS-----", None),
    "LS-AZ-001": (f"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={R(86, ALNUM + '+/')}==",
                  "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=short==", None),
    "LS-GH-001": (f'token = "{gh("ghp")}"', f'token = "{_gh_bad}"', None),
    "LS-GH-002": (f'token = "{gh("gho")}"', f'token = "gho_{R(20)}"', None),
    "LS-GH-003": (f'token = "{gh("ghs")}"', f'token = "ghs_{R(36)}"', None),
    "LS-GH-004": (f"ghr_{R(76)}", f"ghr_{R(40)}", None),
    "LS-GH-005": (f"github_pat_{R(22)}_{R(59)}", f"github_pat_{R(22)}", None),
    "LS-GL-001": (f"glpat-{R(20)}", f"glpat-{R(10)}", None),
    "LS-GL-002": (f"glcbt-{R(20)}", f"glcbt-{R(8)}", None),
    "LS-GL-003": (f"glrt-{R(20)}", f"glrt-{R(8)}", None),
    "LS-GL-004": (f"gldt-{R(20)}", f"gldt-{R(8)}", None),
    "LS-BB-001": (f"ATBB{R(32)}", f"ATBB{R(10)}", None),
    "LS-CI-001": (f"CCIPAT_{R(22)}_{H(40)}", f"CCIPAT_{R(22)}", None),
    "LS-CI-002": (f"bkua_{H(40)}", f"bkua_{H(20)}", None),
    "LS-CI-003": (f"sqp_{H(40)}", f"sqp_{H(20)}", None),
    "LS-STRIPE-001": (f"sk_live_{R(24)}", f"sk_live_{R(10)}", None),
    "LS-STRIPE-002": (f"pk_live_{R(24)}", f"pk_live_{R(10)}", None),
    "LS-STRIPE-003": (f"sk_test_{R(24)}", f"sk_test_{R(10)}", None),
    "LS-STRIPE-004": (f"rk_live_{R(24)}", f"rk_live_{R(10)}", None),
    "LS-STRIPE-005": (f"whsec_{R(32)}", f"whsec_{R(10)}", None),
    "LS-SQ-001": (f"EAAAl{R(60, ALNUM + '_-')}", f"EAAAl{R(20)}", None),
    "LS-SQ-002": (f"sq0atp-{R(22)}", f"sq0atp-{R(10)}", None),
    "LS-PAY-001": (f'PAYPAL_CLIENT_SECRET = "E{R(79)}"', 'PAYPAL_CLIENT_ID = "abc"', None),
    "LS-PAY-002": (f"rzp_live_{R(14)}", f"rzp_live_{R(6)}", None),
    "LS-PAY-003": (f"FLWSECK-{H(32)}-X", f"FLWSECK-{H(10)}-X", None),
    "LS-PAY-004": (f"access_token$production${L(16)}${H(32)}", f"access_token$sandbox${L(16)}${H(32)}", None),
    "LS-PAY-005": (f"shippo_live_{H(40)}", f"shippo_live_{H(10)}", None),
    "LS-PAY-006": (f'coinbase_token = "{R(64)}"', 'coinbase_url = "https://api.coinbase.com"', None),
    "LS-PAY-007": (f'finicity_key = "{H(32)}"', 'finicity_env = "prod"', None),
    "LS-PII-001": (f"card = {_card}", f"card = {_bad_card}", None),
    "LS-TWILIO-001": (f"AC{H(32)}", f"AC{H(10)}", None),
    "LS-TWILIO-002": (f'twilio_auth = "{H(32)}"', 'twilio_region = "us1"', None),
    "LS-TWILIO-003": (f"SK{H(32)}", f"SK{H(12)}", None),
    "LS-SG-001": (f"SG.{R(22)}.{R(43)}", f"SG.{R(10)}.{R(10)}", None),
    "LS-SLACK-001": (f"xoxb-{R(11, string.digits)}-{R(12, string.digits)}-{R(24)}", "xoxb-123-456-abc", None),
    "LS-SLACK-002": (f"xoxp-{R(11, string.digits)}-{R(12, string.digits)}-{R(32)}", "xoxp-123-456-abc", None),
    "LS-SLACK-003": (f"https://hooks.slack.com/services/T{U(9)}/B{U(9)}/{R(24)}", "https://hooks.slack.com/", None),
    "LS-SLACK-004": (f"xapp-1-A{U(10)}-{R(12, string.digits)}-{H(64)}", "xapp-token", None),
    "LS-SLACK-005": (f"xoxe.xoxp-1-{R(150)}", f"xoxe.xoxp-1-{R(20)}", None),
    "LS-SLACK-006": (f"xoxa-{R(11, string.digits)}-{R(11, string.digits)}-{R(30)}", "xoxa-2-abc", None),
    "LS-MAIL-001": (f"key-{R(32)}", f"key-{R(10)}", None),
    "LS-MAIL-002": (f"{H(32)}-us14", f"{H(20)}-us14", None),
    "LS-MAIL-003": (f'postmark_token = "{UUID()}"', 'postmark_from = "a@b.c"', None),
    "LS-MAIL-004": (f"re_{R(8)}_{R(24)}", f"re_{R(4)}_{R(8)}", None),
    "LS-MAIL-005": (f"xkeysib-{H(64)}-{R(16)}", f"xkeysib-{H(20)}", None),
    "LS-MAIL-006": (f"mlsn.{H(64)}", f"mlsn.{H(20)}", None),
    "LS-TG-001": (f"bot = '{R(10, string.digits)}:{R(35, ALNUM + '_-')}'", "time = '12:30'", None),
    "LS-DISCORD-001": (f"M{R(23)}.{R(6)}.{R(27)}", f"M{R(10)}.{R(6)}.{R(10)}", None),
    "LS-DISCORD-002": (f"https://discord.com/api/webhooks/{R(18, string.digits)}/{R(68)}",
                       "https://discord.com/api/webhooks/", None),
    "LS-TEAMS-001": (f"https://acme.webhook.office.com/webhookb2/{UUID()}@{UUID()}/IncomingWebhook/{H(32)}/{UUID()}",
                     "https://acme.webhook.office.com/webhookb2/", None),
    "LS-TELNYX-001": (f"KEY{R(32, '0123456789ABCDEF')}_{R(22)}", f"KEY{R(10, '0123456789ABCDEF')}", None),
    "LS-AI-001": (f"sk-ant-api03-{R(90, ALNUM + '-_')}", f"sk-ant-{R(10)}", None),
    "LS-AI-002": (f"sk-{R(48)}", f"sk-{R(20)}", None),
    "LS-AI-003": (f"sk-proj-{R(120, ALNUM + '-_')}", f"sk-proj-{R(30)}", None),
    "LS-AI-004": (f"hf_{R(34)}", f"hf_{R(10)}", None),
    "LS-AI-005": (f"r8_{R(37)}", f"r8_{R(10)}", None),
    "LS-AI-006": (f'COHERE_API_KEY = "{R(40)}"', 'COHERE_MODEL = "command"', None),
    "LS-AI-007": (f"gsk_{R(52)}", f"gsk_{R(20)}", None),
    "LS-AI-008": (f'PINECONE_API_KEY = "{UUID()}"', 'PINECONE_ENV = "gcp"', None),
    "LS-AI-009": (f"MISTRAL_API_KEY={R(32)}", f"MISTRAL_MODEL={R(10)}", None),
    "LS-AI-010": (f"TOGETHER_API_KEY={H(64)}", f"TOGETHER_API_KEY={H(20)}", None),
    "LS-AI-011": (f"fw_{R(24)}", f"fw_{R(10)}", None),
    "LS-AI-012": (f"pplx-{R(48)}", f"pplx-{R(20)}", None),
    "LS-AI-013": (f'DEEPSEEK_API_KEY = "sk-{H(32)}"', f'DEEPSEEK_API_KEY = "sk-{H(10)}"', None),
    "LS-AI-014": (f"xai-{R(80)}", f"xai-{R(20)}", None),
    "LS-AI-015": (f"WANDB_API_KEY={H(40)}", f"WANDB_API_KEY={H(12)}", None),
    "LS-AI-016": (f"COMET_API_KEY={R(25)}", f"COMET_API_KEY={R(8)}", None),
    "LS-AI-017": (f'"kaggle_key": "{H(32)}"', f'"kaggle_key": "{H(10)}"', None),
    "LS-AI-018": (f"MODAL_TOKEN_SECRET=as-{R(22)}", f"as-{R(8)}", None),
    "LS-AI-019": (f"csk-{L(48)}", f"csk-{L(10)}", None),
    "LS-AI-020": (f"sk-or-v1-{H(64)}", f"sk-or-v1-{H(20)}", None),
    "LS-AI-021": (f"lsv2_pt_{H(32)}_{H(10)}", f"lsv2_pt_{H(10)}", None),
    "LS-AI-022": (f"pa-{R(43, ALNUM + '_-')}", f"pa-{R(10)}", None),
    "LS-AI-023": (f"api_org_{R(34)}", f"api_org_{R(10)}", None),
    "LS-AI-024": (f"ELEVENLABS_API_KEY=sk_{H(48)}", f"ELEVENLABS_VOICE={R(8)}", None),
    "LS-AI-025": (f"ASSEMBLYAI_API_KEY={H(32)}", f"ASSEMBLYAI_API_KEY={H(10)}", None),
    "LS-AI-026": (f"DEEPGRAM_API_KEY={H(40)}", f"DEEPGRAM_API_KEY={H(10)}", None),
    "LS-AI-027": (f"AZURE_OPENAI_API_KEY={H(32)}", f"AZURE_OPENAI_ENDPOINT={R(8)}", None),
    "LS-GCP-002": (f"AIza{R(35, ALNUM + '-_')}", f"AIza{R(10)}", None),
    "LS-GCP-003": (f"GOCSPX-{R(28, ALNUM + '_-')}", f"GOCSPX-{R(10)}", None),
    "LS-GCP-004": (f"ya29.{R(60, ALNUM + '_-')}", f"ya29.{R(10)}", None),
    "LS-GCP-005": (f"AAAA{R(7)}:{R(140, ALNUM + '_-')}", f"AAAA{R(7)}:{R(20)}", None),
    "LS-GCP-006": ('"client_email": "firebase-adminsdk-abc12@my-proj.iam.gserviceaccount.com"',
                   '"client_email": "dev@my-proj.iam.gserviceaccount.com"', None),
    "LS-AZ-002": (f'AZURE_CLIENT_SECRET = "{R(36, ALNUM + "_~.-")}"', 'AZURE_CLIENT_ID = "abc"', None),
    "LS-AZ-003": (f"https://acct.blob.core.windows.net/c?sv=2022-11-02&ss=b&srt=co&sp=rl&sig={R(44)}%3D",
                  "https://acct.blob.core.windows.net/c?sv=2022-11-02&ss=b", None),
    "LS-AZ-004": (f"AZURE_DEVOPS_PAT={L(52)}", f"AZURE_DEVOPS_PAT={L(20)}", None),
    "LS-ALI-001": (f"LTAI{R(16)}", f"LTAI{R(6)}", None),
    "LS-TENCENT-001": (f"AKID{R(32)}", f"AKID{R(10)}", None),
    "LS-SCW-001": (f"SCW{U(17)}", f"SCW{U(6)}", None),
    "LS-YC-001": (f"AQVN{R(36, ALNUM + '_-')}", f"AQVN{R(10)}", None),
    "LS-DO-001": (f"dop_v1_{H(64)}", f"dop_v1_{H(20)}", None),
    "LS-DO-002": (f"doo_v1_{H(64)}", f"doo_v1_{H(20)}", None),
    "LS-CF-001": (f'cloudflare_key = "{H(37)}"', 'cloudflare_zone = "example.org"', None),
    "LS-CF-002": (f"CLOUDFLARE_API_TOKEN = '{R(40, ALNUM + '_-')}'", "CLOUDFLARE_API_TOKEN = ''", None),
    "LS-CF-003": (f"v1.0-{H(24)}-{H(146)}", f"v1.0-{H(24)}-{H(20)}", None),
    "LS-VERCEL-001": (f"vercel_{R(24)}", f"vercel_{R(8)}", None),
    "LS-NETLIFY-001": (f"nfp_{R(36)}", f"nfp_{R(10)}", None),
    "LS-RENDER-001": (f"rnd_{R(32)}", f"rnd_{R(10)}", None),
    "LS-HEROKU-001": (f"HRKU-{R(60, ALNUM + '_-')}", f"HRKU-{R(10)}", None),
    "LS-HEROKU-002": (f"HEROKU_API_KEY={UUID()}", "HEROKU_APP=my-app", None),
    "LS-FLY-001": (f"fm2_{R(80)}", f"fm2_{R(20)}", None),
    "LS-RAILWAY-001": (f'RAILWAY_TOKEN = "{UUID()}"', 'RAILWAY_ENV = "prod"', None),
    "LS-DENO-001": (f"ddp_{R(36)}", f"ddp_{R(10)}", None),
    "LS-EXPO-001": (f"expo_{R(40)}", f"expo_{R(10)}", None),
    "LS-TF-001": (f"{R(14)}.atlasv1.{R(70)}", f"{R(14)}.atlasv1.{R(10)}", None),
    "LS-VAULT-001": (f"hvs.{R(95)}", f"hvs.{R(20)}", None),
    "LS-VAULT-002": (f"hvb.{R(140)}", f"hvb.{R(20)}", None),
    "LS-PULUMI-001": (f"pul-{H(40)}", f"pul-{H(10)}", None),
    "LS-TS-001": (f"tskey-auth-{R(12)}-{R(30)}", "tskey-auth-short", None),
    "LS-NGROK-001": (f"NGROK_AUTHTOKEN={R(27)}_{R(21)}", f"NGROK_AUTHTOKEN={R(10)}", None),
    "LS-DOCKER-001": (f"dckr_pat_{R(27, ALNUM + '_-')}", f"dckr_pat_{R(10)}", None),
    "LS-DOCKER-002": ('{"auths": {"ghcr.io": {"auth": "' + R(24) + '"}}}', '{"auths": {}}', None),
    "LS-K8S-001": (jwt({"alg": "RS256", "kid": "abcdefghijklmnop"}, {"iss": "kubernetes/serviceaccount", "exp": 4102444800}),
                   "eyJhbGciOiJSUzI1NiIsImtpZCI6short", None),
    "LS-WG-001": (f"PrivateKey = {R(43, ALNUM + '+/')}=", "PublicKey = abc=", None),
    "LS-AGE-001": ("AGE-SECRET-KEY-1" + R(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"), "AGE-SECRET-KEY-1ABC", None),
    "LS-1P-001": (f"ops_eyJ{R(300)}", f"ops_eyJ{R(20)}", None),
    "LS-DOPPLER-001": (f"dp.st.{R(44)}", f"dp.st.{R(10)}", None),
    "LS-INFISICAL-001": (f"st.{H(8)}.{H(32)}.{H(16)}", f"st.{H(8)}.{H(10)}", None),
    "LS-DB-001": (f"amqp://admin:{R(12)}@broker:5672", "amqp://broker:5672", None),
    "LS-DB-002": (f"mongodb+srv://app:{R(16)}@cluster0.mongodb.net/db", "mongodb://localhost:27017/db", None),
    "LS-DB-003": (f"postgresql://app:{R(16)}@db:5432/app", "postgresql://localhost/app", None),
    "LS-DB-004": (f"mysql://app:{R(16)}@db:3306/app", "mysql://localhost/app", None),
    "LS-DB-005": (f"redis://:{R(16)}@cache:6379/0", "redis://cache:6379/0", None),
    "LS-DB-006": (f"snowflake://etl:{R(16)}@acme-xy12345/db", "snowflake://acme-xy12345/db", None),
    "LS-DB-007": (f"SNOWFLAKE_PASSWORD={R(16)}", "SNOWFLAKE_ACCOUNT=acme", None),
    "LS-DB-008": (f"dapi{H(32)}", f"dapi{H(10)}", None),
    "LS-DB-009": (jwt(HS256, FUTURE), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.short.sig", None),
    "LS-DB-010": (f"sbp_{H(40)}", f"sbp_{H(10)}", None),
    "LS-DB-011": (f"pscale_tkn_{R(40)}", f"pscale_tkn_{R(10)}", None),
    "LS-DB-012": (f"pscale_oauth_{R(40)}", f"pscale_oauth_{R(10)}", None),
    "LS-DB-013": (f"pscale_pw_{R(40)}", f"pscale_pw_{R(10)}", None),
    "LS-DB-014": (f"napi_{L(64)}", f"napi_{L(10)}", None),
    "LS-DB-015": (f"UPSTASH_REDIS_REST_TOKEN=A{R(60, ALNUM + '_-')}", "UPSTASH_REDIS_REST_URL=https://x", None),
    "LS-DB-016": (f"TURSO_AUTH_TOKEN={jwt({'alg': 'EdDSA', 'typ': 'JWT'}, {'a': 'rw'})}", "TURSO_DB=mydb", None),
    "LS-DB-017": (f"pat{R(14)}.{H(64)}", f"pat{R(14)}.{H(10)}", None),
    "LS-DB-018": (f'ELASTIC_API_KEY = "{R(40, ALNUM + "+/")}=="', 'ELASTIC_HOST = "es:9200"', None),
    "LS-ALGOLIA-001": (f"ALGOLIA_ADMIN_KEY={H(32)}", f"ALGOLIA_APP_ID={U(10)}", None),
    "LS-OKTA-001": (f"OKTA_API_TOKEN=00{R(40, ALNUM + '_-')}", "OKTA_DOMAIN=acme.okta.com", None),
    "LS-AUTH0-001": (f"AUTH0_CLIENT_SECRET={R(64, ALNUM + '_-')}", "AUTH0_DOMAIN=acme.auth0.com", None),
    "LS-CLERK-001": (f"CLERK_SECRET_KEY=sk_live_{R(48)}", "CLERK_PUBLISHABLE_KEY=pk_live_abc", None),
    "LS-JWT-001": (jwt({"alg": "HS512", "typ": "JWT"}, {"sub": "u1", "exp": 4102444800}), "eyJnotjson.eyJnotjson.sig", None),
    "LS-NPM-001": (f"npm_{R(36)}", f"npm_{R(10)}", None),
    "LS-PYPI-001": (f"pypi-AgEIcHlwaS5vcmc{R(100, ALNUM + '_-')}", f"pypi-{R(20)}", None),
    "LS-RUBYGEMS-001": (f"rubygems_{H(48)}", f"rubygems_{H(10)}", None),
    "LS-NUGET-001": (f"oy2{L(43)}", f"oy2{L(10)}", None),
    "LS-CLOJARS-001": (f"CLOJARS_{L(60)}", f"CLOJARS_{L(10)}", None),
    "LS-JFROG-001": (f"AKCp{R(69)}", f"AKCp{R(20)}", None),
    "LS-NPMRC-001": (f"//registry.npmjs.org/:_authToken={R(36)}", "registry=https://registry.npmjs.org/", ".npmrc"),
    "LS-PYPIRC-001": (f"password = {R(20)}", "username = __token__", ".pypirc"),
    "LS-NETRC-001": (f"machine github.com login me password {R(20)}", "machine github.com login me", ".netrc"),
    "LS-SHOPIFY-001": (f"shpat_{H(32)}", f"shpat_{H(10)}", None),
    "LS-SHOPIFY-002": (f"shpss_{H(32)}", f"shpss_{H(10)}", None),
    "LS-SHOPIFY-003": (f"shpca_{H(32)}", f"shpca_{H(10)}", None),
    "LS-DROPBOX-001": (f"sl.{R(135, ALNUM + '_-')}", f"sl.{R(20)}", None),
    "LS-NOTION-001": (f"ntn_{R(43)}", f"ntn_{R(10)}", None),
    "LS-LINEAR-001": (f"lin_api_{R(40)}", f"lin_api_{R(10)}", None),
    "LS-ATLASSIAN-001": (f"ATATT3{R(190)}", f"ATATT3{R(20)}", None),
    "LS-FIGMA-001": (f"figd_{R(40, ALNUM + '_-')}", f"figd_{R(10)}", None),
    "LS-HUBSPOT-001": (f"pat-na1-{UUID()}", "pat-na1-short", None),
    "LS-TYPEFORM-001": (f"tfp_{R(44)}_{R(14)}", f"tfp_{R(10)}", None),
    "LS-CONTENTFUL-001": (f"CFPAT-{R(43)}", f"CFPAT-{R(10)}", None),
    "LS-POSTMAN-001": (f"PMAK-{R(24)}-{R(34)}", f"PMAK-{R(10)}", None),
    "LS-README-001": (f"rdme_{L(70)}", f"rdme_{L(10)}", None),
    "LS-PREFECT-001": (f"pnu_{R(36)}", f"pnu_{R(10)}", None),
    "LS-ADAFRUIT-001": (f"aio_{R(28)}", f"aio_{R(10)}", None),
    "LS-MAPBOX-001": (f"pk.eyJ{R(60)}.{R(22)}", f"pk.eyJ{R(10)}", None),
    "LS-MAPBOX-002": (f"sk.eyJ{R(60)}.{R(22)}", f"sk.eyJ{R(10)}", None),
    "LS-TWITTER-001": ("AAAAAAAAAAAAAAAAAAAAA" + R(60), "AAAAAAAAAAAAAAAAAAAAA" + R(10), None),
    "LS-FB-001": (f"EAAC{R(120)}", f"EAAC{R(20)}", None),
    "LS-TWITCH-001": (f'TWITCH_CLIENT_SECRET = "{L(30)}"', 'TWITCH_CLIENT_ID = "abc"', None),
    "LS-NR-001": (f"NRAK-{U(27)}", f"NRAK-{U(10)}", None),
    "LS-NR-002": (f"{R(36)}NRAL", f"{R(10)}NRAL", None),
    "LS-DD-001": (f"DD_API_KEY={H(32)}", f"DD_API_KEY={H(10)}", None),
    "LS-DD-002": (f"DD_APP_KEY={H(40)}", f"DD_APP_KEY={H(10)}", None),
    "LS-GRAFANA-001": (f"glsa_{R(32)}_{H(8)}", f"glsa_{R(10)}", None),
    "LS-GRAFANA-002": (f"glc_{R(48)}", f"glc_{R(10)}", None),
    "LS-SENTRY-001": (f"sntrys_{R(60)}", f"sntrys_{R(10)}", None),
    "LS-SENTRY-002": (f"https://{H(32)}@o123.ingest.sentry.io/456", "https://sentry.io/456", None),
    "LS-DYNATRACE-001": (f"dt0c01.{U(24)}.{U(64)}", f"dt0c01.{U(10)}", None),
    "LS-PD-001": (f"PAGERDUTY_TOKEN={R(20)}", "PAGERDUTY_SERVICE=svc", None),
    "LS-POSTHOG-001": (f"phx_{R(43)}", f"phx_{R(10)}", None),
    "LS-LD-001": (f"api-{UUID()}", "api-short", None),
    "LS-SNYK-001": (f"SNYK_TOKEN={UUID()}", "SNYK_ORG=acme", None),
    "LS-IAC-001": (f"ENV DB_PASSWORD={R(16)}", "ENV DB_PASSWORD=$DB_PASSWORD", "Dockerfile"),
    "LS-IAC-002": (f"STRIPE_SECRET={R(20)}", "STRIPE_SECRET=", ".env.production"),
    "LS-IAC-003": (f'"password": "{R(16)}",', '"password": "",', "terraform.tfstate"),
    "LS-IAC-004": (f'db_password = "{R(16)}"', 'db_password = var.db_password', "prod.tfvars"),
    "LS-IAC-005": (f"  password: {R(24)}=", "  password: ''", "k8s/secret.yaml"),
    "LS-IAC-006": (f"          API_TOKEN: {R(24)}", "          API_TOKEN: ${{ secrets.API_TOKEN }}", ".github/workflows/ci.yml"),
    "LS-IAC-007": (f"      - POSTGRES_PASSWORD={R(16)}", "      - POSTGRES_PASSWORD=${PG_PASS}", "docker-compose.yml"),
    "LS-IAC-008": (f"admin:$apr1${R(8)}${R(22)}", "admin:", ".htpasswd"),
    "LS-GEN-001": (f'api_key = "{R(24)}"', 'api_key = ""', None),
    "LS-GEN-002": (f'client_secret = "{R(24)}"', 'client_secret = ""', None),
    "LS-GEN-003": (f'password = "{R(14)}"', 'password = ""', None),
    "LS-GEN-004": (f"Authorization: Bearer {R(40)}", "Authorization: Bearer", None),
    "LS-GEN-005": (f"https://deploy:{R(16)}@git.internal.net/repo.git", "https://git.internal.net/repo.git", None),
    "LS-GEN-006": ("private_key_file = /etc/ssl/private/server.pem", "private_key_file = env", None),
    "LS-GEN-007": ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE REQUEST-----", None),
    "LS-CRYPTO-001": (f'WALLET_PRIVATE_KEY = "0x{H(64)}"', f'WALLET_ADDRESS = "0x{H(40)}"', None),
}

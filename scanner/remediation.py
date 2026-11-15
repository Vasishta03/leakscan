from __future__ import annotations

from dataclasses import dataclass

_DOCS = "https://vasishta03.github.io/leakscan/rules/"


@dataclass
class Remediation:
    consequence: str
    blast_radius: str
    rotation_url: str


# secret_type -> (consequence if leaked, blast radius label, rotation action URL)
_DATA: dict[str, tuple[str, str, str]] = {
    "AWS Access Key ID": ("Combined with its secret key, an attacker can call any AWS API the underlying IAM identity is permitted to use, including launching compute, reading S3 buckets, and modifying IAM policies.", "Full cloud account compromise", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    "AWS Secret Access Key": ("Combined with the access key ID, this authenticates as the IAM identity, allowing full programmatic control over every AWS service that identity can reach.", "Full cloud account compromise", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    "GCP Service Account": ("This JSON key authenticates as the service account with all of its granted IAM roles, potentially exposing Compute Engine, Cloud Storage, BigQuery data, and billing controls.", "Full cloud project compromise", "https://console.cloud.google.com/iam-admin/serviceaccounts"),
    "RSA Private Key": ("Allows an attacker to impersonate the key owner for SSH logins, TLS termination, or code signing wherever the matching public key is trusted.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "EC Private Key": ("Allows an attacker to impersonate the key owner for SSH logins or TLS connections wherever the matching public key is trusted.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "PGP Private Key": ("Allows an attacker to decrypt messages encrypted to this key and to forge signatures that appear to come from its owner.", "Identity impersonation and data decryption", "https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key"),
    "OpenSSH Private Key": ("Grants direct SSH access to every server and account that trusts the matching public key.", "Server access", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "PKCS8 Private Key": ("Allows impersonation of the key owner for TLS, signing, or authentication wherever the matching public key or certificate is trusted.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "PKCS8 Encrypted Key": ("If the encryption passphrase is also exposed or weak, this provides the same access as an unencrypted private key.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "DSA Private Key": ("Grants SSH access to any server or account that trusts the matching public key.", "Server access", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "Azure Storage Key": ("Grants full read, write, and delete access to every blob, queue, table, and file share in the storage account, plus the ability to generate SAS tokens.", "Full Azure Storage account compromise", "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"),

    "GitHub Personal Token": ("Grants API access to every repository, organization, and setting the token's scopes allow, including private source code and the ability to push commits.", "Source code and CI/CD compromise", "https://github.com/settings/tokens"),
    "GitHub OAuth Token": ("Acts on behalf of the authorizing user with whatever scopes were granted during the OAuth flow, including private repo access.", "Source code and account access", "https://github.com/settings/applications"),
    "GitHub App Token": ("Grants the GitHub App's installed permissions on every repository it has been installed into, often including code, issues, and CI/CD secrets.", "Source code and CI/CD compromise", "https://github.com/settings/installations"),
    "GitHub Refresh Token": ("Can be exchanged for new access tokens indefinitely, giving an attacker long-lived access to the authorizing user's account and repositories.", "Long-lived account and source code access", "https://github.com/settings/applications"),
    "GitLab Personal Token": ("Grants API access to every project and group the token's scopes allow, including private repository contents and CI/CD variables.", "Source code and CI/CD compromise", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    "GitLab CI Token": ("Allows pulling and pushing container registries and packages, and can read protected CI/CD variables for the project.", "CI/CD pipeline compromise", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    "Stripe Live Secret Key": ("Allows full access to the live Stripe account: charges, refunds, customer payment data, payouts, and account configuration.", "Payment processing and customer financial data", "https://dashboard.stripe.com/apikeys"),
    "Stripe Live Publishable": ("Lower risk than the secret key, but combined with other leaked information it can be used to create tokens or charges against the account in some configurations.", "Payment integration abuse", "https://dashboard.stripe.com/apikeys"),
    "Twilio Account SID": ("Identifies the Twilio account; combined with the matching auth token it allows sending SMS/calls and accessing call logs and recordings, billed to the account owner.", "Communications abuse and billing fraud", "https://console.twilio.com/us1/account/keys-credentials/api-keys"),
    "Twilio Auth Token": ("Combined with the account SID, allows sending SMS and making calls billed to the account, and reading call/message logs and recordings.", "Communications abuse and billing fraud", "https://console.twilio.com/us1/account/keys-credentials/api-keys"),
    "SendGrid API Key": ("Allows sending email as any verified sender on the account, harvesting contact lists, and reading email activity, often used for phishing campaigns.", "Email sending abuse and phishing", "https://app.sendgrid.com/settings/api_keys"),
    "Slack Bot Token": ("Allows the bot to read messages, post as itself, and access any workspace data its OAuth scopes permit.", "Workspace communication compromise", "https://api.slack.com/apps"),
    "Slack User Token": ("Acts as the authorizing user, allowing the attacker to read private channels, DMs, and post messages as that person.", "User account and workspace compromise", "https://api.slack.com/apps"),
    "Slack Webhook": ("Allows anyone with the URL to post arbitrary messages into the configured channel, useful for phishing or spam inside the organization.", "Channel spam and phishing", "https://api.slack.com/messaging/webhooks"),
    "Mailgun API Key": ("Allows sending email through every domain configured on the account and reading mailing lists and logs, commonly abused for phishing.", "Email sending abuse and phishing", "https://app.mailgun.com/app/account/security/api_keys"),
    "Anthropic API Key": ("Allows making Claude API calls billed to the account owner, potentially racking up large usage charges or exhausting rate limits.", "API usage and billing abuse", "https://console.anthropic.com/settings/keys"),
    "OpenAI API Key": ("Allows making OpenAI API calls billed to the account owner, including high-cost model usage, and may expose any fine-tuned models or files on the account.", "API usage and billing abuse", "https://platform.openai.com/api-keys"),
    "OpenAI Project Key": ("Scoped to a single OpenAI project, but still allows API usage billed to that project and access to its resources.", "API usage and billing abuse", "https://platform.openai.com/api-keys"),
    "HuggingFace Token": ("Allows downloading private models and datasets, and if the token has write access, pushing or deleting models under the user's account.", "Private model/dataset access", "https://huggingface.co/settings/tokens"),
    "Replicate API Token": ("Allows running models on Replicate billed to the account owner, and access to any private models the account owns.", "API usage and billing abuse", "https://replicate.com/account/api-tokens"),
    "Telegram Bot Token": ("Grants full control of the Telegram bot, including reading messages sent to it, sending messages to any chat it is in, and changing its profile.", "Bot account takeover", "https://core.telegram.org/bots#botfather"),
    "Discord Bot Token": ("Grants full control of the Discord bot account, including reading messages in every server it has joined and sending messages with its permissions.", "Bot account takeover", "https://discord.com/developers/applications"),
    "Discord Webhook": ("Allows anyone with the URL to post arbitrary messages, embeds, or files into the configured channel.", "Channel spam and phishing", "https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks"),
    "NPM Access Token": ("Allows publishing new versions of any package the token has access to, a common supply-chain attack vector affecting every downstream consumer.", "Package registry supply-chain compromise", "https://www.npmjs.com/settings/~/tokens"),
    "PyPI API Token": ("Allows publishing new releases to PyPI for the scoped project(s), a supply-chain risk for every downstream consumer of the package.", "Package registry supply-chain compromise", "https://pypi.org/manage/account/token/"),
    "Shopify Access Token": ("Grants API access to the store's admin functions per the app's scopes, potentially including orders, customer data, and payment information.", "E-commerce store and customer data compromise", "https://admin.shopify.com/store/_/settings/apps/development"),
    "Shopify Shared Secret": ("Used to verify webhook signatures and OAuth callbacks; an attacker with this secret can forge requests that the store will treat as authentic.", "E-commerce store and customer data compromise", "https://admin.shopify.com/store/_/settings/apps/development"),
    "DigitalOcean Token": ("Allows full control of the DigitalOcean account via the API, including creating or destroying droplets, reading backups, and managing DNS and billing.", "Full cloud account compromise", "https://cloud.digitalocean.com/account/api/tokens"),
    "Dropbox Token": ("Grants access to the files and folders the token's scopes allow, potentially including the entire Dropbox account's contents.", "Cloud storage data exposure", "https://www.dropbox.com/developers/apps"),
    "Notion API Key": ("Allows reading and writing every page and database the integration has been shared with, which can include internal documentation and wikis.", "Internal documentation exposure", "https://www.notion.so/my-integrations"),
    "Linear API Key": ("Grants API access to the Linear workspace's issues, projects, and roadmaps, exposing internal product and engineering plans.", "Internal project management exposure", "https://linear.app/settings/api"),
    "Terraform Cloud Token": ("Allows triggering runs, reading state files (which often contain plaintext secrets and resource IDs), and modifying infrastructure configuration.", "Infrastructure-as-code and state file compromise", "https://app.terraform.io/app/settings/tokens"),
    "Vault Service Token": ("Allows reading every secret the token's policies grant access to, often a master key to an organization's other credentials.", "Secrets manager compromise (cascading)", "https://developer.hashicorp.com/vault/docs/commands/token/revoke"),
    "New Relic API Key": ("Allows querying application performance data, logs, and infrastructure metrics, which can leak internal hostnames, error details, and traffic patterns.", "Observability data exposure", "https://one.newrelic.com/api-keys"),
    "New Relic License Key": ("Allows ingesting data into the account's New Relic instance and, depending on key type, querying existing telemetry data.", "Observability data exposure", "https://one.newrelic.com/api-keys"),
    "Mapbox Token": ("If a secret-scoped token, allows managing styles, datasets, and uploads, and can be used to incur usage charges against the account.", "API usage and billing abuse", "https://account.mapbox.com/access-tokens/"),
    "Square Access Token": ("Grants access to the Square account's payments, orders, and customer data per the token's scopes.", "Payment processing and customer financial data", "https://developer.squareup.com/apps"),
    "Square OAuth Token": ("Acts on behalf of the merchant who authorized the app, with access to payments, orders, and customer records.", "Payment processing and customer financial data", "https://developer.squareup.com/apps"),
    "Twitter Bearer Token": ("Allows making API calls against the X (Twitter) API on behalf of the app, which can be used for spam, scraping, or rate-limit exhaustion.", "API usage abuse", "https://developer.twitter.com/en/portal/dashboard"),
    "Mailchimp API Key": ("Grants access to the account's audiences (mailing lists), campaigns, and subscriber data, and can be used to send email as the account.", "Email sending abuse and contact list exposure", "https://admin.mailchimp.com/account/api/"),

    "Supabase Service Key": ("Bypasses row-level security and grants full read/write access to the entire Postgres database behind the Supabase project.", "Full database compromise (bypasses access control)", "https://supabase.com/dashboard/project/_/settings/api"),
    "Supabase API Key": ("Acts as the project's anon or service key depending on type, potentially allowing access to tables exposed via the project's API.", "Database and API access", "https://supabase.com/dashboard/project/_/settings/api"),
    "Vercel Token": ("Allows managing deployments, environment variables (which often contain other secrets), and domains for every project the account owns.", "Deployment pipeline and secrets compromise", "https://vercel.com/account/tokens"),
    "Cloudflare Global Key": ("Grants full account-level access to every Cloudflare service: DNS records, SSL/TLS settings, Workers, firewall rules, and billing.", "Full Cloudflare account compromise", "https://dash.cloudflare.com/profile/api-tokens"),
    "Datadog API Key": ("Allows submitting metrics, logs, and traces to the account, and can be used to exhaust ingestion quotas or pollute dashboards.", "Observability data exposure and quota abuse", "https://app.datadoghq.com/organization-settings/api-keys"),
    "Datadog App Key": ("Combined with an API key, allows full read/write access to the Datadog account's dashboards, monitors, and configuration via the API.", "Observability data exposure", "https://app.datadoghq.com/organization-settings/application-keys"),
    "PlanetScale Token": ("Allows API access to the database's branches, deploy requests, and connection credentials per the token's scopes.", "Database access and schema control", "https://app.planetscale.com/"),
    "PlanetScale OAuth Token": ("Acts on behalf of the authorizing user, with access to their organizations, databases, and branches.", "Database access and schema control", "https://app.planetscale.com/"),
    "PlanetScale Password": ("Direct database credential; allows connecting to the database branch and reading/writing all data it contains.", "Full database compromise", "https://app.planetscale.com/"),
    "Postman API Key": ("Allows access to the user's Postman workspaces, collections, and environments, which often contain other API keys and credentials.", "Credential exposure (collections often store other secrets)", "https://web.postman.co/settings/me/api-keys"),
    "Grafana Service Token": ("Allows API access to the Grafana instance per the token's role, including reading dashboards and, for admin tokens, managing data sources and users.", "Observability platform compromise", "https://grafana.com/profile/api-keys"),
    "Grafana Cloud Token": ("Allows pushing or querying metrics, logs, or traces in the Grafana Cloud stack, and may expose infrastructure topology through dashboards.", "Observability data exposure", "https://grafana.com/profile/api-keys"),
    "Sentry Auth Token": ("Allows reading error events (which often contain stack traces, user data, and environment variables) and managing projects per the token's scopes.", "Error monitoring data exposure", "https://sentry.io/settings/account/api/auth-tokens/"),
    "Sentry DSN": ("Primarily used to submit events to a Sentry project; if it includes a private key, it could allow ingesting forged error events.", "Error monitoring data pollution", "https://sentry.io/settings/account/api/auth-tokens/"),
    "Doppler Token": ("Grants access to every secret stored in the Doppler project/config the token is scoped to, often the central store for an organization's other credentials.", "Secrets manager compromise (cascading)", "https://dashboard.doppler.com/workplace/access/tokens"),
    "Age Secret Key": ("Allows decrypting any file that was encrypted to the matching public key, exposing whatever secrets or backups were protected by it.", "Encrypted data decryption", "https://github.com/FiloSottile/age"),
    "Infisical Token": ("Grants access to every secret stored in the Infisical project/environment the token is scoped to, often the central store for an organization's other credentials.", "Secrets manager compromise (cascading)", "https://infisical.com/docs/documentation/platform/token"),
    "Finicity App Key": ("Allows accessing the Finicity (Mastercard Open Banking) API for the app, including connected bank account and transaction data for end users.", "Banking and financial data exposure", "https://developer.mastercard.com/finicity/"),
    "Flutterwave Secret Key": ("Allows initiating payments, refunds, and transfers, and reading transaction and customer data on the Flutterwave account.", "Payment processing and customer financial data", "https://dashboard.flutterwave.com/settings/apis"),
    "Coinbase Access Token": ("Allows access to the Coinbase account's wallets and transaction history, and depending on scopes, the ability to send funds.", "Cryptocurrency funds and account compromise", "https://www.coinbase.com/settings/api"),
    "Twitch Client Secret": ("Allows the application to obtain new OAuth tokens on behalf of users who have authorized it, and to manage the application's registration.", "OAuth application compromise", "https://dev.twitch.tv/console/apps"),

    "Generic API Key": ("An unidentified API key. If valid, it likely grants programmatic access to whatever service it belongs to, scoped however that service's keys are normally scoped.", "Unknown service API access", _DOCS),
    "Generic Secret": ("An unidentified secret or client secret. If valid, it can typically be used together with a client ID to authenticate as an application.", "Unknown application credential exposure", _DOCS),
    "Generic Password": ("A hardcoded password. If reused, it may grant access to the associated account, database, or admin panel, and possibly to other systems if the password is reused.", "Account or system access (and credential reuse risk)", _DOCS),
    "Bearer Token": ("An unidentified bearer token. If still valid, it grants whatever access the issuing service associates with that token, usually without any additional credential.", "Unknown API session access", _DOCS),
    "JWT Token": ("JWTs encode claims (often including user ID, role, and expiry) that a receiving service trusts; an attacker can replay it to impersonate the subject until it expires.", "Session/identity impersonation until expiry", _DOCS),
    "Database URL": ("Contains a username and password for a database, message broker, or search cluster, granting whatever access that account has, often full read/write.", "Database or message broker compromise", _DOCS),
    "Basic Auth in URL": ("Embeds a username and password directly in a URL, granting whatever access that account has on the target host or service.", "Account access on the target host", _DOCS),
    "Stripe Test Key": ("Test keys cannot move real money, but they can reveal the structure of the integration and, if mistaken for a live key, indicate the account exists.", "Low (test mode only)", "https://dashboard.stripe.com/test/apikeys"),
    "Firebase Config": ("The Firebase server key allows sending push notifications to all of the app's registered devices via FCM, which can be abused for spam or phishing.", "Push notification abuse", "https://console.firebase.google.com/"),
    "Google API Key": ("Depending on which Google APIs are enabled for this key, an attacker may be able to use Maps, Places, or other billed APIs against the project's quota.", "API usage and billing abuse", "https://console.cloud.google.com/apis/credentials"),
    "Slack App Token": ("App-level tokens are used to connect via Socket Mode and can be used to establish a WebSocket connection as the app across the workspaces it is installed in.", "Workspace communication compromise", "https://api.slack.com/apps"),
    "Private Key File Path": ("This itself is just a file path, but it points to where a private key is stored on disk, useful information for an attacker who already has some access.", "Information disclosure (key location)", _DOCS),

    "MongoDB Connection String": ("Contains a username and password for a MongoDB instance, granting full read/write access to every database and collection that user can reach.", "Full database compromise", "https://www.mongodb.com/docs/manual/tutorial/change-own-password-and-custom-data/"),
    "PostgreSQL Connection String": ("Contains a username and password for a PostgreSQL database, granting full read/write access to every schema that user can reach.", "Full database compromise", "https://www.postgresql.org/docs/current/sql-alterrole.html"),
    "MySQL Connection String": ("Contains a username and password for a MySQL/MariaDB database, granting full read/write access to every database that user can reach.", "Full database compromise", "https://dev.mysql.com/doc/refman/8.0/en/set-password.html"),
    "Redis Connection String": ("Contains a password for a Redis instance, granting access to every key in the database, including cached sessions, queues, and rate-limit counters.", "Cache/queue data compromise", "https://redis.io/docs/management/security/acl/"),
    "PEM Certificate": ("A public certificate by itself is not secret, but its presence often indicates a matching private key is stored nearby, and its subject/SAN fields can reveal internal hostnames.", "Information disclosure (low on its own)", _DOCS),
    "Docker Config Auth": ("The base64-encoded auth field decodes to a username:password (or token) for a container registry, granting pull/push access to private images.", "Container registry compromise (supply chain)", "https://docs.docker.com/engine/reference/commandline/login/"),
    "Kubernetes Service Account Token": ("Grants whatever RBAC permissions the service account has within the cluster, which can range from read-only pod access to full cluster admin.", "Cluster compromise (scope depends on RBAC)", "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume"),
    "Firebase Admin SDK Key": ("The Admin SDK service account bypasses Firebase security rules entirely, granting full read/write access to Firestore, Realtime Database, Authentication, and Storage.", "Full Firebase project compromise (bypasses security rules)", "https://console.firebase.google.com/"),
    "Expo Access Token": ("Grants API access to the Expo/EAS account, including building and submitting app updates, which could be used to push malicious app updates.", "Mobile app build and update pipeline compromise", "https://expo.dev/settings/access-tokens"),
    "Fly.io API Token": ("Grants API access to manage the Fly.io organization's apps, including deploying new code, reading secrets set via flyctl, and accessing machines.", "Deployment pipeline and secrets compromise", "https://fly.io/user/personal_access_tokens"),
    "WireGuard Private Key": ("Allows establishing a VPN tunnel as this peer, granting whatever network access the WireGuard configuration permits, often a path into an internal network.", "VPN/internal network access", "https://www.wireguard.com/quickstart/"),
    "PagerDuty API Key": ("Allows reading and modifying incidents, schedules, and escalation policies, and could be used to silence alerts or access on-call contact information.", "Incident response and on-call data exposure", "https://support.pagerduty.com/docs/api-access-keys"),
    "Elastic Cloud API Key": ("Grants access to the Elasticsearch cluster per the key's privileges, potentially including reading or deleting indices containing logs and application data.", "Search/log cluster data compromise", "https://www.elastic.co/guide/en/cloud/current/ec-api-keys.html"),

    "Azure AD Client Secret": ("Allows the application registration to authenticate as itself and obtain access tokens for whatever Microsoft Graph or API permissions it has been granted, including Azure AD directory data.", "Azure AD application and directory compromise", "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"),
    "Cohere API Key": ("Allows making Cohere API calls billed to the account owner, potentially racking up large usage charges.", "API usage and billing abuse", "https://dashboard.cohere.com/api-keys"),
    "Groq API Key": ("Allows making Groq inference API calls billed to the account owner, potentially exhausting rate limits or quotas.", "API usage and billing abuse", "https://console.groq.com/keys"),
    "Pinecone API Key": ("Grants access to the Pinecone account's vector indexes, allowing reading, writing, or deleting embedded data, which may include sensitive document content.", "Vector database data exposure", "https://app.pinecone.io/"),
    "Atlassian API Token": ("Grants API access to Jira and Confluence as the associated user, including private issues, project data, and wiki content.", "Internal issue tracker and wiki exposure", "https://id.atlassian.com/manage-profile/security/api-tokens"),
    "PayPal Client Secret": ("Combined with the client ID, allows obtaining OAuth access tokens to act as the application, including initiating payments and accessing transaction data.", "Payment processing and customer financial data", "https://developer.paypal.com/dashboard/applications"),
    "Razorpay Key ID": ("Identifies the Razorpay account; combined with the key secret it allows creating orders, capturing payments, and issuing refunds.", "Payment processing and customer financial data", "https://dashboard.razorpay.com/app/keys"),
    "Postmark Server Token": ("Allows sending email through the Postmark server and reading message activity/bounce data, commonly abused for phishing.", "Email sending abuse and phishing", "https://account.postmarkapp.com/servers"),
    "Railway API Token": ("Grants API access to the Railway project, including environment variables (which often contain other secrets), deployments, and the ability to redeploy services.", "Deployment pipeline and secrets compromise", "https://railway.app/account/tokens"),
    "Cloudflare API Token": ("Grants access scoped to whatever permissions the token was created with, which can range from read-only DNS access to full zone or account management.", "Cloudflare zone/account compromise (scope-dependent)", "https://dash.cloudflare.com/profile/api-tokens"),

    "High Entropy String": ("A high-entropy string was detected that does not match any known credential format. It may be a secret, a hash, an encoded value, or random test data.", "Unknown - manual review recommended", _DOCS),
}

_API = "API usage and billing abuse"
_SRC = "Source code and CI/CD compromise"
_PAY = "Payment processing and customer financial data"
_MAIL = "Email sending abuse and phishing"
_DEPLOY = "Deployment pipeline and secrets compromise"
_DB = "Full database compromise"
_REG = "Package registry supply-chain compromise"
_CLOUD = "Full cloud account compromise"


def _ai(service: str, url: str) -> tuple[str, str, str]:
    return (f"Allows calling the {service} API billed to the key owner, and reading any files, fine-tunes or "
            "usage data the account exposes.", _API, url)


def _iac(what: str) -> tuple[str, str, str]:
    return (f"A literal credential was found in {what}. Anyone with read access to the file, the image or its "
            "history can reuse it. Move it to a secret store and inject it at runtime.",
            "Depends on the credential; treat as exposed", _DOCS)


_DATA.update({
    "GitHub Fine-Grained Token": ("Grants the repository and organization permissions selected when the token was created, often including contents write and Actions secrets.", _SRC, "https://github.com/settings/tokens?type=beta"),
    "GitLab Runner Token": ("Allows registering a rogue runner that receives CI jobs, including their variables and source checkouts.", "CI/CD pipeline compromise", "https://docs.gitlab.com/ee/ci/runners/configure_runners.html#reset-the-runner-authentication-token"),
    "GitLab Deploy Token": ("Allows cloning the project and pulling or pushing its container and package registries.", _SRC, "https://docs.gitlab.com/ee/user/project/deploy_tokens/"),
    "Bitbucket App Password": ("Acts as the user over the Bitbucket API with the app password's scopes, including private repositories and pipelines.", _SRC, "https://bitbucket.org/account/settings/app-passwords/"),
    "CircleCI Personal Token": ("Allows triggering pipelines and reading project environment variables, which usually hold deploy credentials.", "CI/CD pipeline compromise", "https://app.circleci.com/settings/user/tokens"),
    "Buildkite Agent Token": ("Allows API access to Buildkite pipelines and builds, including logs and artifacts.", "CI/CD pipeline compromise", "https://buildkite.com/user/api-access-tokens"),
    "SonarQube Token": ("Allows reading analysis results and source snippets, and with admin scope, changing quality gates.", "Code analysis data exposure", "https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/"),
    "Stripe Restricted Key": ("Grants the specific Stripe permissions chosen for this key, which can include charges, refunds and customer data.", _PAY, "https://dashboard.stripe.com/apikeys"),
    "Stripe Webhook Secret": ("Lets an attacker forge webhook events your backend will trust, such as fake successful payments.", "Payment event forgery", "https://dashboard.stripe.com/webhooks"),
    "Braintree Access Token": ("Allows creating transactions and reading customer payment data on the production Braintree merchant account.", _PAY, "https://developer.paypal.com/braintree/articles/control-panel/important-gateway-credentials"),
    "Shippo API Token": ("Allows buying shipping labels billed to the account and reading shipment and address data.", "Billing abuse and customer address exposure", "https://apps.goshippo.com/settings/api"),
    "Credit Card Number": ("A Luhn-valid card number was found. If real, it is cardholder data covered by PCI DSS and may be usable for fraud.", "Cardholder data exposure (PCI scope)", "https://www.pcisecuritystandards.org/"),
    "Twilio API Key": ("Combined with its secret, allows sending SMS and calls billed to the account and reading message logs.", "Communications abuse and billing fraud", "https://console.twilio.com/us1/account/keys-credentials/api-keys"),
    "Slack Config Token": ("Allows creating and modifying Slack apps in the workspace via the App Manifest API.", "Workspace app configuration compromise", "https://api.slack.com/authentication/config-tokens"),
    "Slack Legacy Token": ("Legacy tokens carry the full permissions of the user who created them across the workspace.", "User account and workspace compromise", "https://api.slack.com/legacy/custom-integrations/legacy-tokens"),
    "Resend API Key": ("Allows sending email from your verified domains and reading delivery logs.", _MAIL, "https://resend.com/api-keys"),
    "Brevo API Key": ("Allows sending email and SMS campaigns and exporting contact lists.", _MAIL, "https://app.brevo.com/settings/keys/api"),
    "MailerSend API Token": ("Allows sending email from your domains and reading activity data.", _MAIL, "https://app.mailersend.com/api-tokens"),
    "Microsoft Teams Webhook": ("Anyone with the URL can post messages into the Teams channel, which is useful for internal phishing.", "Channel spam and phishing", "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook"),
    "Telnyx API Key": ("Allows placing calls and sending messages billed to the account, and managing numbers.", "Communications abuse and billing fraud", "https://portal.telnyx.com/#/app/api-keys"),
    "Mistral API Key": _ai("Mistral", "https://console.mistral.ai/api-keys/"),
    "Together AI API Key": _ai("Together AI", "https://api.together.xyz/settings/api-keys"),
    "Fireworks API Key": _ai("Fireworks AI", "https://fireworks.ai/account/api-keys"),
    "Perplexity API Key": _ai("Perplexity", "https://www.perplexity.ai/settings/api"),
    "DeepSeek API Key": _ai("DeepSeek", "https://platform.deepseek.com/api_keys"),
    "xAI API Key": _ai("xAI", "https://console.x.ai/"),
    "Weights & Biases API Key": ("Allows reading and writing experiment runs, artifacts and model files in every W&B project the user can reach.", "ML experiment and model data exposure", "https://wandb.ai/authorize"),
    "Comet API Key": ("Allows reading and writing experiments, models and assets in the Comet workspace.", "ML experiment and model data exposure", "https://www.comet.com/account-settings/apiKeys"),
    "Kaggle API Key": ("Allows downloading private datasets, publishing kernels and datasets as the user.", "Account and private dataset access", "https://www.kaggle.com/settings/account"),
    "Modal Token Secret": ("Combined with the token ID, allows deploying and running code on Modal billed to the workspace.", "Compute billing abuse and code execution", "https://modal.com/settings/tokens"),
    "Cerebras API Key": _ai("Cerebras", "https://cloud.cerebras.ai/"),
    "OpenRouter API Key": _ai("OpenRouter", "https://openrouter.ai/settings/keys"),
    "LangSmith API Key": ("Allows reading traces, which often contain full prompts, completions and user data.", "LLM trace and prompt data exposure", "https://smith.langchain.com/settings"),
    "Voyage AI API Key": _ai("Voyage AI", "https://dash.voyageai.com/api-keys"),
    "HuggingFace Org Token": ("Grants access to the organization's private models, datasets and Spaces.", "Private model/dataset access", "https://huggingface.co/settings/tokens"),
    "ElevenLabs API Key": _ai("ElevenLabs", "https://elevenlabs.io/app/settings/api-keys"),
    "AssemblyAI API Key": _ai("AssemblyAI", "https://www.assemblyai.com/app/account"),
    "Deepgram API Key": _ai("Deepgram", "https://console.deepgram.com/"),
    "Azure OpenAI Key": _ai("Azure OpenAI", "https://portal.azure.com/#view/Microsoft_Azure_ProjectOxford/CognitiveServicesHub/~/OpenAI"),
    "Google OAuth Client Secret": ("Combined with the client ID, lets an attacker impersonate your OAuth app and phish user consent.", "OAuth application impersonation", "https://console.cloud.google.com/apis/credentials"),
    "Google OAuth Access Token": ("A live bearer token for Google APIs with whatever scopes the user granted, valid until it expires (usually 1 hour).", "Account access until expiry", "https://myaccount.google.com/permissions"),
    "Azure SAS Token": ("Grants the storage permissions encoded in the URL (read, write, delete, list) until its expiry time.", "Azure Storage data access", "https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview"),
    "Azure DevOps PAT": ("Acts as the user in Azure DevOps with the token's scopes, including repos, pipelines and artifact feeds.", _SRC, "https://dev.azure.com/_usersSettings/tokens"),
    "Alibaba Cloud Access Key": ("Combined with its secret, allows calling Alibaba Cloud APIs as the RAM identity.", _CLOUD, "https://ram.console.aliyun.com/manage/ak"),
    "Tencent Cloud Secret ID": ("Combined with its SecretKey, allows calling Tencent Cloud APIs as the account or sub-user.", _CLOUD, "https://console.cloud.tencent.com/cam/capi"),
    "Scaleway Access Key": ("Combined with its secret key, allows managing Scaleway resources in the project.", _CLOUD, "https://console.scaleway.com/iam/api-keys"),
    "Yandex Cloud API Key": ("Allows calling Yandex Cloud APIs as the service account the key belongs to.", _CLOUD, "https://console.cloud.yandex.com/"),
    "DigitalOcean OAuth Token": ("Acts on behalf of the user over the DigitalOcean API with the granted scopes.", _CLOUD, "https://cloud.digitalocean.com/account/api/tokens"),
    "Cloudflare Origin CA Key": ("Allows issuing and revoking Origin CA certificates for your zones.", "TLS certificate issuance for your domains", "https://dash.cloudflare.com/profile/api-tokens"),
    "Netlify Access Token": ("Allows deploying sites, reading environment variables and managing DNS for the account.", _DEPLOY, "https://app.netlify.com/user/applications#personal-access-tokens"),
    "Render API Key": ("Allows deploying services and reading their environment variables.", _DEPLOY, "https://dashboard.render.com/u/settings#api-keys"),
    "Heroku API Key": ("Allows deploying apps, reading config vars (which hold other secrets) and running one-off dynos.", _DEPLOY, "https://dashboard.heroku.com/account/applications"),
    "Heroku Legacy API Key": ("Allows deploying apps, reading config vars (which hold other secrets) and running one-off dynos.", _DEPLOY, "https://dashboard.heroku.com/account"),
    "Deno Deploy Token": ("Allows deploying code to Deno Deploy projects and reading their environment variables.", _DEPLOY, "https://dash.deno.com/account#access-tokens"),
    "Vault Batch Token": ("Allows reading every secret the token's policies grant until it expires.", "Secrets manager compromise (cascading)", "https://developer.hashicorp.com/vault/docs/concepts/tokens#batch-tokens"),
    "Pulumi Access Token": ("Allows reading stack state (often containing secrets) and running updates against your infrastructure.", "Infrastructure-as-code and state file compromise", "https://app.pulumi.com/account/tokens"),
    "Tailscale Key": ("Auth keys add devices to your tailnet; API keys manage it. Either is a path into your private network.", "VPN/internal network access", "https://login.tailscale.com/admin/settings/keys"),
    "ngrok Authtoken": ("Allows opening tunnels on your ngrok account, which can be used to host phishing pages under your domains.", "Tunnel abuse under your account", "https://dashboard.ngrok.com/get-started/your-authtoken"),
    "Docker Hub Token": ("Allows pulling private images and, with write scope, pushing malicious image tags.", "Container registry compromise (supply chain)", "https://app.docker.com/settings/personal-access-tokens"),
    "1Password Service Account Token": ("Allows reading every item in the vaults the service account has access to.", "Secrets manager compromise (cascading)", "https://developer.1password.com/docs/service-accounts/manage-service-accounts/"),
    "Snowflake Connection String": ("Contains a username and password for a Snowflake account, giving that user's access to warehouses and data.", _DB, "https://docs.snowflake.com/en/user-guide/admin-user-management"),
    "Snowflake Password": ("Allows logging in to Snowflake as the user, with their role's access to data and compute.", _DB, "https://docs.snowflake.com/en/user-guide/admin-user-management"),
    "Databricks Token": ("Allows running jobs and notebooks and reading data in the Databricks workspace as the user.", "Data platform compromise", "https://docs.databricks.com/en/dev-tools/auth/pat.html"),
    "Neon API Key": ("Allows managing Neon projects, branches and roles, including resetting database passwords.", "Database access and schema control", "https://console.neon.tech/app/settings/api-keys"),
    "Upstash Redis Token": ("Allows reading and writing every key in the Upstash database over its REST API.", "Cache/queue data compromise", "https://console.upstash.com/"),
    "Turso Auth Token": ("Allows querying and modifying the Turso/libSQL database the token is scoped to.", _DB, "https://docs.turso.tech/cli/db/tokens/invalidate"),
    "Airtable Personal Access Token": ("Allows reading and writing records in the bases the token is scoped to.", "Business data exposure", "https://airtable.com/create/tokens"),
    "Algolia Admin Key": ("Admin keys can read, modify and delete every index and rotate other API keys.", "Search index compromise", "https://dashboard.algolia.com/account/api-keys"),
    "Okta API Token": ("Acts as the admin who created it, able to manage users, groups and applications in the Okta org.", "Identity provider compromise", "https://help.okta.com/en-us/content/topics/security/api.htm"),
    "Auth0 Client Secret": ("Lets an attacker authenticate as your Auth0 application and, for M2M apps, call the Management API.", "Identity provider compromise", "https://manage.auth0.com/"),
    "Clerk Secret Key": ("Allows managing users and sessions in your Clerk instance from the backend API.", "Identity provider compromise", "https://dashboard.clerk.com/last-active?path=api-keys"),
    "RubyGems API Key": ("Allows publishing new versions of gems the account owns.", _REG, "https://rubygems.org/profile/api_keys"),
    "NuGet API Key": ("Allows pushing and unlisting packages the key is scoped to.", _REG, "https://www.nuget.org/account/apikeys"),
    "Clojars Deploy Token": ("Allows deploying artifacts to groups the account controls.", _REG, "https://clojars.org/tokens"),
    "JFrog API Key": ("Allows pulling and pushing artifacts in Artifactory repositories the user can access.", _REG, "https://jfrog.com/help/r/jfrog-platform-administration-documentation/access-tokens"),
    "npmrc Auth Token": ("A registry auth token committed in .npmrc lets anyone publish or install private packages as you.", _REG, "https://www.npmjs.com/settings/~/tokens"),
    "pypirc Password": ("A password or token in .pypirc allows uploading releases to PyPI as you.", _REG, "https://pypi.org/manage/account/token/"),
    "netrc Password": (".netrc credentials are sent automatically by curl, git and others to the listed host.", "Account access on the target host", _DOCS),
    "Shopify Custom App Token": ("Grants the store admin API scopes configured for the custom or partner app.", "E-commerce store and customer data compromise", "https://admin.shopify.com/store/_/settings/apps/development"),
    "Figma Personal Token": ("Allows reading every file the user can view, including unreleased designs.", "Design file exposure", "https://www.figma.com/developers/api#access-tokens"),
    "HubSpot Private App Token": ("Grants the CRM scopes configured on the private app, often including all contacts and deals.", "CRM and customer data exposure", "https://app.hubspot.com/private-apps/"),
    "Typeform Token": ("Allows reading form responses, which frequently contain personal data.", "Form response data exposure", "https://admin.typeform.com/user/tokens"),
    "Contentful Token": ("Allows reading and publishing content in every space the user can manage.", "Content defacement", "https://app.contentful.com/account/profile/cma_tokens"),
    "ReadMe API Key": ("Allows editing your public API documentation and reading API logs.", "Documentation defacement and log exposure", "https://dash.readme.com/"),
    "Prefect API Key": ("Allows running and modifying flows and reading blocks, which store other credentials.", "Workflow orchestration compromise", "https://app.prefect.cloud/my/api-keys"),
    "Adafruit IO Key": ("Allows reading and writing feeds, which may control physical devices.", "IoT device and data control", "https://io.adafruit.com/"),
    "Mapbox Secret Token": ("Secret-scoped Mapbox tokens can manage styles, datasets and uploads and incur charges.", _API, "https://account.mapbox.com/access-tokens/"),
    "Facebook Access Token": ("Allows calling the Graph API as the user or page with the token's permissions, such as posting or reading messages.", "Social account and page compromise", "https://developers.facebook.com/tools/debug/accesstoken/"),
    "Dynatrace API Token": ("Allows reading monitoring data and, depending on scopes, changing configuration or ingesting data.", "Observability data exposure", "https://docs.dynatrace.com/docs/manage/access-control/access-tokens"),
    "PostHog Personal API Key": ("Allows querying all analytics events, which often include user identifiers and properties.", "Product analytics and user data exposure", "https://us.posthog.com/settings/user-api-keys"),
    "LaunchDarkly Access Token": ("Allows changing feature flags in production, which can switch features on or off for every user.", "Production behavior control", "https://app.launchdarkly.com/settings/authorization"),
    "Snyk API Token": ("Allows reading vulnerability reports and project details for your organization.", "Security finding exposure", "https://app.snyk.io/account"),
    "Dockerfile Secret": _iac("a Dockerfile ENV or ARG instruction (it ends up in every image layer and in `docker history`)"),
    "Env File Secret": _iac("a .env file"),
    "Terraform State Secret": ("Terraform state stores resource attributes in plaintext, including generated passwords and keys.", "Infrastructure-as-code and state file compromise", "https://developer.hashicorp.com/terraform/language/state/sensitive-data"),
    "Terraform Variable Secret": _iac("a .tfvars file"),
    "Kubernetes Secret Data": ("Kubernetes Secret values are base64, not encrypted. Anyone with the manifest can decode them.", "Depends on the credential; treat as exposed", "https://kubernetes.io/docs/concepts/configuration/secret/"),
    "GitHub Actions Hardcoded Secret": _iac("a GitHub Actions workflow (use `${{ secrets.NAME }}` instead)"),
    "Compose File Secret": _iac("a docker-compose environment block"),
    "Htpasswd Hash": ("Password hashes can be cracked offline; weak or reused passwords will fall quickly.", "Account access after offline cracking", _DOCS),
    "Ethereum Private Key": ("Full control of the wallet: anyone with this key can transfer all of its funds irreversibly.", "Cryptocurrency funds theft", "https://ethereum.org/en/security/"),
})

_DEFAULT = Remediation(
    "An attacker could use this credential to access the associated service or system.",
    "Unknown - review the matched line to determine which system this credential belongs to.",
    _DOCS,
)


def get_remediation(secret_type: str) -> Remediation:
    """Look up the consequence, blast radius, and rotation URL for a secret type.

    Falls back to a generic entry for custom or unrecognized pattern names
    (e.g. user-defined patterns from .leakscan.yaml).
    """
    data = _DATA.get(secret_type)
    if data is None:
        return _DEFAULT
    return Remediation(*data)

"""Secret-scanner fixture: provider-specific credentials hard-coded in Python.

All values are randomly generated and structurally match the provider format only.
They are NOT valid credentials.
"""

# tg-expect: SECRET-010 | critical | aws-access-key-id | AWS access key ID
AWS_ACCESS_KEY_ID = "AKIAGNGVBZSI4KCDHJMQ"
# tg-expect: SECRET-011 | critical | aws-secret-access-key | AWS secret access key
AWS_SECRET_ACCESS_KEY = "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"

# tg-expect: SECRET-012 | critical | github-pat | GitHub classic personal access token
GITHUB_TOKEN = "ghp_QdhJbYngmRZ4Xxdl7C9LoQNX3XKrJPBEziMk"
# tg-expect: SECRET-013 | critical | github-fine-grained-pat | GitHub fine-grained personal access token
GITHUB_FINE_GRAINED_TOKEN = "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"
# tg-expect: SECRET-014 | critical | gitlab-pat | GitLab personal access token
GITLAB_TOKEN = "glpat-uYw62zFjq0EzDvEV5sI1"

# tg-expect: SECRET-015 | high | slack-bot-token | Slack bot token
SLACK_BOT_TOKEN = "xoxb-679832777590-6164029343833-LUEkakqchQqTYy3QILTfUoea"
# tg-expect: SECRET-016 | medium | slack-webhook-url | Slack incoming webhook URL
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

# tg-expect: SECRET-017 | critical | stripe-live-secret-key | Stripe live secret key
STRIPE_SECRET_KEY = "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"
# tg-expect: SECRET-018 | high | gcp-api-key | Google Cloud API key
GOOGLE_MAPS_API_KEY = "AIza9ErAXtl1iRTA7KyaJmMfCa4O-Zle00EblVp"
# tg-expect: SECRET-019 | high | twilio-api-key | Twilio API key SID
TWILIO_API_KEY = "SK2b221dfe8d70c9012a418d37bf170930"
# tg-expect: SECRET-020 | high | sendgrid-api-key | SendGrid API key
SENDGRID_API_KEY = "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"
# tg-expect: SECRET-021 | high | npm-access-token | npm access token
NPM_TOKEN = "npm_pEIma6ZDPIwop9UgYM3u7JizqGF99KtsqYhO"
# tg-expect: SECRET-022 | critical | openai-api-key | OpenAI project API key
OPENAI_API_KEY = "sk-proj-B-TaWi_d6m7MstidwmDC1dXyT1aLC1X6va3goT6lYKEllCpwNyNcvovIJIgS772fXKeZh1Jk9IWZFiKSEmg-r4zjjlqQNj-a7zJw790TEfv5CUF7VLivKVap"
# tg-expect: SECRET-023 | critical | anthropic-api-key | Anthropic API key
ANTHROPIC_API_KEY = "sk-ant-api03-NICktRa1JtksCz0uO_BggPxL3ktcDQkIrVR7NMTZxgAw5nGGToE8U-r-F92pgFxWnlwQCUtOeXL0fnGY3Ahc146Z8o9lVAA"
# tg-expect: SECRET-024 | critical | hashicorp-vault-token | HashiCorp Vault service token
VAULT_TOKEN = "hvs.Mwm3TNbB1NqqOUH4kSTZe85Q"

# tg-expect: SECRET-025 | high | django-secret-key | Django SECRET_KEY
SECRET_KEY = "django-insecure-7(up18(ud6(n55+f+c+3niow^=nbqgbh_fwunt(cri4+f7ho33"
# tg-expect: SECRET-026 | high | jwt | Signed JSON Web Token embedded in source
SERVICE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0aWdlcmdhdGUtZml4dHVyZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc1Nzg5NDQwMH0.l1WpO_yl0Gu4XG8x2cIjIyXhcrceIsJIOOVSnU-VN3R"
# tg-expect: SECRET-027 | critical | database-connection-string | PostgreSQL URI with embedded password
DATABASE_URL = "postgresql://tg_admin:Pr0d-zpL6aPjyCi54iu!@db.internal.example.com:5432/payments"
# tg-expect: SECRET-028 | critical | azure-storage-account-key | Azure Storage connection string with AccountKey
AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=tgfixturestore;AccountKey=cbK5KtYbTh69Q4tpG6ly1N58DD0IHJ7x8BXAysBDMcv9KlZlU6OvkWQIoTEao649D8HUP4keXhEksZcbiCzwPA==;EndpointSuffix=core.windows.net"
# tg-expect: SECRET-029 | high | basic-auth-url | Credentials embedded in URL userinfo
METRICS_ENDPOINT = "https://metrics_user:d40b30b61deb315daa10@metrics.example.com/push"
# tg-expect: SECRET-030 | medium | generic-password | High-entropy password assigned to password variable
smtp_password = "d40b30b61deb315daa1081979dcd11a409882aa773a0726a"

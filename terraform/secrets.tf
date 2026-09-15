# Fake static credential used only to exercise secret-scanning rules.
locals {
  # tg-expect: SECRET-070 | critical | aws-access-key-id | AWS documented example access key (many scanners allow-list *EXAMPLE)
  fixture_access_key = "AKIAIOSFODNN7EXAMPLE"
  # tg-expect: SECRET-071 | low | generic-secret | Low-entropy placeholder secret key in Terraform local
  fixture_secret_key = "not-a-real-aws-secret-for-scanner-testing"
}

# Deliberately insecure IaC fixture for scanner validation. Do not apply.
resource "aws_s3_bucket" "public_fixture" {
  bucket = "tigergate-test-python-public-fixture"
}

resource "aws_s3_bucket_public_access_block" "public_fixture" {
  bucket = aws_s3_bucket.public_fixture.id
  # tg-expect: IAC-001 | high | s3-public-access | S3 public access block: block_public_acls disabled
  block_public_acls = false
  # tg-expect: IAC-002 | high | s3-public-access | S3 public access block: block_public_policy disabled
  block_public_policy = false
  # tg-expect: IAC-003 | high | s3-public-access | S3 public access block: ignore_public_acls disabled
  ignore_public_acls = false
  # tg-expect: IAC-004 | high | s3-public-access | S3 public access block: restrict_public_buckets disabled
  restrict_public_buckets = false
}

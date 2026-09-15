# Deliberately insecure AWS IaC fixture (provider 3.x syntax). Do not apply.

resource "aws_vpc" "fixture" {
  cidr_block = "10.20.0.0/16"
}

resource "aws_security_group" "admin_open" {
  name   = "tg-fixture-admin-open"
  vpc_id = aws_vpc.fixture.id

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # tg-expect: IAC-010 | critical | public-ingress-admin-port | Security group allows SSH (22) from 0.0.0.0/0
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "rdp"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    # tg-expect: IAC-011 | critical | public-ingress-admin-port | Security group allows RDP (3389) from 0.0.0.0/0
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    # tg-expect: IAC-012 | medium | unrestricted-egress | Security group allows unrestricted egress to ::/0
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_db_instance" "payments" {
  identifier        = "tg-fixture-payments"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "tg_admin"
  # tg-expect: SECRET-072 | critical | generic-password | Hard-coded RDS master password
  password = "Pr0d-zpL6aPjyCi54iu!"
  # tg-expect: IAC-013 | critical | public-database | RDS instance publicly accessible
  publicly_accessible = true
  # tg-expect: IAC-014 | high | encryption-at-rest | RDS storage not encrypted
  storage_encrypted = false
  # tg-expect: IAC-015 | medium | backup-disabled | RDS automated backups disabled
  backup_retention_period = 0
  # tg-expect: IAC-016 | low | deletion-protection | RDS deletion protection disabled
  deletion_protection = false
  skip_final_snapshot = true
}

# tg-expect: IAC-017 | high | encryption-at-rest | S3 bucket without server-side encryption configuration
resource "aws_s3_bucket" "reports" {
  bucket = "tg-fixture-reports"
  # tg-expect: IAC-018 | critical | public-storage | S3 bucket ACL public-read-write
  acl = "public-read-write"

  versioning {
    # tg-expect: IAC-019 | medium | versioning-disabled | S3 bucket versioning disabled
    enabled = false
  }
}

resource "aws_s3_bucket_policy" "reports_public" {
  bucket = aws_s3_bucket.reports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      # tg-expect: IAC-020 | critical | public-storage | S3 bucket policy grants access to Principal "*"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.reports.arn}/*"
    }]
  })
}

resource "aws_iam_policy" "god_mode" {
  name = "tg-fixture-god-mode"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      # tg-expect: IAC-021 | critical | iam-wildcard | IAM policy allows Action "*" on Resource "*"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "ci" {
  name = "tg-fixture-ci"
}

resource "aws_iam_user_policy_attachment" "ci_admin" {
  user = aws_iam_user.ci.name
  # tg-expect: IAC-022 | high | iam-admin-to-user | AdministratorAccess attached directly to IAM user
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_instance" "bastion" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.admin_open.id]
  # tg-expect: IAC-023 | medium | public-ip | EC2 instance gets a public IP address
  associate_public_ip_address = true
  # tg-expect: SECRET-073 | high | generic-password | Credential exported in EC2 user_data
  user_data = "export DB_PASSWORD=Pr0d-zpL6aPjyCi54iu!"

  metadata_options {
    http_endpoint = "enabled"
    # tg-expect: IAC-024 | high | imdsv1 | IMDSv1 allowed (http_tokens optional)
    http_tokens = "optional"
  }

  root_block_device {
    # tg-expect: IAC-025 | high | encryption-at-rest | EC2 root volume not encrypted
    encrypted = false
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 50
  # tg-expect: IAC-026 | high | encryption-at-rest | EBS volume not encrypted
  encrypted = false
}

resource "aws_kms_key" "app" {
  description = "tg fixture key"
  # tg-expect: IAC-027 | medium | key-rotation | KMS key rotation disabled
  enable_key_rotation = false
}

resource "aws_cloudtrail" "audit" {
  name           = "tg-fixture-trail"
  s3_bucket_name = aws_s3_bucket.reports.id
  # tg-expect: IAC-028 | medium | audit-logging | CloudTrail log file validation disabled
  enable_log_file_validation = false
  # tg-expect: IAC-029 | medium | audit-logging | CloudTrail not multi-region
  is_multi_region_trail = false
}

resource "aws_lb" "public" {
  name               = "tg-fixture-alb"
  load_balancer_type = "application"
  # tg-expect: IAC-030 | medium | public-load-balancer | Load balancer is internet-facing
  internal = false
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  # tg-expect: IAC-031 | high | encryption-in-transit | Load balancer listener uses plaintext HTTP
  protocol = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener" "legacy_tls" {
  load_balancer_arn = aws_lb.public.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = "arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-0000-0000-000000000000"
  # tg-expect: IAC-032 | high | weak-tls | Load balancer TLS policy allows TLS 1.0
  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}

resource "aws_eks_cluster" "main" {
  name     = "tg-fixture-eks"
  role_arn = "arn:aws:iam::000000000000:role/eks"

  vpc_config {
    subnet_ids             = ["subnet-00000000000000000", "subnet-11111111111111111"]
    endpoint_public_access = true
    # tg-expect: IAC-033 | high | public-control-plane | EKS public API endpoint open to 0.0.0.0/0
    public_access_cidrs = ["0.0.0.0/0"]
  }
}

resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id          = "tg-fixture-sessions"
  replication_group_description = "session cache"
  node_type                     = "cache.t3.micro"
  number_cache_clusters         = 2
  # tg-expect: IAC-034 | high | encryption-at-rest | ElastiCache at-rest encryption disabled
  at_rest_encryption_enabled = false
  # tg-expect: IAC-035 | high | encryption-in-transit | ElastiCache in-transit encryption disabled
  transit_encryption_enabled = false
}

# tg-expect: IAC-036 | medium | encryption-at-rest | SQS queue without KMS encryption
resource "aws_sqs_queue" "jobs" {
  name = "tg-fixture-jobs"
}

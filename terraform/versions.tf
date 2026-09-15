terraform {
  required_providers {
    # Deliberately old provider version for SCA scanner testing.
    aws = {
      source = "hashicorp/aws"
      # tg-expect: SCA-040 | medium | provider-outdated | Terraform AWS provider pinned to 3.0.0 (outdated)
      version = "3.0.0"
    }
  }
}

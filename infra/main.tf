# Falcon lab: deliberately flawed topology. DEDICATED LAB ACCOUNT ONLY.
# Destroy with:  terraform destroy
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "region" { default = "ap-south-1" }
provider "aws" {
  region = var.region
  default_tags { tags = { project = "falcon-lab" } }
}

data "aws_caller_identity" "me" {}
data "aws_vpc" "default" { default = true }
locals { acct = data.aws_caller_identity.me.account_id }

# ---- Attack chain: lowpriv -> deploy -> wildcard-admin ----------------------
resource "aws_iam_role" "lowpriv" {
  name = "falcon-lab-lowpriv"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
      Principal = { AWS = "arn:aws:iam::${local.acct}:root" } }]
  })
}

resource "aws_iam_role" "deploy" {
  name = "falcon-lab-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
      Principal = { AWS = aws_iam_role.lowpriv.arn } }]
  })
}

resource "aws_iam_role" "admin" {
  name = "falcon-lab-wildcard-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
      Principal = { AWS = aws_iam_role.deploy.arn } }]
  })
}

# FLAW 1: lowpriv may assume deploy
resource "aws_iam_role_policy" "lowpriv_can_assume_deploy" {
  name = "assume-deploy"
  role = aws_iam_role.lowpriv.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.deploy.arn }]
  })
}

# FLAW 2: deploy may assume admin (role chaining)
resource "aws_iam_role_policy" "deploy_can_assume_admin" {
  name = "assume-admin"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.admin.arn }]
  })
}

# FLAW 3: wildcard permissions (the high-value target)
resource "aws_iam_role_policy" "admin_wildcard" {
  name = "wildcard-all"
  role = aws_iam_role.admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

# ---- FLAW 4: public bucket (marker file only, no real data) -----------------
resource "aws_s3_bucket" "pub" {
  bucket        = "falcon-lab-public-${local.acct}"
  force_destroy = true
}
resource "aws_s3_bucket_public_access_block" "pub" {
  bucket                  = aws_s3_bucket.pub.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_s3_bucket_policy" "pub" {
  bucket     = aws_s3_bucket.pub.id
  depends_on = [aws_s3_bucket_public_access_block.pub]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject",
      Resource = "${aws_s3_bucket.pub.arn}/*" }]
  })
}
resource "aws_s3_object" "marker" {
  bucket     = aws_s3_bucket.pub.id
  key        = "FALCON-MARKER.txt"
  content    = "FALCON-LAB-MARKER: not real data"
  depends_on = [aws_s3_bucket_policy.pub]
}

# ---- FLAW 5: security group open to the internet (nothing attached to it) ---
resource "aws_security_group" "open" {
  name        = "falcon-lab-open-sg"
  description = "Lab: SSH open to world (no instance attached)"
  vpc_id      = data.aws_vpc.default.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---- Planted benign marker "secret" for the T1552 module (free tier) --------
resource "aws_ssm_parameter" "marker" {
  name  = "/falcon-lab/marker-secret"
  type  = "String"
  value = "FALCON-MARKER-NOT-A-REAL-SECRET"
}

output "account_id" { value = local.acct }

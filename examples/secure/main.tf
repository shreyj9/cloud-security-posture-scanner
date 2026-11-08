resource "aws_s3_bucket" "private_assets" {
  bucket = "example-private-assets"
  acl    = "private"
}

resource "aws_security_group" "app" {
  name = "app-restricted"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_db_instance" "customer_db" {
  identifier          = "customer-db"
  engine              = "postgres"
  publicly_accessible = false
  storage_encrypted   = true
  password            = var.database_password
}

resource "aws_iam_role_policy" "readonly_policy" {
  name = "readonly-policy"
  role = "example-role"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::example-private-assets/*"
  }]
}
EOF
}

resource "aws_instance" "web" {
  ami                         = "ami-1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
}

resource "aws_cloudtrail" "audit" {
  name           = "audit"
  s3_bucket_name = "audit-logs"
  enable_logging = true
}

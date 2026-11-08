resource "aws_s3_bucket" "public_assets" {
  bucket = "example-public-assets"
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name = "admin-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "customer_db" {
  identifier          = "customer-db"
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
  password            = "SuperSecretPassword123!"
}

resource "aws_iam_role_policy" "admin_policy" {
  name = "admin-policy"
  role = "example-role"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF
}

resource "aws_instance" "web" {
  ami                         = "ami-1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}

resource "aws_cloudtrail" "audit" {
  name           = "audit"
  s3_bucket_name = "audit-logs"
  enable_logging = false
}

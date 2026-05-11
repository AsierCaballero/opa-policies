resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket              = aws_s3_bucket.data.id
  block_public_acls   = false
  block_public_policy = false
}

resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "sg-12345"
}

resource "aws_iam_role_policy" "admin" {
  name = "admin-role"
  policy = jsonencode({
    Action = "*"
    Effect = "Allow"
    Resource = "*"
  })
}

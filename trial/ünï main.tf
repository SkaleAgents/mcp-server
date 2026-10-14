resource "aws_s3_bucket" "demo" {
  bucket = "trial-demo"
  acl    = "public-read"
}

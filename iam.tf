# Both hosts get Session Manager and nothing else.
#
# The validator role in particular is deliberately empty beyond SSM: there is
# no S3 bucket it can read, no Secrets Manager entry it can fetch, no KMS
# decrypt it can perform. Keys arrive on that host by a human procedure, once,
# and the cloud control plane is never a path to them. That also means an
# attacker with the instance role cannot reconstruct the key set on a second
# machine, which is the failure that turns a compromise into a slashing.

# Written with jsonencode rather than aws_iam_policy_document on purpose: a
# data source would make the trust policy an API-shaped unknown, and the whole
# module is designed so that everything security-relevant is decidable at plan
# time, with no provider and no credentials.
locals {
  ec2_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "beacon" {
  name               = "${var.name}-beacon"
  assume_role_policy = local.ec2_assume_role_policy
  tags               = local.common_tags
}

resource "aws_iam_role" "validator" {
  name               = "${var.name}-validator"
  assume_role_policy = local.ec2_assume_role_policy
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "beacon_ssm" {
  role       = aws_iam_role.beacon.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "validator_ssm" {
  role       = aws_iam_role.validator.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "beacon" {
  name = "${var.name}-beacon"
  role = aws_iam_role.beacon.name
  tags = local.common_tags
}

resource "aws_iam_instance_profile" "validator" {
  name = "${var.name}-validator"
  role = aws_iam_role.validator.name
  tags = local.common_tags
}

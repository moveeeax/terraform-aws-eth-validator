resource "aws_instance" "beacon" {
  ami                    = var.beacon_ami_id
  instance_type          = var.beacon_instance_type
  subnet_id              = var.beacon_subnet_id
  vpc_security_group_ids = [aws_security_group.beacon.id]
  iam_instance_profile   = aws_iam_instance_profile.beacon.name
  user_data              = local.beacon_user_data

  # No key_name anywhere in this module. Interactive access is Session Manager,
  # which leaves an audit trail and does not require an inbound rule.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size_gb
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
  }

  tags = merge(local.common_tags, {
    Name       = "${var.name}-beacon"
    "eth:role" = "execution+consensus"
  })
}

# Chaindata lives on its own volume so that resizing it, or reattaching it to a
# replacement instance, is not an instance replacement.
resource "aws_ebs_volume" "chaindata" {
  availability_zone = aws_instance.beacon.availability_zone
  size              = var.chaindata_volume_size_gb
  type              = "gp3"
  iops              = var.chaindata_volume_iops
  throughput        = var.chaindata_volume_throughput
  encrypted         = true
  kms_key_id        = var.kms_key_arn

  tags = merge(local.common_tags, { Name = "${var.name}-chaindata" })
}

resource "aws_volume_attachment" "chaindata" {
  device_name = "/dev/xvdf"
  volume_id   = aws_ebs_volume.chaindata.id
  instance_id = aws_instance.beacon.id
}

# There is one of these. Not a count, not an autoscaling group, not a launch
# template with a desired capacity that some other process can nudge.
#
# create_before_destroy is set to false explicitly. It is already the default,
# and it is written down anyway, because the whole safety argument for this
# module rests on the guarantee that a replacement validator host never
# overlaps in time with the one it replaces.
resource "aws_instance" "validator" {
  ami                     = var.validator_ami_id
  instance_type           = var.validator_instance_type
  subnet_id               = var.validator_subnet_id
  vpc_security_group_ids  = [aws_security_group.validator.id]
  iam_instance_profile    = aws_iam_instance_profile.validator.name
  user_data               = local.validator_user_data
  disable_api_termination = var.enable_termination_protection

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size_gb
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
  }

  lifecycle {
    create_before_destroy = false
  }

  tags = merge(local.common_tags, {
    Name       = "${var.name}-validator"
    "eth:role" = "validator"
  })
}

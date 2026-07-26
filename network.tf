# Security groups. The boundary between the two hosts is the point of this
# module, so every rule below is written out one resource at a time rather than
# generated: a reviewer should be able to read the whole exposure of this
# deployment without expanding a for_each.

resource "aws_security_group" "beacon" {
  name        = "${var.name}-beacon"
  description = "Ethereum execution + consensus host for ${var.name}"
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { Name = "${var.name}-beacon" })
}

resource "aws_security_group" "validator" {
  name        = "${var.name}-validator"
  description = "Ethereum validator client and signing keys for ${var.name}"
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { Name = "${var.name}-validator" })
}

# --- Beacon host ingress -----------------------------------------------------
# Peer discovery genuinely needs the open internet. Nothing else here does.

resource "aws_vpc_security_group_ingress_rule" "beacon_el_p2p_tcp" {
  security_group_id = aws_security_group.beacon.id
  description       = "Execution-layer peers"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = var.el_p2p_port
  to_port           = var.el_p2p_port
  tags              = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "beacon_el_p2p_udp" {
  security_group_id = aws_security_group.beacon.id
  description       = "Execution-layer discovery"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "udp"
  from_port         = var.el_p2p_port
  to_port           = var.el_p2p_port
  tags              = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "beacon_cl_p2p_tcp" {
  security_group_id = aws_security_group.beacon.id
  description       = "Consensus-layer peers"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = var.cl_p2p_port
  to_port           = var.cl_p2p_port
  tags              = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "beacon_cl_p2p_udp" {
  security_group_id = aws_security_group.beacon.id
  description       = "Consensus-layer discovery"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "udp"
  from_port         = var.cl_p2p_port
  to_port           = var.cl_p2p_port
  tags              = local.common_tags
}

# The beacon API is the only path from the signing host into the network, and
# it is reachable from exactly one security group. No CIDR, ever: a CIDR here
# is how a second validator instance in the same VPC starts signing.
resource "aws_vpc_security_group_ingress_rule" "beacon_api_from_validator" {
  security_group_id            = aws_security_group.beacon.id
  description                  = "Beacon HTTP API, validator host only"
  referenced_security_group_id = aws_security_group.validator.id
  ip_protocol                  = "tcp"
  from_port                    = var.beacon_api_port
  to_port                      = var.beacon_api_port
  tags                         = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "beacon_metrics" {
  for_each = local.beacon_scrape_rules

  security_group_id = aws_security_group.beacon.id
  description       = "Prometheus scrape: ${each.value.name}"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  tags              = local.common_tags
}

# --- Validator host ingress --------------------------------------------------
# One rule, and only if the caller asked for monitoring. There is no SSH rule
# and no bastion rule: access is Session Manager over the instance's egress.

resource "aws_vpc_security_group_ingress_rule" "validator_metrics" {
  for_each = local.validator_scrape_rules

  security_group_id = aws_security_group.validator.id
  description       = "Prometheus scrape: ${each.value.name}"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  tags              = local.common_tags
}

# --- Egress ------------------------------------------------------------------

resource "aws_vpc_security_group_egress_rule" "beacon_all" {
  security_group_id = aws_security_group.beacon.id
  description       = "Peer discovery reaches arbitrary hosts and ports"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  tags              = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "validator_beacon_api" {
  security_group_id            = aws_security_group.validator.id
  description                  = "Validator client to its beacon node"
  referenced_security_group_id = aws_security_group.beacon.id
  ip_protocol                  = "tcp"
  from_port                    = var.beacon_api_port
  to_port                      = var.beacon_api_port
  tags                         = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "validator_https" {
  security_group_id = aws_security_group.validator.id
  description       = "Session Manager, package repositories"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  tags              = local.common_tags
}

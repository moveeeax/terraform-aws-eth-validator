# A single Holesky validator pair in an existing VPC.
#
# Nothing in this example creates a VPC, a subnet or a NAT gateway: the module
# is meant to drop into networking you already own and can reason about.
#
# Copy terraform.tfvars.example to terraform.tfvars, fill it in, then:
#
#   terraform init
#   terraform plan
#
# `terraform plan` needs AWS credentials. `terraform validate` and the module's
# own test suite do not.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "validator" {
  source = "../.."

  name    = "holesky-01"
  network = "holesky"

  vpc_id              = var.vpc_id
  beacon_subnet_id    = var.beacon_subnet_id
  validator_subnet_id = var.validator_subnet_id

  beacon_ami_id    = var.beacon_ami_id
  validator_ami_id = var.validator_ami_id

  # Version strings are recorded on the host in /etc/eth-validator/versions.env
  # and are what your configuration management installs. Replace them with the
  # versions you have actually pinned and checksum-verified.
  execution_client         = "geth"
  execution_client_version = "REPLACE_WITH_YOUR_PINNED_VERSION"
  consensus_client         = "lighthouse"
  consensus_client_version = "REPLACE_WITH_YOUR_PINNED_VERSION"

  fee_recipient = var.fee_recipient
  graffiti      = "holesky-01"

  # Read this from the beacon node that will serve this validator:
  #   curl -s "$BEACON/eth/v1/beacon/genesis" | jq -r .data.genesis_validators_root
  # The module ships no table of network roots on purpose: a stale constant in
  # a module is a worse failure than a missing one.
  genesis_validators_root = var.genesis_validators_root

  # Only the monitoring subnet may scrape. Never 0.0.0.0/0 — the module
  # rejects that value.
  monitoring_cidr_blocks = var.monitoring_cidr_blocks

  chaindata_volume_size_gb = 1024

  tags = {
    Owner       = "platform"
    Environment = "testnet"
  }
}

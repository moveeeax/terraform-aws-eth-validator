# The validations that stop a caller from configuring their way into a
# slashing. Each run supplies one bad value and expects that variable to fail.

mock_provider "aws" {}

variables {
  name                    = "holesky-01"
  network                 = "holesky"
  vpc_id                  = "vpc-0123456789abcdef0"
  beacon_subnet_id        = "subnet-0123456789abcdef0"
  validator_subnet_id     = "subnet-0abcdef1234567890"
  beacon_ami_id           = "ami-0123456789abcdef0"
  validator_ami_id        = "ami-0abcdef1234567890"
  fee_recipient           = "0x000000000000000000000000000000000000dEaD"
  genesis_validators_root = "0x0000000000000000000000000000000000000000000000000000000000000000"
  monitoring_cidr_blocks  = ["10.20.0.0/16"]
}

run "doppelganger_protection_cannot_be_disabled_silently" {
  command = plan

  variables {
    doppelganger_protection = false
  }

  expect_failures = [var.doppelganger_protection]
}

run "the_preflight_cannot_run_without_a_genesis_root" {
  command = plan

  variables {
    enable_slashguard_preflight = true
    genesis_validators_root     = ""
  }

  expect_failures = [var.genesis_validators_root]
}

run "a_malformed_genesis_root_is_rejected" {
  command = plan

  variables {
    genesis_validators_root = "0xnotahash"
  }

  expect_failures = [var.genesis_validators_root]
}

run "monitoring_may_not_be_opened_to_the_internet" {
  command = plan

  variables {
    monitoring_cidr_blocks = ["10.20.0.0/16", "0.0.0.0/0"]
  }

  expect_failures = [var.monitoring_cidr_blocks]
}

run "a_malformed_fee_recipient_is_rejected" {
  command = plan

  variables {
    fee_recipient = "0xdeadbeef"
  }

  expect_failures = [var.fee_recipient]
}

run "an_unsupported_network_is_rejected" {
  command = plan

  variables {
    network = "gnosis"
  }

  expect_failures = [var.network]
}

run "an_unsupported_consensus_client_is_rejected" {
  command = plan

  variables {
    consensus_client = "homegrown"
  }

  expect_failures = [var.consensus_client]
}

run "graffiti_longer_than_the_consensus_limit_is_rejected" {
  command = plan

  variables {
    graffiti = "this graffiti string is definitely longer than thirty-two bytes"
  }

  expect_failures = [var.graffiti]
}

run "an_undersized_chaindata_volume_is_rejected" {
  command = plan

  variables {
    chaindata_volume_size_gb = 100
  }

  expect_failures = [var.chaindata_volume_size_gb]
}

run "a_non_https_slashguard_url_is_rejected" {
  command = plan

  variables {
    slashguard_url = "http://example.invalid/slashguard"
  }

  expect_failures = [var.slashguard_url]
}

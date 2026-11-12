# The safety properties of this module, asserted at plan time against a mocked
# AWS provider. No credentials, no API calls, no cost.
#
# If a change to this module breaks one of these, the change is wrong.

mock_provider "aws" {}

variables {
  name                = "hoodi-01"
  network             = "hoodi"
  vpc_id              = "vpc-0123456789abcdef0"
  beacon_subnet_id    = "subnet-0123456789abcdef0"
  validator_subnet_id = "subnet-0abcdef1234567890"
  beacon_ami_id       = "ami-0123456789abcdef0"
  validator_ami_id    = "ami-0abcdef1234567890"
  fee_recipient       = "0x000000000000000000000000000000000000dEaD"

  # Placeholder. Real deployments read this from their own beacon node; this
  # module never ships a table of network roots.
  genesis_validators_root = "0x0000000000000000000000000000000000000000000000000000000000000000"

  monitoring_cidr_blocks = ["10.20.0.0/16"]
}

run "there_is_exactly_one_validator_and_no_failover" {
  command = plan

  assert {
    condition     = output.slashing_safety.validator_instance_count == 1
    error_message = "This module must provision exactly one validator instance."
  }

  assert {
    condition     = output.slashing_safety.automatic_failover == false
    error_message = "Automatic failover of a validator client is a slashing mechanism, not a availability mechanism."
  }

  assert {
    condition     = output.slashing_safety.replacement_strategy == "destroy-then-create"
    error_message = "A replacement validator host must never overlap in time with the host it replaces."
  }
}

run "doppelganger_protection_is_on_by_default" {
  command = plan

  assert {
    condition     = output.slashing_safety.doppelganger_protection == true
    error_message = "Doppelganger protection must default to on."
  }
}

run "the_beacon_api_is_not_reachable_from_any_cidr" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.beacon_api_from_validator.cidr_ipv4 == null
    error_message = "The beacon API rule must reference the validator security group, never a CIDR."
  }

  assert {
    condition     = length(output.slashing_safety.beacon_api_reachable_from_cidrs) == 0
    error_message = "No CIDR may reach the beacon API."
  }
}

run "the_validator_host_accepts_nothing_but_a_metrics_scrape" {
  command = plan

  # One CIDR times two metrics ports. If a rule is ever added to this security
  # group, this count changes and the test fails on purpose.
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.validator_metrics) == 2
    error_message = "The validator security group must have exactly the metrics ingress rules and nothing else."
  }

  assert {
    condition     = alltrue([for r in values(aws_vpc_security_group_ingress_rule.validator_metrics) : r.cidr_ipv4 != "0.0.0.0/0"])
    error_message = "No ingress rule on the validator host may come from the open internet."
  }

  assert {
    condition     = alltrue([for r in values(aws_vpc_security_group_ingress_rule.validator_metrics) : r.from_port == r.to_port])
    error_message = "Metrics ingress must be per-port, never a range."
  }
}

run "metrics_ingress_never_covers_the_p2p_or_api_ports" {
  command = plan

  assert {
    condition = alltrue([
      for r in values(aws_vpc_security_group_ingress_rule.beacon_metrics) :
      r.from_port != var.cl_p2p_port && r.from_port != var.el_p2p_port && r.from_port != var.beacon_api_port
    ])
    error_message = "A metrics rule must not open a peer or API port."
  }
}

run "both_hosts_require_imdsv2_and_encrypted_volumes" {
  command = plan

  assert {
    condition     = aws_instance.validator.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must be required on the validator host."
  }

  assert {
    condition     = aws_instance.beacon.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must be required on the beacon host."
  }

  assert {
    condition     = aws_instance.validator.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "The metadata hop limit must be 1 so a container cannot reach the instance role."
  }

  assert {
    condition     = aws_instance.validator.root_block_device[0].encrypted == true
    error_message = "The validator root volume holds the keystores; it must be encrypted."
  }

  assert {
    condition     = aws_ebs_volume.chaindata.encrypted == true
    error_message = "The chaindata volume must be encrypted."
  }
}

run "the_validator_host_is_protected_from_casual_termination" {
  command = plan

  assert {
    condition     = aws_instance.validator.disable_api_termination == true
    error_message = "Termination protection must default to on for the signing host."
  }
}

run "disabling_doppelganger_protection_requires_an_explicit_acknowledgement" {
  command = plan

  variables {
    doppelganger_protection                                = false
    i_accept_the_risk_of_disabling_doppelganger_protection = true
  }

  assert {
    condition     = output.slashing_safety.doppelganger_protection == false
    error_message = "The acknowledged opt-out must be reflected in the safety output so an audit can see it."
  }
}

run "monitoring_can_be_left_off_entirely" {
  command = plan

  variables {
    monitoring_cidr_blocks = []
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.validator_metrics) == 0
    error_message = "With no monitoring CIDRs the validator host must have no ingress at all."
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.beacon_metrics) == 0
    error_message = "With no monitoring CIDRs the beacon host must only have its p2p and API rules."
  }
}

# The preflight only catches a restore from an old backup if it knows the head
# epoch. These runs pin that the unit gets it from the beacon node on every
# start instead of relying on an operator to pass --current-epoch.
#
# They use command = apply because the rendered user data depends on the
# beacon host's private IP, which is unknown at plan time. Against the mock
# provider, apply creates nothing and needs no credentials.
run "the_preflight_runs_with_the_head_epoch_from_the_beacon_node" {
  command = apply

  override_resource {
    target = aws_instance.beacon
    values = {
      private_ip = "10.20.1.10"
    }
  }

  assert {
    condition     = strcontains(local.validator_user_data, "ExecStartPre=/usr/local/bin/slashguard-preflight\n")
    error_message = "The validator unit must start through the preflight wrapper, not a bare slashguard call without a head epoch."
  }

  assert {
    condition     = strcontains(local.validator_user_data, "cat >/usr/local/bin/slashguard-preflight <<'PREFLIGHT'")
    error_message = "The validator user data must install the preflight wrapper."
  }

  assert {
    condition     = strcontains(local.slashguard_preflight_script, "beacon='http://10.20.1.10:5052'")
    error_message = "The wrapper must ask the beacon node this validator uses for the head."
  }

  assert {
    condition     = strcontains(local.slashguard_preflight_script, "/eth/v1/beacon/headers/head") && strcontains(local.slashguard_preflight_script, "/eth/v1/node/syncing")
    error_message = "The wrapper must read the head header and refuse a syncing beacon node."
  }

  assert {
    condition     = strcontains(local.slashguard_preflight_script, "--current-epoch \"$epoch\"")
    error_message = "The wrapper must pass the head epoch to slashguard, or the staleness check is skipped."
  }

  assert {
    condition     = strcontains(local.slashguard_preflight_script, "--max-epoch-lag 4 \\") && strcontains(local.slashguard_preflight_script, "--fail-on high\n")
    error_message = "The wrapper must pass the default lag (4) and fail-on (high) to slashguard."
  }

  assert {
    condition     = output.slashing_safety.preflight_checks_staleness == true
    error_message = "With the preflight on, the safety output must report that it checks staleness."
  }

  assert {
    condition     = output.slashing_safety.slashguard_max_epoch_lag == 4 && output.slashing_safety.slashguard_fail_on == "high"
    error_message = "The safety output must carry the preflight thresholds so a reviewer can diff them."
  }
}

run "preflight_thresholds_reach_the_wrapper" {
  command = apply

  override_resource {
    target = aws_instance.beacon
    values = {
      private_ip = "10.20.1.10"
    }
  }

  variables {
    slashguard_max_epoch_lag = 0
    slashguard_fail_on       = "medium"
  }

  assert {
    condition     = strcontains(local.slashguard_preflight_script, "--max-epoch-lag 0 \\") && strcontains(local.slashguard_preflight_script, "--fail-on medium\n")
    error_message = "slashguard_max_epoch_lag and slashguard_fail_on must be passed through to slashguard."
  }
}

run "without_the_preflight_nothing_claims_a_staleness_check" {
  command = apply

  override_resource {
    target = aws_instance.beacon
    values = {
      private_ip = "10.20.1.10"
    }
  }

  variables {
    enable_slashguard_preflight = false
  }

  assert {
    condition     = !strcontains(local.validator_user_data, "ExecStartPre=")
    error_message = "With the preflight off, the unit must have no ExecStartPre."
  }

  assert {
    condition     = output.slashing_safety.preflight_checks_staleness == false
    error_message = "With the preflight off, the safety output must not claim a staleness check."
  }
}

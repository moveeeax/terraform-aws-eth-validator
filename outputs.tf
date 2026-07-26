output "beacon_instance_id" {
  description = "Instance ID of the execution + consensus host."
  value       = aws_instance.beacon.id
}

output "validator_instance_id" {
  description = "Instance ID of the validator host."
  value       = aws_instance.validator.id
}

output "beacon_private_ip" {
  description = "Private IP of the beacon host; this is the endpoint the validator client dials."
  value       = aws_instance.beacon.private_ip
}

output "validator_private_ip" {
  description = "Private IP of the validator host."
  value       = aws_instance.validator.private_ip
}

output "beacon_security_group_id" {
  description = "Security group of the beacon host."
  value       = aws_security_group.beacon.id
}

output "validator_security_group_id" {
  description = "Security group of the validator host. Reference it from your monitoring stack rather than widening monitoring_cidr_blocks."
  value       = aws_security_group.validator.id
}

output "chaindata_volume_id" {
  description = "EBS volume holding execution and consensus chaindata."
  value       = aws_ebs_volume.chaindata.id
}

output "prometheus_scrape_targets" {
  description = "Ready-made static_configs entries for the Prometheus job in monitoring/prometheus/."
  value = {
    execution      = "${aws_instance.beacon.private_ip}:${local.metrics_ports.execution}"
    beacon         = "${aws_instance.beacon.private_ip}:${local.metrics_ports.beacon}"
    validator      = "${aws_instance.validator.private_ip}:${local.metrics_ports.validator}"
    node_beacon    = "${aws_instance.beacon.private_ip}:${local.metrics_ports.node}"
    node_validator = "${aws_instance.validator.private_ip}:${local.metrics_ports.node}"
  }
}

# The audit surface of this deployment, in the form a reviewer asks for it.
#
# Every field here is derived from configuration rather than from the AWS API,
# so it is known at plan time. That is what makes the invariants testable in
# CI, and it is what lets an operator diff the safety posture of a change
# before applying it.
output "slashing_safety" {
  description = "Slashing-relevant properties of this deployment, known at plan time."
  value = {
    validator_instance_count            = 1
    automatic_failover                  = false
    replacement_strategy                = "destroy-then-create"
    doppelganger_protection             = var.doppelganger_protection
    keys_on_separate_host_from_beacon   = true
    validator_role_can_read_key_backups = false
    beacon_api_reachable_from_cidrs     = []
    validator_ingress_cidrs             = var.monitoring_cidr_blocks
    slashguard_preflight                = var.enable_slashguard_preflight
    termination_protection              = var.enable_termination_protection
    imdsv2_required                     = true
    volumes_encrypted                   = true
    ssh_key_configured                  = false
  }
}

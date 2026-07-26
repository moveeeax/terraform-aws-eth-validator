# The design in one paragraph.
#
# Two hosts. The beacon host runs the execution client and the consensus
# client; it is the only thing that talks to the network. The validator host
# runs the validator client and holds the keys; it accepts no inbound traffic
# except a metrics scrape from an address range you name, and it reaches the
# beacon API over a security-group reference rather than a CIDR.
#
# There is exactly one validator host and there is no automatic failover. That
# is not an omission. Automatic failover of a validator client is a mechanism
# whose failure mode is two instances signing with the same keys, and the
# penalty for that is correlated slashing. Downtime costs a fraction of a
# percent of a validator's stake per day. A correlated slashing costs a
# meaningful fraction of the whole stake. The trade is not close.

locals {
  common_tags = merge(
    {
      "eth:network"  = var.network
      "eth:module"   = "terraform-aws-eth-validator"
      "eth:instance" = var.name
    },
    var.tags,
  )

  # Ports the clients listen on locally. Only the p2p ports and the metrics
  # ports are reachable from anywhere else.
  metrics_ports = {
    execution = 6060
    beacon    = 5054
    validator = 5064
    node      = 9100
  }

  # One security-group rule per (CIDR, port) pair. A port *range* covering the
  # metrics ports would also cover the consensus p2p port and everything
  # between, which is exactly the kind of quiet over-exposure this module is
  # supposed to be a counter-example to.
  beacon_scrape_rules = {
    for pair in setproduct(var.monitoring_cidr_blocks, [
      { name = "execution", port = local.metrics_ports.execution },
      { name = "beacon", port = local.metrics_ports.beacon },
      { name = "node-exporter", port = local.metrics_ports.node },
    ]) : "${pair[0]}-${pair[1].port}" => { cidr = pair[0], port = pair[1].port, name = pair[1].name }
  }

  validator_scrape_rules = {
    for pair in setproduct(var.monitoring_cidr_blocks, [
      { name = "validator", port = local.metrics_ports.validator },
      { name = "node-exporter", port = local.metrics_ports.node },
    ]) : "${pair[0]}-${pair[1].port}" => { cidr = pair[0], port = pair[1].port, name = pair[1].name }
  }

  beacon_user_data = templatefile("${path.module}/templates/beacon-user-data.sh.tftpl", {
    network                  = var.network
    execution_client         = var.execution_client
    consensus_client         = var.consensus_client
    execution_client_version = var.execution_client_version
    consensus_client_version = var.consensus_client_version
    el_p2p_port              = var.el_p2p_port
    cl_p2p_port              = var.cl_p2p_port
    beacon_api_port          = var.beacon_api_port
    metrics_ports            = local.metrics_ports
    chaindata_device         = "/dev/xvdf"
    chaindata_mount          = "/var/lib/eth/chaindata"
  })

  validator_user_data = templatefile("${path.module}/templates/validator-user-data.sh.tftpl", {
    network                 = var.network
    consensus_client        = var.consensus_client
    client_version          = var.consensus_client_version
    beacon_endpoint         = "http://${aws_instance.beacon.private_ip}:${var.beacon_api_port}"
    fee_recipient           = var.fee_recipient
    graffiti                = var.graffiti
    doppelganger_protection = var.doppelganger_protection
    metrics_port            = local.metrics_ports.validator
    enable_preflight        = var.enable_slashguard_preflight
    genesis_validators_root = var.genesis_validators_root
    slashguard_url          = var.slashguard_url
    keys_dir                = "/var/lib/eth/validator/keys"
    protection_file         = "/var/lib/eth/validator/slashing-protection.json"
  })
}

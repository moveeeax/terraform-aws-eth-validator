variable "name" {
  description = "Name prefix for every resource. One deployment per name."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$", var.name))
    error_message = "name must be 3-32 lowercase alphanumeric characters or hyphens, and may not start or end with a hyphen."
  }
}

variable "network" {
  description = "Ethereum network this pair runs on."
  type        = string

  validation {
    condition     = contains(["mainnet", "sepolia", "holesky", "hoodi"], var.network)
    error_message = "network must be one of: mainnet, sepolia, holesky, hoodi."
  }
}

variable "vpc_id" {
  description = "VPC the two hosts live in."
  type        = string
}

variable "beacon_subnet_id" {
  description = "Subnet for the execution + consensus host. Needs inbound peer traffic, so it is normally a public subnet with an Elastic IP or a NAT-free public IP."
  type        = string
}

variable "validator_subnet_id" {
  description = "Subnet for the validator host. Should be a private subnet: nothing on the internet ever needs to reach the signing host."
  type        = string
}

variable "beacon_ami_id" {
  description = "AMI for the beacon host. Pinned by the caller on purpose: a module that resolves 'latest' rebuilds your beacon node on an unrelated terraform apply."
  type        = string
}

variable "validator_ami_id" {
  description = "AMI for the validator host. Pinned by the caller, for the same reason, and more so: replacing this host is a slashing-relevant event."
  type        = string
}

variable "beacon_instance_type" {
  description = "Instance type for the execution + consensus host."
  type        = string
  default     = "m7i.xlarge"
}

variable "validator_instance_type" {
  description = "Instance type for the validator host. The validator client is cheap; this host is small on purpose."
  type        = string
  default     = "t3.small"
}

variable "execution_client" {
  description = "Execution client running on the beacon host."
  type        = string
  default     = "geth"

  validation {
    condition     = contains(["geth", "nethermind", "besu", "erigon", "reth"], var.execution_client)
    error_message = "execution_client must be one of: geth, nethermind, besu, erigon, reth."
  }
}

variable "consensus_client" {
  description = "Consensus client running on the beacon host. The validator client is the same implementation."
  type        = string
  default     = "lighthouse"

  validation {
    condition     = contains(["lighthouse", "teku", "nimbus", "prysm", "lodestar"], var.consensus_client)
    error_message = "consensus_client must be one of: lighthouse, teku, nimbus, prysm, lodestar."
  }
}

variable "execution_client_version" {
  description = "Version string written to /etc/eth-validator/versions.env. The module does not download binaries; see the README for why."
  type        = string
  default     = ""
}

variable "consensus_client_version" {
  description = "Version string written to /etc/eth-validator/versions.env."
  type        = string
  default     = ""
}

variable "fee_recipient" {
  description = "Execution-layer address that receives priority fees and MEV."
  type        = string

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.fee_recipient))
    error_message = "fee_recipient must be a 20-byte hex address, for example 0x000000000000000000000000000000000000dEaD."
  }
}

variable "graffiti" {
  description = "Graffiti string. Kept short and boring; graffiti is public and identifying your operator by it is an operational choice, not a default."
  type        = string
  default     = ""

  validation {
    condition     = length(var.graffiti) <= 32
    error_message = "graffiti is limited to 32 bytes by the consensus layer."
  }
}

variable "doppelganger_protection" {
  description = "Run the validator client with doppelganger protection. It costs two to three epochs of missed attestations at start-up and it is the single cheapest defence against a second signing instance."
  type        = bool
  default     = true

  validation {
    condition     = var.doppelganger_protection || var.i_accept_the_risk_of_disabling_doppelganger_protection
    error_message = "Disabling doppelganger protection also requires i_accept_the_risk_of_disabling_doppelganger_protection = true. If you cannot write that line down, do not disable it."
  }
}

variable "i_accept_the_risk_of_disabling_doppelganger_protection" {
  description = "Explicit acknowledgement required to set doppelganger_protection = false."
  type        = bool
  default     = false
}

variable "enable_slashguard_preflight" {
  description = "Add an ExecStartPre to the validator unit that runs slashguard against the slashing-protection export before the client is allowed to start. If the check fails, the unit does not start."
  type        = bool
  default     = true
}

variable "slashguard_url" {
  description = "Optional HTTPS URL to a slashguard binary, fetched at first boot. Leave empty and install it with your configuration-management tool instead; the module will not invent an artefact store for you."
  type        = string
  default     = ""

  validation {
    condition     = var.slashguard_url == "" || startswith(var.slashguard_url, "https://")
    error_message = "slashguard_url must be an https:// URL."
  }
}

variable "genesis_validators_root" {
  description = "Genesis validators root of var.network, passed to the slashguard preflight. Read it from your own beacon node rather than trusting a table: curl -s $BEACON/eth/v1/beacon/genesis | jq -r .data.genesis_validators_root"
  type        = string
  default     = ""

  validation {
    condition     = var.genesis_validators_root == "" || can(regex("^0x[0-9a-fA-F]{64}$", var.genesis_validators_root))
    error_message = "genesis_validators_root must be a 32-byte hex value with a 0x prefix."
  }

  validation {
    condition     = !var.enable_slashguard_preflight || var.genesis_validators_root != ""
    error_message = "enable_slashguard_preflight = true requires genesis_validators_root; a preflight that cannot tell which chain the export came from is not a preflight."
  }
}

variable "chaindata_volume_size_gb" {
  description = "Size of the beacon host's chaindata volume."
  type        = number
  default     = 2048

  validation {
    condition     = var.chaindata_volume_size_gb >= 512
    error_message = "chaindata_volume_size_gb below 512 will not hold a synced execution client for long, and a full disk is one of the four things that reliably precedes an incident."
  }
}

variable "chaindata_volume_iops" {
  description = "Provisioned IOPS for the gp3 chaindata volume."
  type        = number
  default     = 6000
}

variable "chaindata_volume_throughput" {
  description = "Provisioned throughput (MiB/s) for the gp3 chaindata volume."
  type        = number
  default     = 500
}

variable "root_volume_size_gb" {
  description = "Root volume size for both hosts."
  type        = number
  default     = 30
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key for EBS encryption. Null uses the AWS-managed aws/ebs key. Volumes are always encrypted either way."
  type        = string
  default     = null
}

variable "monitoring_cidr_blocks" {
  description = "CIDRs allowed to scrape the metrics ports. This is the only ingress the validator host accepts."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.monitoring_cidr_blocks, "0.0.0.0/0")
    error_message = "monitoring_cidr_blocks must not contain 0.0.0.0/0. Metrics endpoints leak validator identity and duty timing."
  }
}

variable "el_p2p_port" {
  description = "Execution-layer peer port (TCP and UDP)."
  type        = number
  default     = 30303
}

variable "cl_p2p_port" {
  description = "Consensus-layer peer port (TCP and UDP)."
  type        = number
  default     = 9000
}

variable "beacon_api_port" {
  description = "Beacon HTTP API port. Reachable only from the validator security group."
  type        = number
  default     = 5052
}

variable "enable_termination_protection" {
  description = "Set disable_api_termination on the validator host. Replacing the signing host is a procedure, not a click."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

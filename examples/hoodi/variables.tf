variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-central-1"
}

variable "vpc_id" {
  description = "Existing VPC."
  type        = string
}

variable "beacon_subnet_id" {
  description = "Public subnet for the beacon host."
  type        = string
}

variable "validator_subnet_id" {
  description = "Private subnet for the validator host."
  type        = string
}

variable "beacon_ami_id" {
  description = "Pinned AMI for the beacon host."
  type        = string
}

variable "validator_ami_id" {
  description = "Pinned AMI for the validator host."
  type        = string
}

variable "fee_recipient" {
  description = "Execution-layer address that receives priority fees."
  type        = string
}

variable "genesis_validators_root" {
  description = "Genesis validators root of the target network, read from your own beacon node."
  type        = string
}

variable "monitoring_cidr_blocks" {
  description = "CIDRs allowed to scrape metrics."
  type        = list(string)
  default     = []
}

terraform {
  # 1.9 is the floor because several variable validations in this module refer
  # to other variables, which older Terraform does not allow. Those validations
  # are the ones that stop a caller from disabling a slashing guard by
  # accident, so they are not optional.
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    fmc = {
      source  = "CiscoDevNet/fmc"
      version = "2.0.1"
    }
  }
}

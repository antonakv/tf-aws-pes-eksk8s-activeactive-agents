terraform {
  required_version = ">= 1.5.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.12.0"
    }
    template = {
      source  = "hashicorp/template"
      version = "= 2.2.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "= 2.4.0"
    }
  }
}

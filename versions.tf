terraform {
  required_version = ">= 1.5.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.9.0"
    }
    template = {
      source  = "hashicorp/template"
      version = "= 2.2.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 4.10.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "= 2.4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "= 2.22.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "= 2.10.1"
    }
  }
}

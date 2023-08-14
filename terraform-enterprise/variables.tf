variable "tfe_license_path" {
  type        = string
  description = "Path for the TFE license"
}
variable "tfe_hostname" {
  type        = string
  description = "Terraform Enterprise hostname"
}
variable "domain_name" {
  type        = string
  description = "Domain name"
}
variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare DNS zone id"
  sensitive   = true
}
variable "cloudflare_api_token" {
  type        = string
  description = "Cloudflare DNS API token"
  sensitive   = true
}
variable "ssl_cert_path" {
  type        = string
  description = "SSL certificate file path"
}
variable "ssl_fullchain_cert_path" {
  type        = string
  description = "SSL fullchain cert file path"
}
variable "ssl_key_path" {
  type        = string
  description = "SSL key file path"
}
variable "ssl_chain_path" {
  type        = string
  description = "SSL chain file path"
}
variable "docker_repository_token" {
  type        = string
  description = "Docker repository token"
  sensitive   = true
}
variable "docker_repository_login" {
  type        = string
  description = "Docker repository login"
  sensitive   = true
}
variable "docker_image_tag" {
  type        = string
  description = "Docker tfe image tag"
}
variable "docker_repository" {
  type        = string
  description = "Docker tfe image repository"
}
variable "tfe_tls_version" {
  type        = string
  description = "TFE tls version"
}
variable "tfc_agent_docker_image_tag" {
  type        = string
  description = "hashicorp/tfc-agent image tag"
}

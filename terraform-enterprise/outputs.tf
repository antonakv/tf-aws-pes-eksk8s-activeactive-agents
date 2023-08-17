output "service_url" {
  value       = data.kubernetes_service.tfe.status != null ? data.kubernetes_service.tfe.status.0.load_balancer.0.ingress.0.hostname : "0.0.0.0"
  description = "Service url"
}
output "url" {
  value       = "https://${local.tfe_hostname}/admin/account/new?token=${random_id.user_token.hex}"
  description = "Login URL and token"
}
output "tfe_hostname" {
  value       = local.tfe_hostname
  description = "TFE fqdn"
}

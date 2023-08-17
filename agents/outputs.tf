output "agent_token" {
  description = "Agent token"
  value       = var.agent_token
  sensitive   = true
}
output "aws_active_agents_ips" {
  value       = join(", ", data.aws_instances.tfc_agent.private_ips)
  description = "Agent hosts in the autoscaling group"
}
output "aws_agent_ec2_ids" {
  value       = toset(data.aws_instances.tfc_agent.ids)
  description = "Agent EC2 host ids"
}

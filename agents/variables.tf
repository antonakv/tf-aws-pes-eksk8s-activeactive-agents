variable "instance_type_agent" {
  description = "Amazon EC2 instance type"
}
variable "agent_ami" {
  description = "Amazon EC2 ami with tfc agent created with Packer"
}
variable "agent_token" {
  description = "Terraform agent token"
  default     = "not_set"
  sensitive   = true
}
variable "asg_min_agents" {
  type        = number
  default     = 0
  description = "Minimal number of tfc agents in Autoscaling group"
}
variable "asg_max_agents" {
  type        = number
  default     = 0
  description = "Maximal number of tfc agents in Autoscaling group"
}
variable "asg_desired_agents" {
  type        = number
  default     = 0
  description = "Desired number of tfc agents in Autoscaling group"
}

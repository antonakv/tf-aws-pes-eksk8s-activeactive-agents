variable "region" {
  type        = string
  description = "AWS region"
}
variable "tfe_license_path" {
  type        = string
  description = "Path for the TFE license"
}
variable "cidr_vpc" {
  type        = string
  description = "Amazon EC2 VPC net"
}
variable "cidr_subnet_private_1" {
  type        = string
  description = "Amazon EC2 subnet 1 private"
}
variable "cidr_subnet_private_2" {
  type        = string
  description = "Amazon EC2 subnet 2 private"
}
variable "cidr_subnet_public_1" {
  type        = string
  description = "Amazon EC2 subnet 1 public"
}
variable "cidr_subnet_public_2" {
  type        = string
  description = "Amazon EC2 subnet 2 public"
}
variable "aws_az_1" {
  type        = string
  description = "Amazon AWS availability zone 1"
}
variable "aws_az_2" {
  type        = string
  description = "Amazon AWS availability zone 2"
}
variable "instance_type_redis" {
  description = "Amazon Elasticashe Redis instance type"
}
variable "key_name" {
  description = "Name of Amazon EC2 keypair for the specific region"
}
variable "db_instance_type" {
  description = "Amazon EC2 RDS instance type"
}
variable "instance_type" {
  description = "Amazon EC2 instance type"
}
variable "tfe_hostname" {
  type        = string
  description = "Terraform Enterprise hostname"
}
variable "domain_name" {
  type        = string
  description = "Domain name"
}
variable "postgres_db_name" {
  type        = string
  description = "Postgres database DB name"
}
variable "postgres_engine_version" {
  type        = string
  description = "Postgres engine version"
}
variable "postgres_username" {
  type        = string
  description = "Postgres database username"
}
variable "aws_ami" {
  type        = string
  description = "Ubuntu focal AMI with preinstalled docker-ce 20.10.7 docker-ce-cli 20.10.7 containerd.io"
}
variable "k8s_min_nodes" {
  type        = number
  description = "Minimal number of nodes in k8s"
}
variable "k8s_max_nodes" {
  type        = number
  default     = 2
  description = "Maximal number of nodes in k8s"
}
variable "k8s_desired_nodes" {
  type        = number
  description = "Desired number of nodes in k8s"
  validation {
    condition     = var.k8s_desired_nodes <= 3
    error_message = "Maximal number of active nodes for ActiveActive is 3"
  }
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
variable "lb_ssl_policy" {
  type        = string
  description = "SSL policy for load balancer"
}
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
variable "k8s_desired_agents" {
  type = number
}
variable "tfc_agent_docker_image_tag" {
  type        = string
  description = "hashicorp/tfc-agent image tag"
}

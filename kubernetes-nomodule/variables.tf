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
variable "instance_type" {
  type        = string
  description = "Amazon EKS EC2 instance type"
}
variable "tfe_k8s_namespace_name" {
  type        = string
  description = "Name of the TFE k8s namespace"
}
variable "tfe_k8s_serviceaccount_name" {
  type        = string
  description = "Name of the TFE k8s namespace"
}

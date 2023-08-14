output "kubectl_get_update_credentials" {
  description = "Run to retrieve the access credentials for the k8s and configure kubectl"
  value       = "aws eks --region ${data.terraform_remote_state.main.outputs.region} update-kubeconfig --name ${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks"
}
output "aws_eks_k8s_endpoint" {
  description = "AWS EKS K8S endpoint"
  value       = data.aws_eks_cluster.k8s.endpoint
}
output "aws_eks_k8s_certificate_authority" {
  description = "AWS EKS K8S certificate authority"
  value       = data.aws_eks_cluster.k8s.certificate_authority.0.data
}
output "aws_eks_cluster_k8s_name" {
  description = "AWS EKS K8S cluster name"
  value       = data.aws_eks_cluster.k8s.name
}

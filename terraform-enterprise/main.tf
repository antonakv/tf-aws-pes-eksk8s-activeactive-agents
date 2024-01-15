data "terraform_remote_state" "main" {
  backend = "local"

  config = {
    path = "../terraform.tfstate"
  }
}

data "terraform_remote_state" "kubernetes" {
  backend = "local"

  config = {
    path = "../kubernetes/terraform.tfstate"
  }
}

data "aws_eks_cluster_auth" "cluster_auth" {
  name = data.terraform_remote_state.kubernetes.outputs.aws_eks_cluster_k8s_name
}

locals {
  tfe_hostname         = "${data.terraform_remote_state.main.outputs.friendly_name_id}${var.tfe_hostname}"
  service_account_name = "terraform-enterprise"
  tfe_k8s_namespace    = "terraform-enterprise"
  overrides-yaml = templatefile(
    "templates/overrides.yaml.tpl",
    {
      hostname          = local.tfe_hostname
      docker_image_tag  = var.docker_image_tag
      enc_password      = random_id.enc_password.hex
      pg_dbname         = data.terraform_remote_state.main.outputs.postgres_db_name
      pg_netloc         = data.terraform_remote_state.main.outputs.postgres_endpoint
      pg_password       = data.terraform_remote_state.main.outputs.postgres_password
      pg_user           = data.terraform_remote_state.main.outputs.postgres_username
      region            = data.terraform_remote_state.main.outputs.region
      s3_bucket         = data.terraform_remote_state.main.outputs.aws_s3_bucket_name
      install_id        = random_id.install_id.hex
      user_token        = random_id.user_token.hex
      redis_pass        = data.terraform_remote_state.main.outputs.redis_password
      redis_host        = data.terraform_remote_state.main.outputs.redis_host
      tfe_tls_version   = var.tfe_tls_version
      tls_key_data      = filebase64(var.ssl_key_path)
      tls_crt_data      = filebase64(var.ssl_fullchain_cert_path)
      license_data      = file(var.tfe_license_path) # ! License variable is not base64 encoded for k8s setup
      docker_repository = var.docker_repository
      tfe_s3_role_arn   = data.terraform_remote_state.kubernetes.outputs.tfe_pods_assume_role
    }
  )
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

provider "helm" {
  kubernetes {
    host                   = data.terraform_remote_state.kubernetes.outputs.aws_eks_k8s_endpoint
    cluster_ca_certificate = base64decode(data.terraform_remote_state.kubernetes.outputs.aws_eks_k8s_certificate_authority)
    token                  = data.aws_eks_cluster_auth.cluster_auth.token
  }
  experiments {
    # show rendered helm values in the terraform plan
    manifest = false
  }
}

provider "kubernetes" {
  host                   = data.terraform_remote_state.kubernetes.outputs.aws_eks_k8s_endpoint
  cluster_ca_certificate = base64decode(data.terraform_remote_state.kubernetes.outputs.aws_eks_k8s_certificate_authority)
  token                  = data.aws_eks_cluster_auth.cluster_auth.token
}

resource "helm_release" "terraform-enterprise" {
  name             = "terraform-enterprise"
  chart            = "../terraform-enterprise-helm"
  values           = [local.overrides-yaml]
  namespace        = kubernetes_namespace.terraform-enterprise.id
  cleanup_on_fail  = true
  replace          = true
  force_update     = false
  create_namespace = false
  version          = "0.1.2"
  wait             = false
  wait_for_jobs    = true
  timeout          = 800
  depends_on       = [kubernetes_namespace.terraform-enterprise, kubernetes_namespace.terraform-enterprise-agents]
}

data "local_sensitive_file" "sslcert" {
  filename = var.ssl_cert_path
}

data "local_sensitive_file" "sslkey" {
  filename = var.ssl_key_path
}

data "local_sensitive_file" "sslchain" {
  filename = var.ssl_chain_path
}

data "aws_instances" "tfc_agent" {
  instance_tags = {
    Name = "${data.terraform_remote_state.main.outputs.friendly_name_id}-asg-tfc_agent"
  }
  filter {
    name   = "instance.group-id"
    values = [data.terraform_remote_state.main.outputs.internal_sg_id]
  }
  instance_state_names = ["running"]
}

provider "aws" {
  region = data.terraform_remote_state.main.outputs.region
}

resource "random_id" "enc_password" {
  byte_length = 16
}

resource "random_id" "install_id" {
  byte_length = 16
}

resource "random_id" "user_token" {
  byte_length = 16
}

resource "random_string" "password" {
  length  = 16
  special = false
}

resource "kubernetes_namespace" "terraform-enterprise" {
  metadata {
    name = "terraform-enterprise"
    labels = {
      app = "terraform-enterprise"
    }
    annotations = {
      "meta.helm.sh/release-name" : "terraform-enterprise"
      "meta.helm.sh/release-namespace" : "terraform-enterprise"
    }
  }
  lifecycle {
    ignore_changes = [metadata.0.annotations, metadata.0.labels]
  }
}

resource "kubernetes_namespace" "terraform-enterprise-agents" {
  metadata {
    name = "terraform-enterprise-agents"
    labels = {
      "app.kubernetes.io/managed-by" : "Helm"
    }
    annotations = {
      "app.kubernetes.io/managed-by" : "Helm"
      "meta.helm.sh/release-name" : "terraform-enterprise"
      "meta.helm.sh/release-namespace" : "terraform-enterprise"
    }
  }
  lifecycle {
    ignore_changes = [metadata.0.annotations, metadata.0.labels]
  }
}

data "template_file" "docker_config" {
  template = file("templates/docker_registry.json.tpl")
  vars = {
    docker-username = var.docker_repository_login
    docker-password = var.docker_repository_token
    docker-server   = var.docker_repository
    auth            = base64encode("${var.docker_repository_login}:${var.docker_repository_token}")
  }
}

resource "kubernetes_secret" "docker_registry" {
  metadata {
    name      = "docker-registry"
    namespace = kubernetes_namespace.terraform-enterprise.id
  }
  data = {
    ".dockerconfigjson" = "${data.template_file.docker_config.rendered}"
  }
  type = "kubernetes.io/dockerconfigjson"
}

data "kubernetes_service" "tfe" {
  metadata {
    name      = "terraform-enterprise"
    namespace = "terraform-enterprise"
  }
}

resource "cloudflare_record" "tfe" {
  zone_id    = var.cloudflare_zone_id
  name       = local.tfe_hostname
  type       = "CNAME"
  ttl        = 1
  value      = data.kubernetes_service.tfe.status != null ? data.kubernetes_service.tfe.status.0.load_balancer.0.ingress.0.hostname : "0.0.0.0"
  depends_on = [helm_release.terraform-enterprise]
}
# ! Default service account in the TFE FDO Helm chart is terraform-enterprise and annotations for TFE should be there 

resource "kubernetes_service_account" "terraform-enterprise-s3" {
  metadata {
    name      = "terraform-enterprise-s3"
    namespace = "terraform-enterprise"
    annotations = {
      "eks.amazonaws.com/role-arn" : data.terraform_remote_state.kubernetes.outputs.tfe_pods_assume_role
    }
  }
  depends_on = [kubernetes_namespace.terraform-enterprise]
}

resource "kubernetes_pod" "busybox" {
  metadata {
    name      = "busybox"
    namespace = "terraform-enterprise"
  }
  spec {
    service_account_name = "terraform-enterprise-s3"
    container {
      name    = "busybox"
      image   = "busybox:1.36"
      command = ["sleep", "3600"]
    }
  }
  depends_on = [kubernetes_namespace.terraform-enterprise]
}

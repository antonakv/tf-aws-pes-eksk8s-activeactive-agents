locals {
  tfe_hostname         = "${random_string.friendly_name.id}${var.tfe_hostname}"
  service_account_name = "terraform-enterprise"
  tfe_k8s_namespace    = "terraform-enterprise"
  overrides-yaml = templatefile(
    "templates/overrides.yaml.tpl",
    {
      hostname          = local.tfe_hostname
      docker_image_tag  = var.docker_image_tag
      enc_password      = random_id.enc_password.hex
      pg_dbname         = var.postgres_db_name
      pg_netloc         = aws_db_instance.tfe.endpoint
      pg_password       = random_string.pgsql_password.result
      pg_user           = var.postgres_username
      region            = var.region
      s3_bucket         = aws_s3_bucket.tfe_data.id
      install_id        = random_id.install_id.hex
      user_token        = random_id.user_token.hex
      redis_pass        = random_id.redis_password.hex
      redis_host        = aws_elasticache_replication_group.redis.primary_endpoint_address
      tfe_tls_version   = var.tfe_tls_version
      tls_key_data      = filebase64(var.ssl_key_path)
      tls_crt_data      = filebase64(var.ssl_fullchain_cert_path)
      license_data      = file(var.tfe_license_path) # ! License variable is not base64 encoded for k8s setup
      docker_repository = var.docker_repository
      tfe_s3_role_arn   = aws_iam_role.tfe_pods_assume_role.arn
    }
  )
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.k8s.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.k8s.certificate_authority.0.data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        data.aws_eks_cluster.k8s.name
      ]
    }
  }
  experiments {
    # show rendered helm values in the terraform plan
    manifest = false
  }
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.k8s.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.k8s.certificate_authority.0.data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      data.aws_eks_cluster.k8s.name
    ]
  }
}

resource "helm_release" "ingress-nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  cleanup_on_fail  = true
  replace          = false
  force_update     = true
  create_namespace = false
  version          = "4.7.1"
  wait             = false
  depends_on       = [module.eks, kubernetes_namespace.ingress-nginx]
}

resource "helm_release" "terraform-enterprise" {
  name            = "terraform-enterprise"
  chart           = "../terraform-enterprise-helm"
  values          = [local.overrides-yaml]
  namespace       = kubernetes_namespace.terraform-enterprise.id
  cleanup_on_fail = true
  replace         = false
  force_update    = false
  version         = "0.1.2"
  wait            = false
  depends_on      = [module.eks, kubernetes_namespace.terraform-enterprise, helm_release.ingress-nginx]
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
    Name = "${local.friendly_name_prefix}-asg-tfc_agent"
  }
  filter {
    name   = "instance.group-id"
    values = [aws_security_group.internal_sg.id]
  }
  instance_state_names = ["running"]
}

provider "aws" {
  region = var.region
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
  }
  depends_on = [
    module.eks
  ]
}

resource "kubernetes_namespace" "ingress-nginx" {
  metadata {
    name = "ingress-nginx"
  }
  depends_on = [
    module.eks
  ]
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

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

data "aws_eks_cluster" "k8s" {
  name = module.eks.cluster_name
}


locals {
  friendly_name_prefix = "aakulov-${random_string.friendly_name.id}"
  tfe_hostname         = "${random_string.friendly_name.id}${var.tfe_hostname}"
  service_account_name = "terraform-enterprise"
  tfe_k8s_namespace    = "terraform-enterprise"
  tfc_agent_user_data = templatefile(
    "templates/installagent.sh.tpl",
    {
      region           = var.region
      tfcagent_service = filebase64("files/tfc-agent.service")
      agent_token_id   = aws_secretsmanager_secret.agent_token.id
      tfe_hostname     = local.tfe_hostname
    }
  )
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
      license_data      = filebase64(var.tfe_license_path)
      docker_repository = var.docker_repository
      tfe_s3_role_arn   = aws_iam_role.tfe_pods_assume_role.arn
    }
  )
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

provider "cloudflare" {
  api_token = var.cloudflare_api_token
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

resource "random_id" "redis_password" {
  byte_length = 16
}

resource "random_string" "friendly_name" {
  length  = 6
  upper   = false
  numeric = true
  special = false
}

resource "random_string" "pgsql_password" {
  length  = 24
  special = false
}

resource "aws_acm_certificate" "tfe" {
  private_key       = data.local_sensitive_file.sslkey.content
  certificate_body  = data.local_sensitive_file.sslcert.content
  certificate_chain = data.local_sensitive_file.sslchain.content
  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy_document" "secretsmanager" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    effect    = "Allow"
    resources = [aws_secretsmanager_secret_version.agent_token.secret_id]
    sid       = "AllowSecretsManagerSecretAccess"
  }
}

resource "aws_iam_role_policy" "secretsmanager" {
  policy = data.aws_iam_policy_document.secretsmanager.json
  role   = aws_iam_role.instance_role.id
  name   = "${local.friendly_name_prefix}-tfe-secretsmanager"
}

data "aws_iam_policy_document" "tfe_asg_discovery" {
  statement {
    effect = "Allow"

    actions = [
      "autoscaling:Describe*"
    ]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "instance_role" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance_role" {
  name_prefix        = "${local.friendly_name_prefix}-tfe"
  assume_role_policy = data.aws_iam_policy_document.instance_role.json
}

resource "aws_iam_instance_profile" "tfe" {
  name_prefix = "${local.friendly_name_prefix}-tfe"
  role        = aws_iam_role.instance_role.name
}

resource "aws_secretsmanager_secret" "agent_token" {
  description             = "TFC agent token"
  name                    = "${local.friendly_name_prefix}-agent_token"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "agent_token" {
  secret_string = var.agent_token
  secret_id     = aws_secretsmanager_secret.agent_token.id
}

resource "aws_iam_role_policy" "tfe_asg_discovery" {
  name   = "${local.friendly_name_prefix}-tfe-asg-discovery"
  role   = aws_iam_role.instance_role.id
  policy = data.aws_iam_policy_document.tfe_asg_discovery.json
}

resource "aws_vpc" "vpc" {
  cidr_block           = var.cidr_vpc
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${local.friendly_name_prefix}-vpc"
  }
}

resource "aws_subnet" "subnet_private1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_private_1
  availability_zone = var.aws_az_1
}

resource "aws_subnet" "subnet_private2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_private_2
  availability_zone = var.aws_az_2
}

resource "aws_subnet" "subnet_public1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_public_1
  availability_zone = var.aws_az_1
}

resource "aws_subnet" "subnet_public2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_public_2
  availability_zone = var.aws_az_2
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${local.friendly_name_prefix}-vpc"
  }
}

resource "aws_eip" "aws_nat" {
  domain = "vpc"
  depends_on = [
    aws_internet_gateway.igw
  ]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.aws_nat.id
  subnet_id     = aws_subnet.subnet_public1.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "${local.friendly_name_prefix}-nat"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "${local.friendly_name_prefix}-private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${local.friendly_name_prefix}-public"
  }
}

resource "aws_route_table_association" "private1" {
  subnet_id      = aws_subnet.subnet_private1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "public1" {
  subnet_id      = aws_subnet.subnet_public1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.subnet_private2.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.subnet_public2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "lb_sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "${local.friendly_name_prefix}-lb-sg"
  tags = {
    Name = "${local.friendly_name_prefix}-lb-sg"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow https port incoming connection"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow ssh port incoming connection"
  }

  ingress {
    from_port   = 19999
    to_port     = 19999
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow netdata port incoming connection"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow outgoing connections"
  }
}

resource "aws_security_group" "internal_sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "${local.friendly_name_prefix}-internal-sg"
  tags = {
    Name = "${local.friendly_name_prefix}-internal-sg"
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all the icmp types"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow ssh port 22"
  }

  ingress {
    from_port   = 19999
    to_port     = 19999
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow netdata port"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow https port incoming connection"
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_sg.id]
    description     = "allow https port incoming connection from Load balancer"
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    self        = true
    description = "allow postgres port incoming connections"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    self        = true
    description = "allow https port incoming connection"
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.public_sg.id]
    description     = "Allow ssh port 22 from public security group"
  }

  ingress {
    from_port       = 19999
    to_port         = 19999
    protocol        = "tcp"
    security_groups = [aws_security_group.public_sg.id]
    description     = "Allow netdata port from public security group"
  }

  ingress {
    from_port   = 8201
    to_port     = 8201
    protocol    = "tcp"
    self        = true
    description = "allow Vault HA request forwarding"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outgoing connections"
  }
}

resource "aws_security_group" "public_sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "${local.friendly_name_prefix}-public-sg"
  tags = {
    Name = "${local.friendly_name_prefix}-public-sg"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow http port incoming connection"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow https port incoming connection"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow ssh port 22"
  }

  ingress {
    from_port   = 19999
    to_port     = 19999
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow netdata port 19999"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outgoing connections"
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.${var.region}.s3"
}

resource "aws_vpc_endpoint_route_table_association" "private_s3_endpoint" {
  route_table_id  = aws_route_table.private.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_s3_bucket" "tfe_data" {
  bucket        = "${local.friendly_name_prefix}-tfe-data"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "tfe_data" {
  bucket = aws_s3_bucket.tfe_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "tfe_data" {
  bucket = aws_s3_bucket.tfe_data.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

/* resource "aws_s3_bucket_policy" "tfe_data" {
  bucket = aws_s3_bucket_public_access_block.tfe_data.bucket
  policy = data.aws_iam_policy_document.tfe_data.json
} */

resource "aws_security_group" "redis_sg" {
  name   = "${local.friendly_name_prefix}-redis-sg"
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.friendly_name_prefix}-redis-sg"
  }

  ingress {
    from_port       = 6379
    to_port         = 6380
    protocol        = "tcp"
    security_groups = [aws_security_group.internal_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_db_subnet_group" "tfe" {
  name       = "${local.friendly_name_prefix}-db-subnet"
  subnet_ids = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
  tags = {
    Name = "${local.friendly_name_prefix}-db-subnet"
  }
}

resource "aws_db_instance" "tfe" {
  allocated_storage           = 20
  max_allocated_storage       = 100
  engine                      = "postgres"
  engine_version              = var.postgres_engine_version
  db_name                     = var.postgres_db_name
  username                    = var.postgres_username
  password                    = random_string.pgsql_password.result
  instance_class              = var.db_instance_type
  db_subnet_group_name        = aws_db_subnet_group.tfe.name
  vpc_security_group_ids      = [aws_security_group.internal_sg.id]
  skip_final_snapshot         = true
  allow_major_version_upgrade = true
  apply_immediately           = true
  auto_minor_version_upgrade  = true
  deletion_protection         = false
  publicly_accessible         = false
  storage_type                = "gp2"
  port                        = 5432
  tags = {
    Name = "${local.friendly_name_prefix}-tfe-db"
  }
}

resource "aws_launch_configuration" "tfc_agent" {
  name_prefix   = "${local.friendly_name_prefix}-tfc_agent-launch-configuration"
  image_id      = var.agent_ami
  instance_type = var.instance_type_agent

  user_data_base64 = base64encode(local.tfc_agent_user_data)

  iam_instance_profile = aws_iam_instance_profile.tfe.name
  key_name             = var.key_name
  security_groups      = [aws_security_group.internal_sg.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
    http_tokens                 = "optional"
  }

  root_block_device {
    volume_type           = "io1"
    iops                  = 1000
    volume_size           = 40
    delete_on_termination = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "tfc_agent" {
  name                      = "${local.friendly_name_prefix}-asg-tfc_agent"
  min_size                  = var.asg_min_agents
  max_size                  = var.asg_max_agents
  desired_capacity          = var.asg_desired_agents
  vpc_zone_identifier       = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
  health_check_grace_period = 900
  health_check_type         = "EC2"
  launch_configuration      = aws_launch_configuration.tfc_agent.name
  tag {
    key                 = "Name"
    value               = "${local.friendly_name_prefix}-asg-tfc_agent"
    propagate_at_launch = true
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.16.0"

  cluster_name                                 = "${local.friendly_name_prefix}-eks"
  cluster_version                              = "1.27"
  enable_irsa                                  = true
  cluster_endpoint_private_access              = true
  cluster_endpoint_public_access               = true
  node_security_group_enable_recommended_rules = false # overrides with custom ingress rules

  create_iam_role          = true
  iam_role_name            = "${local.friendly_name_prefix}-eks-managed-node-group"
  iam_role_use_name_prefix = false

  iam_role_additional_policies = {
    AmazonEC2ContainerRegistryReadOnly = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    additional                         = aws_iam_policy.eks_s3.arn
    # additional policy should match with role used for service account annotation in helm config
  }

  cluster_addons = {
    coredns = {
      #preserve                    = false
      resolve_conflicts_on_create = "PRESERVE"
      resolve_conflicts_on_update = "OVERWRITE"
      resolve_conflicts           = "OVERWRITE"
    }
    kube-proxy = {
      #preserve                    = false
      resolve_conflicts_on_create = "PRESERVE"
      resolve_conflicts_on_update = "OVERWRITE"
      resolve_conflicts           = "OVERWRITE"
    }
    vpc-cni = {
      #preserve                    = false
      resolve_conflicts_on_create = "PRESERVE"
      resolve_conflicts_on_update = "OVERWRITE"
      resolve_conflicts           = "OVERWRITE"
    }
  }

  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }

  vpc_id                   = aws_vpc.vpc.id
  subnet_ids               = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
  control_plane_subnet_ids = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]

  eks_managed_node_group_defaults = {
    #ami_type                              = "AL2_x86_64"
    ami_type                              = "BOTTLEROCKET_x86_64"
    attach_cluster_primary_security_group = true # was false
  }

  eks_managed_node_groups = {
    first = {
      name = "${local.friendly_name_prefix}-ng-1"

      instance_types = [var.instance_type]
      disk_size      = 50

      min_size     = 1
      max_size     = 3
      desired_size = 3

      vpc_security_group_ids = [
        aws_security_group.internal_sg.id
      ]
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "optional"
        http_put_response_hop_limit = 2
        # Do not disable instance metadata `http_put_response_hop_limit = 1` as this will prevent components like the node 
        # termination handler and other things that rely on instance metadata from working properly.
        # https://aws.github.io/aws-eks-best-practices/security/docs/iam/#restrict-access-to-the-instance-profile-assigned-to-the-worker-node
        instance_metadata_tags = "enabled"
      }
    }
  }
}

data "aws_eks_cluster" "k8s" {
  name = module.eks.cluster_name
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

/* resource "kubernetes_namespace" "tfc-agent" {
  metadata {
    name = "tfc-agent"
    labels = {
      app = "tfc-agent"
    }
  }
  depends_on = [
    module.eks
  ]
} */

/* resource "kubernetes_deployment" "tfc-agent" {
  metadata {
    name = "tfc-agent"
    labels = {
      app = "tfc-agent"

    }
    namespace = kubernetes_namespace.tfc-agent.id
  }
  spec {
    selector {
      match_labels = {
        app = "tfc-agent"
      }
    }
    replicas = var.k8s_desired_agents
    template {
      metadata {
        labels = {
          app = "tfc-agent"
        }
      }
      spec {
        container {
          image = "hashicorp/tfc-agent:${var.tfc_agent_docker_image_tag}"
          name  = "tfc-agent"
          env {
            name  = "TFC_AGENT_TOKEN"
            value = var.agent_token
          }
          env {
            name  = "TFC_ADDRESS"
            value = "https://${local.tfe_hostname}"
          }
          env {
            name  = "TFC_AGENT_LOG_LEVEL"
            value = "trace"
          }
          resources {
            limits = {
              cpu    = "1"
              memory = "512Mi"
            }
            requests = {
              cpu    = "250m"
              memory = "50Mi"
            }
          }
        }
      }
    }
  }
  depends_on = [
    kubernetes_namespace.tfc-agent
  ]
} */

/* resource "aws_iam_role" "eks_s3_service" {
  name_prefix        = "${local.friendly_name_prefix}-eks_s3_service"
  assume_role_policy = data.aws_iam_policy_document.eks_s3.json
} */

# Service account name for TFE in helm-chart is `terraform-enterprise`
# https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
# https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html

# How to configure service accounts for pods
# https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/

# Projected volume storage use instead of service account ?
# https://kubernetes.io/docs/tasks/configure-pod-container/configure-projected-volume-storage/

data "aws_iam_policy_document" "eks_s3" {
  statement {
    actions = [
      "s3:ListBucket",
      "s3:ListBucketVersions"
    ]
    effect    = "Allow"
    resources = [aws_s3_bucket.tfe_data.arn]
  }

  statement {
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.tfe_data.arn}/*"]
  }
}

resource "aws_iam_policy" "eks_s3" {
  name   = "${local.friendly_name_prefix}-eks_s3"
  policy = data.aws_iam_policy_document.eks_s3.json
  # Policy for AWS EKS service account used for pods
}

data "aws_iam_policy_document" "tfe_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = ["system:serviceaccount:${local.tfe_k8s_namespace}:${local.tfe_k8s_namespace}"]
    }

    principals {
      identifiers = [module.eks.oidc_provider_arn]
      type        = "Federated"
    }
  }

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }

    principals {
      identifiers = [module.eks.oidc_provider_arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "tfe_pods_assume_role" {
  assume_role_policy = data.aws_iam_policy_document.tfe_assume_role_policy.json
  name               = "${local.friendly_name_prefix}-tfe-pods-assume-role"
}

resource "aws_iam_policy_attachment" "tfe_pods_assume_role" {
  name       = "${local.friendly_name_prefix}-tfe-pods-assume-role"
  roles      = [aws_iam_role.tfe_pods_assume_role.name]
  policy_arn = aws_iam_policy.eks_s3.arn
}

/* data "aws_iam_policy_document" "tfe_data" {
  statement {
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]
    effect = "Allow"
    principals {
      identifiers = [aws_iam_role.instance_role.arn]
      type        = "AWS"
    }
    resources = [aws_s3_bucket.tfe_data.arn]
    sid       = "AllowS3ListBucketData"
  }

  statement {
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    effect = "Allow"
    principals {
      identifiers = [aws_iam_role.instance_role.arn]
      type        = "AWS"
    }
    resources = ["${aws_s3_bucket.tfe_data.arn}/*"]
    sid       = "AllowS3ManagementData"
  }
} */

/* resource "aws_lb" "tfe_lb" {
  name               = "${local.friendly_name_prefix}-tfe-app-lb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.subnet_public1.id, aws_subnet.subnet_public2.id]
  security_groups    = [aws_security_group.lb_sg.id]
}

resource "aws_lb_target_group" "tfe_443" {
  name     = "${local.friendly_name_prefix}-tfe-tg-443"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    healthy_threshold   = 6
    unhealthy_threshold = 2
    timeout             = 2
    interval            = 5
    path                = "/_health_check"
    protocol            = "HTTPS"
    matcher             = "200-399"
  }
  stickiness {
    enabled = true
    type    = "lb_cookie"
  }
} */

# Adjust to k8s

/* resource "aws_lb_listener" "lb_443" {
  load_balancer_arn = aws_lb.tfe_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.lb_ssl_policy
  certificate_arn   = aws_acm_certificate.tfe.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tfe_443.arn
  }
}

resource "cloudflare_record" "tfe" {
  zone_id = var.cloudflare_zone_id
  name    = local.tfe_hostname
  type    = "CNAME"
  ttl     = 1
  value   = aws_lb.tfe_lb.dns_name
} */

resource "aws_elasticache_subnet_group" "tfe" {
  name       = "${local.friendly_name_prefix}-tfe-redis"
  subnet_ids = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
}

resource "aws_elasticache_replication_group" "redis" {
  node_type                  = var.instance_type_redis
  num_cache_clusters         = 1
  replication_group_id       = "${local.friendly_name_prefix}-tfe"
  description                = "Redis replication group for TFE"
  apply_immediately          = true
  auth_token                 = random_id.redis_password.hex
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  automatic_failover_enabled = false
  engine                     = "redis"
  engine_version             = "7.0"
  parameter_group_name       = "default.redis7"
  port                       = 6380
  subnet_group_name          = aws_elasticache_subnet_group.tfe.name
  multi_az_enabled           = false
  auto_minor_version_upgrade = true
  snapshot_retention_limit   = 0
  security_group_ids         = [aws_security_group.redis_sg.id]
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

# resource "kubernetes_namespace" "k8tz" {
#   metadata {
#     name = "k8tz"
#   }
#   depends_on = [
#     module.eks
#   ]
# }

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

/* resource "helm_release" "ingress-nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  cleanup_on_fail  = true
  replace          = true
  force_update     = true
  create_namespace = true
  version          = "4.7.1"
  depends_on       = [module.eks]
} */

/* resource "helm_release" "k8tz" {
  name             = "k8tz"
  repository       = "../k8tz/charts"
  chart            = "k8tz"
  namespace        = "k8tz"
  cleanup_on_fail  = true
  replace          = true
  force_update     = true
  create_namespace = false
  depends_on       = [module.eks, kubernetes_namespace.k8tz]
  version          = "0.13.1"

  set {
    name  = "timezone"
    value = "Europe/Amsterdam"
    type  = "string"
  }
} */

resource "helm_release" "terraform-enterprise" {
  name            = "terraform-enterprise"
  chart           = "../terraform-enterprise-helm"
  values          = [local.overrides-yaml]
  namespace       = kubernetes_namespace.terraform-enterprise.id
  cleanup_on_fail = true
  replace         = true
  force_update    = true
  version         = "0.1.2"
  wait            = false
  depends_on      = [module.eks, kubernetes_namespace.terraform-enterprise]
}

# Configure service accounts for pods
# https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
#
# AWS S3 config of TFE in source code https://github.com/hashicorp/terraform-enterprise/blob/main/config/config.go
#
# container for testing service account
#
# Create resource:
# resource "kubernetes_service_account" "terraform-enterprise-s3" {
#   metadata {
#     name      = "terraform-enterprise"
#     namespace = local.tfe_k8s_namespace
#     annotations = {
#       "eks.amazonaws.com/role-arn" : aws_iam_role.tfe_pods_assume_role.arn
#     }
#   }
#   depends_on = [kubernetes_namespace.terraform-enterprise]
# }

# resource "kubernetes_pod" "awsclitest" {
#   metadata {
#     name      = "awsclitest"
#     namespace = local.tfe_k8s_namespace
#   }
#   spec {
#     service_account_name = "terraform-enterprise"
#     container {
#       name  = "awsclitest"
#       image = "amazon/aws-cli:latest"
#       # Sleep so that the container stays alive
#       # #continuous-sleeping
#       command = ["/bin/bash", "-c", "--"]
#       args    = ["while true; do sleep 5; done;"]
#     }
#   }
#   depends_on = [kubernetes_namespace.terraform-enterprise]
# }

# Exec into the running pod
# $ kubectl -n terraform-enterprise exec -ti awsclitest -- /bin/bash
#
# Check the AWS Security Token Service identity
# $ aws sts get-caller-identity
# {
#     "UserId": "AROA46FON4H773JH4MPJD:botocore-session-1637837863",
#     "Account": "889424044543",
#     "Arn": "arn:aws:sts::889424044543:assumed-role/iam-role-test/botocore-session-1637837863"
# }
#
# Check the AWS environment variables
# bash-4.2# aws sts get-caller-identity
# {
#     "UserId": "AROATTLF7RR6EA6ET2EB5:botocore-session-1691689294",
#     "Account": "247711370364",
#     "Arn": "arn:aws:sts::247711370364:assumed-role/xxxx-cws8t6-tfe-pods-assume-role/botocore-session-1691689294"
# }
# bash-4.2# env | grep "AWS_"
# AWS_ROLE_ARN=arn:aws:iam::247711370364:role/xxxx-cws8t6-tfe-pods-assume-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
# AWS_DEFAULT_REGION=eu-north-1
# AWS_REGION=eu-north-1
# AWS_STS_REGIONAL_ENDPOINTS=regional
#
# IAM role for Service Account is supported from AWS SDK Go 1.23.13
#
# View ARN of the IAM role that pod is using:
# $ kubectl describe pod my-app-6f4dfff6cb-76cv9 | grep AWS_ROLE_ARN:
#
# AWS_ROLE_ARN:                 arn:aws:iam::111122223333:role/my-role
#
# Confirm that deployment is using service account:
# $ kubectl describe deployment my-app | grep "Service Account"
#
# Service Account:  my-service-account
#
# Helm get chart values
# helm -n terraform-enterprise get values terraform-enterprise
#

resource "kubernetes_pod" "awsclitest" {
  metadata {
    name      = "awsclitest"
    namespace = local.tfe_k8s_namespace
  }
  spec {
    service_account_name = kubernetes_service_account.terraform-enterprise-s3.metadata[0].name
    container {
      name  = "awsclitest"
      image = "amazon/aws-cli:latest"
      # Sleep so that the container stays alive
      # #continuous-sleeping
      command = ["/bin/bash", "-c", "--"]
      args    = ["while true; do sleep 5; done;"]
    }
  }
  depends_on = [kubernetes_service_account.terraform-enterprise-s3, kubernetes_namespace.terraform-enterprise]
}

resource "kubernetes_service_account" "terraform-enterprise-s3" {
  metadata {
    name      = "terraform-enterprise-s3"
    namespace = local.tfe_k8s_namespace
    annotations = {
      "eks.amazonaws.com/role-arn" : aws_iam_role.tfe_pods_assume_role.arn
    }
  }
  depends_on = [kubernetes_namespace.terraform-enterprise, module.eks]
}

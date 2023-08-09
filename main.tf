locals {
  friendly_name_prefix = "aakulov-${random_string.friendly_name.id}"
  tfe_hostname         = "${random_string.friendly_name.id}${var.tfe_hostname}"
  tfc_agent_user_data = templatefile(
    "templates/installagent.sh.tpl",
    {
      region           = var.region
      tfcagent_service = filebase64("files/tfc-agent.service")
      agent_token_id   = aws_secretsmanager_secret.agent_token.id
      tfe_hostname     = local.tfe_hostname
    }
  )
  values-yaml = templatefile(
    "templates/values.yaml.tpl",
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
    resources = [aws_secretsmanager_secret_version.tfe_license.secret_id, aws_secretsmanager_secret_version.tls_certificate.secret_id, aws_secretsmanager_secret_version.tls_key.secret_id, aws_secretsmanager_secret_version.tls_chain.secret_id, aws_secretsmanager_secret_version.agent_token.secret_id]
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

resource "aws_secretsmanager_secret" "tfe_license" {
  description             = "The TFE license"
  name                    = "${local.friendly_name_prefix}-tfe_license"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "tfe_license" {
  secret_binary = filebase64(var.tfe_license_path)
  secret_id     = aws_secretsmanager_secret.tfe_license.id
}

resource "aws_secretsmanager_secret" "tls_certificate" {
  description             = "TLS certificate"
  name                    = "${local.friendly_name_prefix}-tfe_certificate"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "tls_certificate" {
  secret_binary = filebase64(var.ssl_fullchain_cert_path)
  secret_id     = aws_secretsmanager_secret.tls_certificate.id
}

resource "aws_secretsmanager_secret" "tls_key" {
  description             = "TLS key"
  name                    = "${local.friendly_name_prefix}-tfe_key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "tls_key" {
  secret_binary = filebase64(var.ssl_key_path)
  secret_id     = aws_secretsmanager_secret.tls_key.id
}

resource "aws_secretsmanager_secret_version" "tls_chain" {
  secret_binary = filebase64(var.ssl_chain_path)
  secret_id     = aws_secretsmanager_secret.tls_chain.id
}

resource "aws_secretsmanager_secret" "tls_chain" {
  description             = "TLS chain"
  name                    = "${local.friendly_name_prefix}-tfe_chain"
  recovery_window_in_days = 0
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

resource "aws_s3_bucket_policy" "tfe_data" {
  bucket = aws_s3_bucket_public_access_block.tfe_data.bucket
  policy = data.aws_iam_policy_document.tfe_data.json
}

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
  version = "18.31.2"

  cluster_name    = "${local.friendly_name_prefix}-eks"
  cluster_version = "1.27"

  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true
  create_node_security_group      = true
  create_cluster_security_group   = true

  cluster_addons = {
    coredns = {
      resolve_conflicts_on_create = "PRESERVE"
      resolve_conflicts_on_update = "OVERWRITE"
    }
    kube-proxy = {
      resolve_conflicts_on_create = "PRESERVE"
      resolve_conflicts_on_update = "OVERWRITE"
    }
    vpc-cni = {
      resolve_conflicts_on_create = "PRESERVE"
      resolve_conflicts_on_update = "OVERWRITE"
    }
  }

  vpc_id     = aws_vpc.vpc.id
  subnet_ids = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]

  eks_managed_node_group_defaults = {
    ami_type                              = "AL2_x86_64"
    attach_cluster_primary_security_group = false
    create_security_group                 = true
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
    }
  }
}

data "aws_eks_cluster" "k8s" {
  name = module.eks.cluster_id
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

data "aws_iam_policy_document" "tfe_data" {
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
}

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
/* 
resource "kubernetes_service_account" "assumerole" {
  metadata {
    name      = "terraform-enterprise"
    namespace = kubernetes_namespace.terraform-enterprise.id
  }
} */

resource "helm_release" "ingress-nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  cleanup_on_fail  = true
  replace          = true
  force_update     = true
  create_namespace = true
  version          = "4.7.1"
}

resource "helm_release" "terraform-enterprise" {
  name            = "terraform-enterprise"
  chart           = "../terraform-enterprise-helm"
  values          = [local.values-yaml]
  namespace       = kubernetes_namespace.terraform-enterprise.id
  cleanup_on_fail = true
  replace         = true
  force_update    = true
  version         = "0.1.2"
  depends_on      = [helm_release.ingress-nginx]
}

/* data "aws_eks_cluster" "eks" {
  name = "${local.friendly_name_prefix}-eks"
} */

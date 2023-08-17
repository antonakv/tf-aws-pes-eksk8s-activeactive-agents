data "terraform_remote_state" "main" {
  backend = "local"

  config = {
    path = "../terraform.tfstate"
  }
}

provider "aws" {
  region = data.terraform_remote_state.main.outputs.region
}

data "aws_eks_cluster_auth" "cluster_auth" {
  name = module.eks.cluster_name
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.cluster_auth.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.cluster_auth.token
  }
  experiments {
    # show rendered helm values in the terraform plan
    manifest = false
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.16.0"

  cluster_name                                 = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks"
  cluster_version                              = "1.27"
  enable_irsa                                  = true
  cluster_endpoint_private_access              = true
  cluster_endpoint_public_access               = true
  node_security_group_enable_recommended_rules = false # overrides with custom ingress rules

  create_iam_role          = true
  iam_role_name            = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks-managed-node-group"
  iam_role_use_name_prefix = false

  iam_role_additional_policies = {
    AmazonEC2ContainerRegistryReadOnly = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    AmazonS3BucketReadWrite            = aws_iam_policy.eks_s3.arn
    # additional policy should match with role used for service account annotation in helm config
  }

  cluster_addons = {
    coredns = {
      #preserve                    = false
      resolve_conflicts_on_create = "NONE"
      resolve_conflicts_on_update = "OVERWRITE"
    }
    kube-proxy = {
      #preserve                    = false
      resolve_conflicts_on_create = "NONE"
      resolve_conflicts_on_update = "OVERWRITE"
    }
    vpc-cni = {
      #preserve                    = false
      resolve_conflicts_on_create = "NONE"
      resolve_conflicts_on_update = "OVERWRITE"
    }
  }

  # node_security_group_additional_rules = {
  #   ingress_self_all = {
  #     description = "Node to node all ports/protocols"
  #     protocol    = "-1"
  #     from_port   = 0
  #     to_port     = 0
  #     type        = "ingress"
  #     self        = true
  #   }
  #   egress_all = {
  #   description      = "Node all egress"
  #   protocol         = "-1"
  #   from_port        = 0
  #   to_port          = 0
  #   type             = "egress"
  #   cidr_blocks      = ["0.0.0.0/0"]
  #   ipv6_cidr_blocks = ["::/0"]
  # }
  # }

  vpc_id                   = data.terraform_remote_state.main.outputs.vpc_id
  subnet_ids               = [data.terraform_remote_state.main.outputs.subnet_private1_id, data.terraform_remote_state.main.outputs.subnet_private2_id]
  control_plane_subnet_ids = [data.terraform_remote_state.main.outputs.subnet_private1_id, data.terraform_remote_state.main.outputs.subnet_private2_id]

  eks_managed_node_group_defaults = {
    ami_type                              = "BOTTLEROCKET_x86_64"
    attach_cluster_primary_security_group = false
    # Should be false to avoid ingress attachment error: Multiple tagged security groups found for instance 
  }

  eks_managed_node_groups = {
    first = {
      name = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-ng-1"

      instance_types = [var.instance_type]
      disk_size      = 50

      min_size     = 1
      max_size     = 3
      desired_size = 3

      vpc_security_group_ids = [
        data.terraform_remote_state.main.outputs.internal_sg_id
      ]
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "optional"
        http_put_response_hop_limit = 2
        # Limit=1 is forcing nodes to use IMDSv2 only 
        # Do not disable instance metadata `http_put_response_hop_limit = 1` as this can prevent components like the node 
        # termination handler and other things that rely on instance metadata from working properly.
        # https://aws.github.io/aws-eks-best-practices/security/docs/iam/#restrict-access-to-the-instance-profile-assigned-to-the-worker-node
        instance_metadata_tags = "enabled"
      }
    }
  }
}

data "aws_iam_policy_document" "tfe_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = ["system:serviceaccount:${var.tfe_k8s_namespace_name}:${var.tfe_k8s_serviceaccount_name}"]
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
  name               = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-tfe-pods-assume-role"
}

resource "aws_iam_policy_attachment" "tfe_pods_assume_role" {
  name       = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-tfe-pods-assume-role"
  roles      = [aws_iam_role.tfe_pods_assume_role.name]
  policy_arn = aws_iam_policy.eks_s3.arn
}

resource "aws_iam_policy" "eks_s3" {
  name   = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks_s3"
  policy = data.aws_iam_policy_document.eks_s3.json
  # Policy for AWS EKS service account used for pods
}

data "aws_iam_policy_document" "eks_s3" {
  statement {
    actions = [
      "s3:ListBucket",
      "s3:ListBucketVersions"
    ]
    effect    = "Allow"
    resources = [data.terraform_remote_state.main.outputs.aws_s3_bucket_arn]
  }

  statement {
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    effect    = "Allow"
    resources = ["${data.terraform_remote_state.main.outputs.aws_s3_bucket_arn}/*"]
  }
}

resource "helm_release" "ingress-nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  cleanup_on_fail  = true
  replace          = true
  force_update     = true
  create_namespace = false
  version          = "4.7.1"
  wait             = true
  wait_for_jobs    = true
  verify           = false # doesn't work with ingress-nginx chart
  timeout          = 400
  depends_on       = [kubernetes_namespace.ingress-nginx]
}

resource "kubernetes_namespace" "ingress-nginx" {
  metadata {
    name = "ingress-nginx"
  }
  depends_on = [module.eks]
}

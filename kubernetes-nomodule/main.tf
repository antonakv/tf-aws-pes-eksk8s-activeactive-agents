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
  name = aws_eks_cluster.k8s.name
}

provider "kubernetes" {
  host                   = aws_eks_cluster.k8s.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.k8s.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster_auth.token
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.k8s.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.k8s.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.cluster_auth.token
  }
  experiments {
    # show rendered helm values in the terraform plan
    manifest = false
  }
}

# Create Amazon EKS cluster IAM role

data "aws_iam_policy_document" "eks_cluster_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eks_cluster_assume_role" {
  name               = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks-cluster-assume-role"
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume_role.json
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_assume_role.name
}

# Create EKS cluster

resource "aws_eks_cluster" "k8s" {
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
  name                      = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks"
  role_arn                  = aws_iam_role.eks_cluster_assume_role.arn
  version                   = "1.27"
  /*   encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_kms.arn
    }
  } */
  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "172.16.0.0/16"
  }
  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
    security_group_ids      = [data.terraform_remote_state.main.outputs.internal_sg_id]
    subnet_ids              = [data.terraform_remote_state.main.outputs.subnet_private1_id, data.terraform_remote_state.main.outputs.subnet_private2_id]
  }
  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.AmazonEKSVPCResourceController,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy
  ]
}

resource "aws_eks_node_group" "ng-1" {
  ami_type        = "BOTTLEROCKET_x86_64"
  capacity_type   = "ON_DEMAND"
  cluster_name    = aws_eks_cluster.k8s.name
  instance_types  = [var.instance_type]
  disk_size       = 50
  node_group_name = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks-ng-1"
  node_role_arn   = aws_iam_role.eks_nodegroup_assume_role.arn
  subnet_ids      = [data.terraform_remote_state.main.outputs.subnet_private1_id, data.terraform_remote_state.main.outputs.subnet_private2_id]
  version         = "1.27"
  scaling_config {
    desired_size = var.k8s_desired_nodes
    max_size     = var.k8s_max_nodes
    min_size     = var.k8s_min_nodes
  }
  update_config {
    max_unavailable_percentage = 33
  }
  depends_on = [
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
    aws_iam_role_policy_attachment.AmazonS3BucketReadWrite
    #    aws_iam_role_policy_attachment.ClusterEncryption
  ]
}

data "aws_eks_addon_version" "kube-proxy" {
  addon_name         = "kube-proxy"
  kubernetes_version = aws_eks_cluster.k8s.version
  most_recent        = true
}

resource "aws_eks_addon" "kube-proxy" {
  cluster_name                = aws_eks_cluster.k8s.name
  addon_name                  = "kube-proxy"
  addon_version               = data.aws_eks_addon_version.kube-proxy.version
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.ng-1]
}

data "aws_eks_addon_version" "vpc-cni" {
  addon_name         = "vpc-cni"
  kubernetes_version = aws_eks_cluster.k8s.version
  most_recent        = true
}

resource "aws_eks_addon" "vpc-cni" {
  cluster_name                = aws_eks_cluster.k8s.name
  addon_name                  = "vpc-cni"
  addon_version               = data.aws_eks_addon_version.vpc-cni.version
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.ng-1]
  # service_account_role_arn = ""
}

/*
data "aws_eks_addon_version" "coredns" {
  addon_name         = "coredns"
  kubernetes_version = aws_eks_cluster.k8s.version
  most_recent        = true
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.k8s.name
  addon_name                  = "coredns"
  addon_version               = data.aws_eks_addon_version.coredns.version
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.ng-1]
} */

data "tls_certificate" "oidc" {
  url = aws_eks_cluster.k8s.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "oidc" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.k8s.identity[0].oidc[0].issuer
}

/* resource "aws_iam_policy" "eks_kms" {
  name   = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks-kms"
  policy = data.aws_iam_policy_document.eks_kms.json
}

data "aws_iam_policy_document" "eks_kms" {
  statement {
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ListGrants",
      "kms:DescribeKey"
    ]
    effect    = "Allow"
    resources = [aws_kms_key.eks_kms.arn]
  }
} */

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodegroup_assume_role.name
}

/* resource "aws_iam_role_policy_attachment" "ClusterEncryption" {
  policy_arn = aws_iam_policy.eks_kms.arn
  role       = aws_iam_role.eks_nodegroup_assume_role.name
} */

resource "aws_iam_role_policy_attachment" "AmazonS3BucketReadWrite" {
  policy_arn = aws_iam_policy.eks_s3.arn
  role       = aws_iam_role.tfe_pods_assume_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodegroup_assume_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodegroup_assume_role.name
}

# AmazonEKSVPCResourceController policy allows the role to manage network interfaces, their private IP addresses, 
# and their attachment and detachment to and from network instances. 

# Enable the Amazon VPC CNI add-on to manage network interfaces for Pods by setting the ENABLE_POD_ENI variable to true 
# in the aws-node DaemonSet. Once this setting is set to true, for each node in the cluster the add-on adds a label with 
# the value vpc.amazonaws.com/has-trunk-attached=true. The VPC resource controller creates and attaches one special network 
# interface called a trunk network interface with the description aws-k8s-trunk-eni.

resource "aws_iam_role_policy_attachment" "AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster_assume_role.name
}

data "aws_iam_policy_document" "eks_nodegroup_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_nodegroup_assume_role" {
  force_detach_policies = true
  assume_role_policy    = data.aws_iam_policy_document.eks_nodegroup_assume_role.json
  name                  = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks-managed-node-group"
}

data "aws_iam_policy_document" "tfe_pods_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.k8s.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:${var.tfe_k8s_namespace_name}:${var.tfe_k8s_serviceaccount_name}"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.oidc.arn]
      type        = "Federated"
    }
  }

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.k8s.identity[0].oidc[0].issuer, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.oidc.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "tfe_pods_assume_role" {
  assume_role_policy = data.aws_iam_policy_document.tfe_pods_assume_role_policy.json
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

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "eks_kms_cluster" {
  statement {
    actions = [
      "kms:Update*",
      "kms:UntagResource",
      "kms:TagResource",
      "kms:ScheduleKeyDeletion",
      "kms:Revoke*",
      "kms:Put*",
      "kms:List*",
      "kms:Get*",
      "kms:Enable*",
      "kms:Disable*",
      "kms:Describe*",
      "kms:Delete*",
      "kms:Create*",
      "kms:CancelKeyDeletion"
    ]
    effect    = "Allow"
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.arn]
    }
  }
  statement {
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    effect    = "Allow"
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.eks_nodegroup_assume_role.arn]
    }
  }
}

/* resource "aws_kms_key" "eks_kms" {
  description              = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks-cluster"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  multi_region             = false
  policy                   = data.aws_iam_policy_document.eks_kms_cluster.json
} */

###

# https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html

/* data "aws_iam_policy_document" "AmazonEKSLoadBalancerControllerRole" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.k8s.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.oidc_provider[0].arn]
      type        = "Federated"
    }
  }

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.k8s.identity[0].oidc[0].issuer, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.oidc_provider[0].arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "AmazonEKSLoadBalancerControllerRole" {
  assume_role_policy = data.aws_iam_policy_document.AmazonEKSLoadBalancerControllerRole.json
  name               = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-eks-lb-controller-role"
}

resource "aws_iam_role_policy_attachment" "AmazonEKSLoadBalancerControllerRole" {
  name       = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-AmazonEKSLoadBalancerControllerRole"
  policy_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/AWSLoadBalancerControllerIAMPolicy"
  role       = aws_iam_role.AmazonEKSLoadBalancerControllerRole.name
} */


/* resource "helm_release" "ingress-nginx" {
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
  depends_on = [aws_eks_cluster.k8s]
} */


/* data "aws_iam_policy_document" "vpc_cni" {
  count = var.create_role && var.attach_vpc_cni_policy ? 1 : 0

  # arn:${local.partition}:iam::aws:policy/AmazonEKS_CNI_Policy
  dynamic "statement" {
    for_each = var.vpc_cni_enable_ipv4 ? [1] : []
    content {
      sid = "IPV4"
      actions = [
        "ec2:AssignPrivateIpAddresses",
        "ec2:AttachNetworkInterface",
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeInstances",
        "ec2:DescribeTags",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstanceTypes",
        "ec2:DetachNetworkInterface",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:UnassignPrivateIpAddresses",
      ]
      resources = ["*"]
    }
  }

  # https://docs.aws.amazon.com/eks/latest/userguide/cni-iam-role.html#cni-iam-role-create-ipv6-policy
  dynamic "statement" {
    for_each = var.vpc_cni_enable_ipv6 ? [1] : []
    content {
      sid = "IPV6"
      actions = [
        "ec2:AssignIpv6Addresses",
        "ec2:DescribeInstances",
        "ec2:DescribeTags",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstanceTypes",
      ]
      resources = ["*"]
    }
  }

  statement {
    sid       = "CreateTags"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:*:*:network-interface/*"]
  }
} */


/* resource "aws_iam_policy" "vpc_cni" {
  count = var.create_role && var.attach_vpc_cni_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}CNI_Policy-"
  path        = var.role_path
  description = "Provides the Amazon VPC CNI Plugin (amazon-vpc-cni-k8s) the permissions it requires to modify the IPv4/IPv6 address configuration on your EKS worker nodes"
  policy      = data.aws_iam_policy_document.vpc_cni[0].json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "vpc_cni" {
  count = var.create_role && var.attach_vpc_cni_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.vpc_cni[0].arn
} */

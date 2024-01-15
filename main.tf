locals {
  friendly_name_prefix = "aakulov-${random_string.friendly_name.id}"
}

provider "aws" {
  region = var.region
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

  # ingress {
  #   from_port       = 443
  #   to_port         = 443
  #   protocol        = "tcp"
  #   security_groups = [aws_security_group.lb_sg.id]
  #   description     = "allow https port incoming connection from Load balancer"
  # }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    self        = true
    description = "Allow postgres port incoming connections"
  }

  /*   ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.node.id]
    description     = "Allow connection to postgres from eks worker nodes"
  }

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
    description     = "Allow connection to postgres from eks cluster nodes"
  } */

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    self        = true
    description = "Allow https port incoming connection"
  }

  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    self        = true
    description = "EKS Cluster API to EKS node kubelets"
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    self        = true
    description = "DNS tcp"
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    self        = true
    description = "DNS udp"
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

/* resource "aws_security_group" "cluster" {
  description = "EKS cluster security group"
  name        = "${local.friendly_name_prefix}-eks-cluster"
  vpc_id      = aws_vpc.vpc.id
}

resource "aws_security_group" "node" {
  description = "EKS node shared security group"
  name        = "${local.friendly_name_prefix}-eks-node"
  vpc_id      = aws_vpc.vpc.id
}

resource "aws_security_group_rule" "node" {
  description              = "Cluster API to node groups"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.node.id
  source_security_group_id = aws_security_group.cluster.id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "cluster" {
  description              = "Node groups to cluster API"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.cluster.id
  source_security_group_id = aws_security_group.node.id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "node_kublets" {
  description              = "Node groups to cluster API"
  from_port                = 10250
  protocol                 = "tcp"
  security_group_id        = aws_security_group.node.id
  source_security_group_id = aws_security_group.cluster.id
  to_port                  = 10250
  type                     = "ingress"
}

resource "aws_security_group_rule" "node_coredns" {
  description       = "Node groups to cluster API"
  from_port         = 53
  protocol          = "tcp"
  security_group_id = aws_security_group.node.id
  self              = true
  to_port           = 53
  type              = "ingress"
}

resource "aws_security_group_rule" "node_coredns_udp" {
  description       = "Node groups to cluster API udp"
  from_port         = 53
  protocol          = "udp"
  security_group_id = aws_security_group.node.id
  self              = true
  to_port           = 53
  type              = "ingress"
} */

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

  /*   ingress {
    from_port       = 6379
    to_port         = 6380
    protocol        = "tcp"
    security_groups = [aws_security_group.node.id]
  }

  ingress {
    from_port       = 6379
    to_port         = 6380
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  } */

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outgoing connections for redis"
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

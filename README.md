# tf-aws-pes-eksk8s-activeactive-agents
Terraform Terraform Enterprise FDO PES K8s on AWS EKS Active Active with Agents

This manual is dedicated to install Terraform Enterprise FDO beta (not for production use) using customized Helm chart.
Terraform-aws-modules/eks/aws module used for K8S cluster provisioning.
EC2 instance based terraform agents can be added using AWS Autoscaling group.

## Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Configured CloudFlare DNS zone for domain `my-domain-here.com`
[Cloudflare DNS zone setup](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/)

- SSL certificate and SSL key files for the corresponding domain name
[Certbot manual](https://certbot.eff.org/instructions)

- Created Amazon EC2 key pair for Linux instance
[Creating a public hosted zone](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

## Preparation 

- Clone git repository

```bash
git clone https://github.com/antonakv/tf-aws-pes-eksk8s-activeactive-agents.git
```
Example output:

```bash
Cloning into 'tf-aws-pes-eksk8s-activeactive-agents'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```

- Change folder to tf-aws-pes-eksk8s-activeactive-agents

```bash
cd tf-aws-pes-eksk8s-activeactive-agents
```

- Create file terraform.tfvars with following contents

```
region                  = "eu-north-1"
cidr_vpc                = "10.5.0.0/16"
cidr_subnet_private_1   = "10.5.1.0/24"
cidr_subnet_private_2   = "10.5.2.0/24"
cidr_subnet_public_1    = "10.5.3.0/24"
cidr_subnet_public_2    = "10.5.4.0/24"
key_name                = "PUT_YOUR_KEY_NAME_HERE"
db_instance_type        = "db.t3.xlarge"
instance_type_redis     = "cache.t3.medium"
postgres_db_name        = "mydbtfe"
postgres_engine_version = "14.4"
postgres_username       = "postgres"
aws_az_1                = "eu-north-1b"
aws_az_2                = "eu-north-1c"

```

## Run terraform code for provisioning of base infrastructure

- Initialize terraform providers

```bash
terraform init
```

Sample result:

```bash
% terraform init                  

Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/local from the dependency lock file
- Reusing previous version of hashicorp/random from the dependency lock file
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/template from the dependency lock file
- Using previously-installed hashicorp/local v2.4.0
- Using previously-installed hashicorp/random v3.5.1
- Using previously-installed hashicorp/aws v5.12.0
- Using previously-installed hashicorp/template v2.2.0

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

- Run the `terraform apply`

```bash
terraform apply 
```

Sample result:

```bash
 % terraform apply --auto-approve

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_db_instance.tfe will be created
  + resource "aws_db_instance" "tfe" {
      + address                               = (known after apply)
      + allocated_storage                     = 20
      + allow_major_version_upgrade           = true
      + apply_immediately                     = true
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = (known after apply)
      + backup_target                         = (known after apply)
      + backup_window                         = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_name                               = "mydbtfe"
      + db_subnet_group_name                  = (known after apply)
      + delete_automated_backups              = true
      + deletion_protection                   = false
      + endpoint                              = (known after apply)
      + engine                                = "postgres"
      + engine_version                        = "14.4"
      + engine_version_actual                 = (known after apply)
      + hosted_zone_id                        = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = (known after apply)
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t3.xlarge"
      + iops                                  = (known after apply)
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + listener_endpoint                     = (known after apply)
      + maintenance_window                    = (known after apply)
      + master_user_secret                    = (known after apply)
      + master_user_secret_kms_key_id         = (known after apply)
      + max_allocated_storage                 = 100
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = (known after apply)
      + nchar_character_set_name              = (known after apply)
      + network_type                          = (known after apply)
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + password                              = (sensitive value)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = 5432
      + publicly_accessible                   = false
      + replica_mode                          = (known after apply)
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = true
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_throughput                    = (known after apply)
      + storage_type                          = "gp2"
      + tags                                  = (known after apply)
      + tags_all                              = (known after apply)
      + timezone                              = (known after apply)
      + username                              = "postgres"
      + vpc_security_group_ids                = (known after apply)
    }

  # aws_db_subnet_group.tfe will be created
  + resource "aws_db_subnet_group" "tfe" {
      + arn                     = (known after apply)
      + description             = "Managed by Terraform"
      + id                      = (known after apply)
      + name                    = (known after apply)
      + name_prefix             = (known after apply)
      + subnet_ids              = (known after apply)
      + supported_network_types = (known after apply)
      + tags                    = (known after apply)
      + tags_all                = (known after apply)
      + vpc_id                  = (known after apply)
    }

  # aws_eip.aws_nat will be created
  + resource "aws_eip" "aws_nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = "vpc"
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags_all             = (known after apply)
      + vpc                  = (known after apply)
    }

  # aws_elasticache_replication_group.redis will be created
  + resource "aws_elasticache_replication_group" "redis" {
      + apply_immediately              = true
      + arn                            = (known after apply)
      + at_rest_encryption_enabled     = true
      + auth_token                     = (sensitive value)
      + auto_minor_version_upgrade     = "true"
      + automatic_failover_enabled     = false
      + cluster_enabled                = (known after apply)
      + configuration_endpoint_address = (known after apply)
      + data_tiering_enabled           = (known after apply)
      + description                    = "Redis replication group for TFE"
      + engine                         = "redis"
      + engine_version                 = "7.0"
      + engine_version_actual          = (known after apply)
      + global_replication_group_id    = (known after apply)
      + id                             = (known after apply)
      + maintenance_window             = (known after apply)
      + member_clusters                = (known after apply)
      + multi_az_enabled               = false
      + node_type                      = "cache.t3.medium"
      + num_cache_clusters             = 1
      + num_node_groups                = (known after apply)
      + parameter_group_name           = "default.redis7"
      + port                           = 6380
      + primary_endpoint_address       = (known after apply)
      + reader_endpoint_address        = (known after apply)
      + replicas_per_node_group        = (known after apply)
      + replication_group_id           = (known after apply)
      + security_group_ids             = (known after apply)
      + security_group_names           = (known after apply)
      + snapshot_retention_limit       = 0
      + snapshot_window                = (known after apply)
      + subnet_group_name              = (known after apply)
      + tags_all                       = (known after apply)
      + transit_encryption_enabled     = true
    }

  # aws_elasticache_subnet_group.tfe will be created
  + resource "aws_elasticache_subnet_group" "tfe" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = (known after apply)
      + subnet_ids  = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_internet_gateway.igw will be created
  + resource "aws_internet_gateway" "igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = (known after apply)
      + tags_all = (known after apply)
      + vpc_id   = (known after apply)
    }

  # aws_nat_gateway.nat will be created
  + resource "aws_nat_gateway" "nat" {
      + allocation_id                      = (known after apply)
      + association_id                     = (known after apply)
      + connectivity_type                  = "public"
      + id                                 = (known after apply)
      + network_interface_id               = (known after apply)
      + private_ip                         = (known after apply)
      + public_ip                          = (known after apply)
      + secondary_private_ip_address_count = (known after apply)
      + secondary_private_ip_addresses     = (known after apply)
      + subnet_id                          = (known after apply)
      + tags                               = (known after apply)
      + tags_all                           = (known after apply)
    }

  # aws_route_table.private will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + core_network_arn           = ""
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = (known after apply)
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = (known after apply)
      + tags_all         = (known after apply)
      + vpc_id           = (known after apply)
    }

  # aws_route_table.public will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + core_network_arn           = ""
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = (known after apply)
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = ""
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = (known after apply)
      + tags_all         = (known after apply)
      + vpc_id           = (known after apply)
    }

  # aws_route_table_association.private1 will be created
  + resource "aws_route_table_association" "private1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.private2 will be created
  + resource "aws_route_table_association" "private2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.public1 will be created
  + resource "aws_route_table_association" "public1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.public2 will be created
  + resource "aws_route_table_association" "public2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_s3_bucket.tfe_data will be created
  + resource "aws_s3_bucket" "tfe_data" {
      + acceleration_status         = (known after apply)
      + acl                         = (known after apply)
      + arn                         = (known after apply)
      + bucket                      = (known after apply)
      + bucket_domain_name          = (known after apply)
      + bucket_prefix               = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + object_lock_enabled         = (known after apply)
      + policy                      = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags_all                    = (known after apply)
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)
    }

  # aws_s3_bucket_public_access_block.tfe_data will be created
  + resource "aws_s3_bucket_public_access_block" "tfe_data" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_s3_bucket_versioning.tfe_data will be created
  + resource "aws_s3_bucket_versioning" "tfe_data" {
      + bucket = (known after apply)
      + id     = (known after apply)

      + versioning_configuration {
          + mfa_delete = (known after apply)
          + status     = "Enabled"
        }
    }

  # aws_security_group.internal_sg will be created
  + resource "aws_security_group" "internal_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow all the icmp types"
              + from_port        = -1
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "icmp"
              + security_groups  = []
              + self             = false
              + to_port          = -1
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow netdata port"
              + from_port        = 19999
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 19999
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow ssh port 22"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "Allow netdata port from public security group"
              + from_port        = 19999
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 19999
            },
          + {
              + cidr_blocks      = []
              + description      = "Allow ssh port 22 from public security group"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = []
              + description      = "allow Vault HA request forwarding"
              + from_port        = 8201
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 8201
            },
          + {
              + cidr_blocks      = []
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "allow postgres port incoming connections"
              + from_port        = 5432
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 5432
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.public_sg will be created
  + resource "aws_security_group" "public_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow http port incoming connection"
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow netdata port 19999"
              + from_port        = 19999
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 19999
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow ssh port 22"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.redis_sg will be created
  + resource "aws_security_group" "redis_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 6379
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 6380
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_subnet.subnet_private1 will be created
  + resource "aws_subnet" "subnet_private1" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.1.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_private2 will be created
  + resource "aws_subnet" "subnet_private2" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.2.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_public1 will be created
  + resource "aws_subnet" "subnet_public1" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.3.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_public2 will be created
  + resource "aws_subnet" "subnet_public2" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.4.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_vpc.vpc will be created
  + resource "aws_vpc" "vpc" {
      + arn                                  = (known after apply)
      + cidr_block                           = "10.5.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_dns_hostnames                 = true
      + enable_dns_support                   = true
      + enable_network_address_usage_metrics = (known after apply)
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = (known after apply)
      + tags_all                             = (known after apply)
    }

  # aws_vpc_endpoint.s3 will be created
  + resource "aws_vpc_endpoint" "s3" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + ip_address_type       = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = false
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-north-1.s3"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags_all              = (known after apply)
      + vpc_endpoint_type     = "Gateway"
      + vpc_id                = (known after apply)
    }

  # aws_vpc_endpoint_route_table_association.private_s3_endpoint will be created
  + resource "aws_vpc_endpoint_route_table_association" "private_s3_endpoint" {
      + id              = (known after apply)
      + route_table_id  = (known after apply)
      + vpc_endpoint_id = (known after apply)
    }

  # random_id.redis_password will be created
  + resource "random_id" "redis_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_string.friendly_name will be created
  + resource "random_string" "friendly_name" {
      + id          = (known after apply)
      + length      = 6
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = false
    }

  # random_string.pgsql_password will be created
  + resource "random_string" "pgsql_password" {
      + id          = (known after apply)
      + length      = 24
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

Plan: 29 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_s3_bucket_arn    = (known after apply)
  + aws_s3_bucket_name   = (known after apply)
  + friendly_name_id     = (known after apply)
  + friendly_name_prefix = (known after apply)
  + internal_sg_id       = (known after apply)
  + postgres_db_name     = "mydbtfe"
  + postgres_endpoint    = (known after apply)
  + postgres_password    = (sensitive value)
  + postgres_username    = "postgres"
  + public_sg_id         = (known after apply)
  + redis_host           = (known after apply)
  + redis_password       = (known after apply)
  + region               = "eu-north-1"
  + ssh_key_name         = "aakulov2"
  + subnet_private1_id   = (known after apply)
  + subnet_private2_id   = (known after apply)
  + subnet_public1_id    = (known after apply)
  + subnet_public2_id    = (known after apply)
  + vpc_id               = (known after apply)
random_id.redis_password: Creating...
random_string.pgsql_password: Creating...
random_string.friendly_name: Creating...
random_id.redis_password: Creation complete after 0s [id=It_AgQ6vvHWDVrzLw0Epiw]
random_string.pgsql_password: Creation complete after 0s [id=agwU3kGN7TOmznU6GBaMRXEa]
random_string.friendly_name: Creation complete after 0s [id=pwpjfq]
aws_vpc.vpc: Creating...
aws_s3_bucket.tfe_data: Creating...
aws_s3_bucket.tfe_data: Creation complete after 2s [id=aakulov-pwpjfq-tfe-data]
aws_s3_bucket_public_access_block.tfe_data: Creating...
aws_s3_bucket_versioning.tfe_data: Creating...
aws_s3_bucket_public_access_block.tfe_data: Creation complete after 0s [id=aakulov-pwpjfq-tfe-data]
aws_s3_bucket_versioning.tfe_data: Creation complete after 2s [id=aakulov-pwpjfq-tfe-data]
aws_vpc.vpc: Still creating... [10s elapsed]
aws_vpc.vpc: Creation complete after 12s [id=vpc-004d7d76e8854003a]
aws_internet_gateway.igw: Creating...
aws_subnet.subnet_public2: Creating...
aws_subnet.subnet_public1: Creating...
aws_subnet.subnet_private2: Creating...
aws_subnet.subnet_private1: Creating...
aws_vpc_endpoint.s3: Creating...
aws_security_group.public_sg: Creating...
aws_internet_gateway.igw: Creation complete after 1s [id=igw-01303cfa6bef891bf]
aws_eip.aws_nat: Creating...
aws_route_table.public: Creating...
aws_subnet.subnet_public1: Creation complete after 1s [id=subnet-089b9dedd25d06aba]
aws_subnet.subnet_public2: Creation complete after 1s [id=subnet-0f1d8d07cc56cbb13]
aws_subnet.subnet_private1: Creation complete after 1s [id=subnet-0746808c2389800b2]
aws_subnet.subnet_private2: Creation complete after 1s [id=subnet-092125954f3c87d13]
aws_elasticache_subnet_group.tfe: Creating...
aws_db_subnet_group.tfe: Creating...
aws_eip.aws_nat: Creation complete after 0s [id=eipalloc-0fc4ec21aee617e13]
aws_nat_gateway.nat: Creating...
aws_route_table.public: Creation complete after 1s [id=rtb-0fab82fbd8f145f9d]
aws_route_table_association.public1: Creating...
aws_route_table_association.public2: Creating...
aws_route_table_association.public1: Creation complete after 0s [id=rtbassoc-0508281faccfb029d]
aws_route_table_association.public2: Creation complete after 0s [id=rtbassoc-0e2c467ff7e9f4667]
aws_elasticache_subnet_group.tfe: Creation complete after 1s [id=aakulov-pwpjfq-tfe-redis]
aws_security_group.public_sg: Creation complete after 2s [id=sg-0655ee8e76ea71314]
aws_security_group.internal_sg: Creating...
aws_db_subnet_group.tfe: Creation complete after 1s [id=aakulov-pwpjfq-db-subnet]
aws_security_group.internal_sg: Creation complete after 3s [id=sg-07a5cb9b652511b71]
aws_security_group.redis_sg: Creating...
aws_db_instance.tfe: Creating...
aws_vpc_endpoint.s3: Creation complete after 6s [id=vpce-0c6091d784738f3d4]
aws_security_group.redis_sg: Creation complete after 2s [id=sg-03140916231178267]
aws_elasticache_replication_group.redis: Creating...
aws_nat_gateway.nat: Still creating... [10s elapsed]
aws_db_instance.tfe: Still creating... [10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [10s elapsed]
aws_nat_gateway.nat: Still creating... [20s elapsed]
aws_db_instance.tfe: Still creating... [20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [20s elapsed]
aws_nat_gateway.nat: Still creating... [30s elapsed]
aws_db_instance.tfe: Still creating... [30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [30s elapsed]
aws_nat_gateway.nat: Still creating... [40s elapsed]
aws_db_instance.tfe: Still creating... [40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [40s elapsed]
aws_nat_gateway.nat: Still creating... [50s elapsed]
aws_db_instance.tfe: Still creating... [50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [50s elapsed]
aws_nat_gateway.nat: Still creating... [1m0s elapsed]
aws_db_instance.tfe: Still creating... [1m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m0s elapsed]
aws_nat_gateway.nat: Still creating... [1m10s elapsed]
aws_db_instance.tfe: Still creating... [1m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m10s elapsed]
aws_nat_gateway.nat: Still creating... [1m20s elapsed]
aws_db_instance.tfe: Still creating... [1m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m20s elapsed]
aws_nat_gateway.nat: Still creating... [1m30s elapsed]
aws_db_instance.tfe: Still creating... [1m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m30s elapsed]
aws_nat_gateway.nat: Still creating... [1m40s elapsed]
aws_db_instance.tfe: Still creating... [1m40s elapsed]
aws_nat_gateway.nat: Creation complete after 1m45s [id=nat-08b58107702dd0909]
aws_route_table.private: Creating...
aws_route_table.private: Creation complete after 1s [id=rtb-0202bc834e4c1957f]
aws_route_table_association.private1: Creating...
aws_vpc_endpoint_route_table_association.private_s3_endpoint: Creating...
aws_route_table_association.private2: Creating...
aws_elasticache_replication_group.redis: Still creating... [1m40s elapsed]
aws_route_table_association.private2: Creation complete after 0s [id=rtbassoc-039560dfef47a2256]
aws_vpc_endpoint_route_table_association.private_s3_endpoint: Creation complete after 0s [id=a-vpce-0c6091d784738f3d41780673423]
aws_route_table_association.private1: Creation complete after 0s [id=rtbassoc-0a0d67463659b60dd]
aws_db_instance.tfe: Still creating... [1m50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m50s elapsed]
aws_db_instance.tfe: Still creating... [2m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m0s elapsed]
aws_db_instance.tfe: Still creating... [2m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m10s elapsed]
aws_db_instance.tfe: Still creating... [2m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m20s elapsed]
aws_db_instance.tfe: Still creating... [2m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m30s elapsed]
aws_db_instance.tfe: Still creating... [2m40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m40s elapsed]
aws_db_instance.tfe: Still creating... [2m50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m50s elapsed]
aws_db_instance.tfe: Still creating... [3m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m0s elapsed]
aws_db_instance.tfe: Still creating... [3m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m10s elapsed]
aws_db_instance.tfe: Creation complete after 3m16s [id=db-2Z5CE6OLPHHCEFKTLD3VKYESSI]
aws_elasticache_replication_group.redis: Still creating... [3m20s elapsed]

[...]

aws_elasticache_replication_group.redis: Still creating... [9m0s elapsed]
aws_elasticache_replication_group.redis: Creation complete after 9m7s [id=aakulov-pwpjfq-tfe]

Apply complete! Resources: 29 added, 0 changed, 0 destroyed.

Outputs:

aws_s3_bucket_arn = "arn:aws:s3:::aakulov-pwpjfq-tfe-data"
aws_s3_bucket_name = "aakulov-pwpjfq-tfe-data"
friendly_name_id = "pwpjfq"
friendly_name_prefix = "aakulov-pwpjfq"
internal_sg_id = "sg-07a5cb9b652511b71"
postgres_db_name = "mydbtfe"
postgres_endpoint = "terraform-20230817142935834700000003.cxlk5utpl18k.eu-north-1.rds.amazonaws.com:5432"
postgres_password = <sensitive>
postgres_username = "postgres"
public_sg_id = "sg-0655ee8e76ea71314"
redis_host = "master.aakulov-pwpjfq-tfe.ih5hb7.eun1.cache.amazonaws.com"
redis_password = "22dfc0810eafbc758356bccbc341298b"
region = "eu-north-1"
ssh_key_name = "aakulov2"
subnet_private1_id = "subnet-0746808c2389800b2"
subnet_private2_id = "subnet-092125954f3c87d13"
subnet_public1_id = "subnet-089b9dedd25d06aba"
subnet_public2_id = "subnet-0f1d8d07cc56cbb13"
vpc_id = "vpc-004d7d76e8854003a"
```

- Change folder to tf-aws-pes-eksk8s-activeactive-agents/kubernetes

```bash
cd kubernetes
```

- Create file terraform.tfvars with following contents

```
instance_type               = "t3.2xlarge"
tfe_k8s_namespace_name      = "terraform-enterprise"
tfe_k8s_serviceaccount_name = "terraform-enterprise"
k8s_min_nodes               = 3
k8s_max_nodes               = 3
k8s_desired_nodes           = 3
```

- Run the `terraform apply`

```bash
terraform apply 
```

Sample result:

```bash
% terraform apply --auto-approve
data.terraform_remote_state.main: Reading...
data.terraform_remote_state.main: Read complete after 0s
module.eks.module.eks_managed_node_group["first"].data.aws_partition.current: Reading...
module.eks.data.aws_caller_identity.current: Reading...
module.eks.data.aws_partition.current: Reading...
data.aws_iam_policy_document.eks_s3: Reading...
module.eks.module.kms.data.aws_partition.current: Reading...
module.eks.module.kms.data.aws_caller_identity.current: Reading...
module.eks.module.eks_managed_node_group["first"].data.aws_caller_identity.current: Reading...
module.eks.module.eks_managed_node_group["first"].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_iam_policy_document.eks_s3: Read complete after 0s [id=866525205]
module.eks.module.eks_managed_node_group["first"].data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks.module.eks_managed_node_group["first"].data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2560088296]
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks.module.eks_managed_node_group["first"].data.aws_caller_identity.current: Read complete after 0s [id=247711370364]
module.eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=247711370364]
module.eks.data.aws_caller_identity.current: Read complete after 0s [id=247711370364]
module.eks.data.aws_iam_session_context.current: Reading...
module.eks.data.aws_iam_session_context.current: Read complete after 1s [id=arn:aws:sts::247711370364:assumed-role/aws_aakulov_test-developer/aakulov@hashicorp.com]
data.aws_eks_cluster_auth.cluster_auth: Reading...
data.aws_eks_cluster_auth.cluster_auth: Read complete after 0s [id=aakulov-pwpjfq-eks]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_iam_policy_document.tfe_assume_role_policy will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "tfe_assume_role_policy" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:terraform-enterprise:terraform-enterprise",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # aws_iam_policy.eks_s3 will be created
  + resource "aws_iam_policy" "eks_s3" {
      + arn         = (known after apply)
      + id          = (known after apply)
      + name        = "aakulov-pwpjfq-eks_s3"
      + name_prefix = (known after apply)
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "s3:ListBucketVersions",
                          + "s3:ListBucket",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:s3:::aakulov-pwpjfq-tfe-data"
                    },
                  + {
                      + Action   = [
                          + "s3:PutObject",
                          + "s3:GetObject",
                          + "s3:DeleteObject",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:s3:::aakulov-pwpjfq-tfe-data/*"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_iam_policy_attachment.tfe_pods_assume_role will be created
  + resource "aws_iam_policy_attachment" "tfe_pods_assume_role" {
      + id         = (known after apply)
      + name       = "aakulov-pwpjfq-tfe-pods-assume-role"
      + policy_arn = (known after apply)
      + roles      = [
          + "aakulov-pwpjfq-tfe-pods-assume-role",
        ]
    }

  # aws_iam_role.tfe_pods_assume_role will be created
  + resource "aws_iam_role" "tfe_pods_assume_role" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "aakulov-pwpjfq-tfe-pods-assume-role"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # helm_release.ingress-nginx will be created
  + resource "helm_release" "ingress-nginx" {
      + atomic                     = false
      + chart                      = "ingress-nginx"
      + cleanup_on_fail            = true
      + create_namespace           = false
      + dependency_update          = false
      + disable_crd_hooks          = false
      + disable_openapi_validation = false
      + disable_webhooks           = false
      + force_update               = true
      + id                         = (known after apply)
      + lint                       = false
      + manifest                   = (known after apply)
      + max_history                = 0
      + metadata                   = (known after apply)
      + name                       = "ingress-nginx"
      + namespace                  = "ingress-nginx"
      + pass_credentials           = false
      + recreate_pods              = false
      + render_subchart_notes      = true
      + replace                    = true
      + repository                 = "https://kubernetes.github.io/ingress-nginx"
      + reset_values               = false
      + reuse_values               = false
      + skip_crds                  = false
      + status                     = "deployed"
      + timeout                    = 400
      + verify                     = false
      + version                    = "4.7.1"
      + wait                       = true
      + wait_for_jobs              = true
    }

  # kubernetes_namespace.ingress-nginx will be created
  + resource "kubernetes_namespace" "ingress-nginx" {
      + id                               = (known after apply)
      + wait_for_default_service_account = false

      + metadata {
          + generation       = (known after apply)
          + name             = "ingress-nginx"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.eks.data.aws_eks_addon_version.this["coredns"] will be read during apply
  # (depends on a resource or a module with changes pending)
 <= data "aws_eks_addon_version" "this" {
      + addon_name         = "coredns"
      + id                 = (known after apply)
      + kubernetes_version = "1.27"
      + version            = (known after apply)
    }

  # module.eks.data.aws_eks_addon_version.this["kube-proxy"] will be read during apply
  # (depends on a resource or a module with changes pending)
 <= data "aws_eks_addon_version" "this" {
      + addon_name         = "kube-proxy"
      + id                 = (known after apply)
      + kubernetes_version = "1.27"
      + version            = (known after apply)
    }

  # module.eks.data.aws_eks_addon_version.this["vpc-cni"] will be read during apply
  # (depends on a resource or a module with changes pending)
 <= data "aws_eks_addon_version" "this" {
      + addon_name         = "vpc-cni"
      + id                 = (known after apply)
      + kubernetes_version = "1.27"
      + version            = (known after apply)
    }

  # module.eks.data.tls_certificate.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "tls_certificate" "this" {
      + certificates = (known after apply)
      + id           = (known after apply)
      + url          = (known after apply)
    }

  # module.eks.aws_cloudwatch_log_group.this[0] will be created
  + resource "aws_cloudwatch_log_group" "this" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + name              = "/aws/eks/aakulov-pwpjfq-eks/cluster"
      + name_prefix       = (known after apply)
      + retention_in_days = 90
      + skip_destroy      = false
      + tags              = {
          + "Name" = "/aws/eks/aakulov-pwpjfq-eks/cluster"
        }
      + tags_all          = {
          + "Name" = "/aws/eks/aakulov-pwpjfq-eks/cluster"
        }
    }

  # module.eks.aws_eks_addon.this["coredns"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name           = "coredns"
      + addon_version        = (known after apply)
      + arn                  = (known after apply)
      + cluster_name         = "aakulov-pwpjfq-eks"
      + configuration_values = (known after apply)
      + created_at           = (known after apply)
      + id                   = (known after apply)
      + modified_at          = (known after apply)
      + resolve_conflicts    = "OVERWRITE"
      + tags_all             = (known after apply)

      + timeouts {}
    }

  # module.eks.aws_eks_addon.this["kube-proxy"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name           = "kube-proxy"
      + addon_version        = (known after apply)
      + arn                  = (known after apply)
      + cluster_name         = "aakulov-pwpjfq-eks"
      + configuration_values = (known after apply)
      + created_at           = (known after apply)
      + id                   = (known after apply)
      + modified_at          = (known after apply)
      + resolve_conflicts    = "OVERWRITE"
      + tags_all             = (known after apply)

      + timeouts {}
    }

  # module.eks.aws_eks_addon.this["vpc-cni"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name           = "vpc-cni"
      + addon_version        = (known after apply)
      + arn                  = (known after apply)
      + cluster_name         = "aakulov-pwpjfq-eks"
      + configuration_values = (known after apply)
      + created_at           = (known after apply)
      + id                   = (known after apply)
      + modified_at          = (known after apply)
      + resolve_conflicts    = "OVERWRITE"
      + tags_all             = (known after apply)

      + timeouts {}
    }

  # module.eks.aws_eks_cluster.this[0] will be created
  + resource "aws_eks_cluster" "this" {
      + arn                       = (known after apply)
      + certificate_authority     = (known after apply)
      + cluster_id                = (known after apply)
      + created_at                = (known after apply)
      + enabled_cluster_log_types = [
          + "api",
          + "audit",
          + "authenticator",
        ]
      + endpoint                  = (known after apply)
      + id                        = (known after apply)
      + identity                  = (known after apply)
      + name                      = "aakulov-pwpjfq-eks"
      + platform_version          = (known after apply)
      + role_arn                  = (known after apply)
      + status                    = (known after apply)
      + tags_all                  = (known after apply)
      + version                   = "1.27"

      + encryption_config {
          + resources = [
              + "secrets",
            ]

          + provider {
              + key_arn = (known after apply)
            }
        }

      + kubernetes_network_config {
          + ip_family         = (known after apply)
          + service_ipv4_cidr = (known after apply)
          + service_ipv6_cidr = (known after apply)
        }

      + timeouts {}

      + vpc_config {
          + cluster_security_group_id = (known after apply)
          + endpoint_private_access   = true
          + endpoint_public_access    = true
          + public_access_cidrs       = [
              + "0.0.0.0/0",
            ]
          + security_group_ids        = (known after apply)
          + subnet_ids                = [
              + "subnet-0746808c2389800b2",
              + "subnet-092125954f3c87d13",
            ]
          + vpc_id                    = (known after apply)
        }
    }

  # module.eks.aws_iam_openid_connect_provider.oidc_provider[0] will be created
  + resource "aws_iam_openid_connect_provider" "oidc_provider" {
      + arn             = (known after apply)
      + client_id_list  = [
          + "sts.amazonaws.com",
        ]
      + id              = (known after apply)
      + tags            = {
          + "Name" = "aakulov-pwpjfq-eks-eks-irsa"
        }
      + tags_all        = {
          + "Name" = "aakulov-pwpjfq-eks-eks-irsa"
        }
      + thumbprint_list = (known after apply)
      + url             = (known after apply)
    }

  # module.eks.aws_iam_policy.cluster_encryption[0] will be created
  + resource "aws_iam_policy" "cluster_encryption" {
      + arn         = (known after apply)
      + description = "Cluster encryption policy to allow cluster role to utilize CMK provided"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "aakulov-pwpjfq-eks-managed-node-group-ClusterEncryption"
      + path        = "/"
      + policy      = (known after apply)
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.eks.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "eks.amazonaws.com"
                        }
                      + Sid       = "EKSClusterAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "aakulov-pwpjfq-eks-managed-node-group"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = "aakulov-pwpjfq-eks-managed-node-group"
          + policy = jsonencode(
                {
                  + Statement = [
                      + {
                          + Action   = [
                              + "logs:CreateLogGroup",
                            ]
                          + Effect   = "Deny"
                          + Resource = "*"
                        },
                    ]
                  + Version   = "2012-10-17"
                }
            )
        }
    }

  # module.eks.aws_iam_role_policy_attachment.additional["AmazonEC2ContainerRegistryReadOnly"] will be created
  + resource "aws_iam_role_policy_attachment" "additional" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = "aakulov-pwpjfq-eks-managed-node-group"
    }

  # module.eks.aws_iam_role_policy_attachment.additional["AmazonS3BucketReadWrite"] will be created
  + resource "aws_iam_role_policy_attachment" "additional" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "aakulov-pwpjfq-eks-managed-node-group"
    }

  # module.eks.aws_iam_role_policy_attachment.cluster_encryption[0] will be created
  + resource "aws_iam_role_policy_attachment" "cluster_encryption" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "aakulov-pwpjfq-eks-managed-node-group"
    }

  # module.eks.aws_iam_role_policy_attachment.this["AmazonEKSClusterPolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
      + role       = "aakulov-pwpjfq-eks-managed-node-group"
    }

  # module.eks.aws_iam_role_policy_attachment.this["AmazonEKSVPCResourceController"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
      + role       = "aakulov-pwpjfq-eks-managed-node-group"
    }

  # module.eks.aws_security_group.cluster[0] will be created
  + resource "aws_security_group" "cluster" {
      + arn                    = (known after apply)
      + description            = "EKS cluster security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "aakulov-pwpjfq-eks-cluster-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-pwpjfq-eks-cluster"
        }
      + tags_all               = {
          + "Name" = "aakulov-pwpjfq-eks-cluster"
        }
      + vpc_id                 = "vpc-004d7d76e8854003a"
    }

  # module.eks.aws_security_group.node[0] will be created
  + resource "aws_security_group" "node" {
      + arn                    = (known after apply)
      + description            = "EKS node shared security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "aakulov-pwpjfq-eks-node-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                                     = "aakulov-pwpjfq-eks-node"
          + "kubernetes.io/cluster/aakulov-pwpjfq-eks" = "owned"
        }
      + tags_all               = {
          + "Name"                                     = "aakulov-pwpjfq-eks-node"
          + "kubernetes.io/cluster/aakulov-pwpjfq-eks" = "owned"
        }
      + vpc_id                 = "vpc-004d7d76e8854003a"
    }

  # module.eks.aws_security_group_rule.cluster["ingress_nodes_443"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Node groups to cluster API"
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_443"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node groups"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node kubelets"
      + from_port                = 10250
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 10250
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS UDP"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.time_sleep.this[0] will be created
  + resource "time_sleep" "this" {
      + create_duration = "30s"
      + id              = (known after apply)
      + triggers        = {
          + "cluster_certificate_authority_data" = (known after apply)
          + "cluster_endpoint"                   = (known after apply)
          + "cluster_name"                       = "aakulov-pwpjfq-eks"
          + "cluster_version"                    = "1.27"
        }
    }

  # module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0] will be created
  + resource "aws_eks_node_group" "this" {
      + ami_type               = "BOTTLEROCKET_x86_64"
      + arn                    = (known after apply)
      + capacity_type          = (known after apply)
      + cluster_name           = "aakulov-pwpjfq-eks"
      + disk_size              = (known after apply)
      + id                     = (known after apply)
      + instance_types         = [
          + "t3.2xlarge",
        ]
      + node_group_name        = (known after apply)
      + node_group_name_prefix = "aakulov-pwpjfq-ng-1-"
      + node_role_arn          = (known after apply)
      + release_version        = (known after apply)
      + resources              = (known after apply)
      + status                 = (known after apply)
      + subnet_ids             = [
          + "subnet-0746808c2389800b2",
          + "subnet-092125954f3c87d13",
        ]
      + tags                   = {
          + "Name" = "aakulov-pwpjfq-ng-1"
        }
      + tags_all               = {
          + "Name" = "aakulov-pwpjfq-ng-1"
        }
      + version                = "1.27"

      + launch_template {
          + id      = (known after apply)
          + name    = (known after apply)
          + version = (known after apply)
        }

      + scaling_config {
          + desired_size = 3
          + max_size     = 3
          + min_size     = 1
        }

      + timeouts {}

      + update_config {
          + max_unavailable_percentage = 33
        }
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = "EKSNodeAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + description           = "EKS managed node group IAM role"
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "aakulov-pwpjfq-ng-1-eks-node-group-"
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_launch_template.this[0] will be created
  + resource "aws_launch_template" "this" {
      + arn                    = (known after apply)
      + default_version        = (known after apply)
      + description            = "Custom launch template for aakulov-pwpjfq-ng-1 EKS managed node group"
      + id                     = (known after apply)
      + latest_version         = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "first-"
      + tags_all               = (known after apply)
      + update_default_version = true
      + vpc_security_group_ids = (known after apply)

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_protocol_ipv6          = (known after apply)
          + http_put_response_hop_limit = 2
          + http_tokens                 = "optional"
          + instance_metadata_tags      = "enabled"
        }

      + monitoring {
          + enabled = true
        }

      + tag_specifications {
          + resource_type = "instance"
          + tags          = {
              + "Name" = "aakulov-pwpjfq-ng-1"
            }
        }
      + tag_specifications {
          + resource_type = "network-interface"
          + tags          = {
              + "Name" = "aakulov-pwpjfq-ng-1"
            }
        }
      + tag_specifications {
          + resource_type = "volume"
          + tags          = {
              + "Name" = "aakulov-pwpjfq-ng-1"
            }
        }
    }

  # module.eks.module.kms.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id                        = (known after apply)
      + json                      = (known after apply)
      + override_policy_documents = []
      + source_policy_documents   = []

      + statement {
          + actions   = [
              + "kms:CancelKeyDeletion",
              + "kms:Create*",
              + "kms:Delete*",
              + "kms:Describe*",
              + "kms:Disable*",
              + "kms:Enable*",
              + "kms:Get*",
              + "kms:List*",
              + "kms:Put*",
              + "kms:Revoke*",
              + "kms:ScheduleKeyDeletion",
              + "kms:TagResource",
              + "kms:UntagResource",
              + "kms:Update*",
            ]
          + resources = [
              + "*",
            ]
          + sid       = "KeyAdministration"

          + principals {
              + identifiers = [
                  + "arn:aws:iam::247711370364:role/aws_aakulov_test-developer",
                ]
              + type        = "AWS"
            }
        }
      + statement {
          + actions   = [
              + "kms:Decrypt",
              + "kms:DescribeKey",
              + "kms:Encrypt",
              + "kms:GenerateDataKey*",
              + "kms:ReEncrypt*",
            ]
          + resources = [
              + "*",
            ]
          + sid       = "KeyUsage"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
    }

  # module.eks.module.kms.aws_kms_alias.this["cluster"] will be created
  + resource "aws_kms_alias" "this" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + name           = "alias/eks/aakulov-pwpjfq-eks"
      + name_prefix    = (known after apply)
      + target_key_arn = (known after apply)
      + target_key_id  = (known after apply)
    }

  # module.eks.module.kms.aws_kms_key.this[0] will be created
  + resource "aws_kms_key" "this" {
      + arn                                = (known after apply)
      + bypass_policy_lockout_safety_check = false
      + customer_master_key_spec           = "SYMMETRIC_DEFAULT"
      + description                        = "aakulov-pwpjfq-eks cluster encryption key"
      + enable_key_rotation                = true
      + id                                 = (known after apply)
      + is_enabled                         = true
      + key_id                             = (known after apply)
      + key_usage                          = "ENCRYPT_DECRYPT"
      + multi_region                       = false
      + policy                             = (known after apply)
      + tags_all                           = (known after apply)
    }

Plan: 34 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_eks_cluster_k8s_name          = "aakulov-pwpjfq-eks"
  + aws_eks_k8s_certificate_authority = (sensitive value)
  + aws_eks_k8s_endpoint              = (known after apply)
  + kubectl_get_update_credentials    = "aws eks --region eu-north-1 update-kubeconfig --name aakulov-pwpjfq-eks"
  + tfe_pods_assume_role              = (known after apply)
aws_iam_policy.eks_s3: Creating...
module.eks.aws_cloudwatch_log_group.this[0]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role.this[0]: Creating...
module.eks.aws_security_group.cluster[0]: Creating...
module.eks.aws_iam_role.this[0]: Creating...
module.eks.aws_security_group.node[0]: Creating...
module.eks.aws_cloudwatch_log_group.this[0]: Creation complete after 1s [id=/aws/eks/aakulov-pwpjfq-eks/cluster]
aws_iam_policy.eks_s3: Creation complete after 1s [id=arn:aws:iam::247711370364:policy/aakulov-pwpjfq-eks_s3]
module.eks.module.eks_managed_node_group["first"].aws_iam_role.this[0]: Creation complete after 1s [id=aakulov-pwpjfq-ng-1-eks-node-group-20230817144329306500000002]
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creating...
module.eks.aws_iam_role.this[0]: Creation complete after 2s [id=aakulov-pwpjfq-eks-managed-node-group]
module.eks.aws_iam_role_policy_attachment.additional["AmazonEC2ContainerRegistryReadOnly"]: Creating...
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSVPCResourceController"]: Creating...
module.eks.aws_iam_role_policy_attachment.additional["AmazonS3BucketReadWrite"]: Creating...
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSClusterPolicy"]: Creating...
module.eks.module.kms.data.aws_iam_policy_document.this[0]: Reading...
module.eks.module.kms.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=635482757]
module.eks.module.kms.aws_kms_key.this[0]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creation complete after 1s [id=aakulov-pwpjfq-ng-1-eks-node-group-20230817144329306500000002-20230817144330416200000004]
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creation complete after 1s [id=aakulov-pwpjfq-ng-1-eks-node-group-20230817144329306500000002-20230817144330481400000005]
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creation complete after 1s [id=aakulov-pwpjfq-ng-1-eks-node-group-20230817144329306500000002-20230817144330547900000006]
module.eks.aws_iam_role_policy_attachment.additional["AmazonEC2ContainerRegistryReadOnly"]: Creation complete after 0s [id=aakulov-pwpjfq-eks-managed-node-group-20230817144330750700000007]
module.eks.aws_iam_role_policy_attachment.additional["AmazonS3BucketReadWrite"]: Creation complete after 0s [id=aakulov-pwpjfq-eks-managed-node-group-20230817144330794700000008]
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSClusterPolicy"]: Creation complete after 0s [id=aakulov-pwpjfq-eks-managed-node-group-2023081714433087690000000a]
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSVPCResourceController"]: Creation complete after 0s [id=aakulov-pwpjfq-eks-managed-node-group-20230817144330833800000009]
module.eks.aws_security_group.cluster[0]: Creation complete after 2s [id=sg-03f0329641b67df57]
module.eks.aws_security_group.node[0]: Creation complete after 2s [id=sg-080f2bd5165649eaa]
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creating...
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creating...
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creating...
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creation complete after 1s [id=sgrule-2945775187]
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creation complete after 1s [id=sgrule-1563803989]
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creation complete after 1s [id=sgrule-4184498874]
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creation complete after 2s [id=sgrule-3646539924]
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creation complete after 2s [id=sgrule-3638530300]
module.eks.module.kms.aws_kms_key.this[0]: Still creating... [10s elapsed]
module.eks.module.kms.aws_kms_key.this[0]: Creation complete after 16s [id=da8aed09-cf6d-420d-ae98-2406f96b652e]
module.eks.module.kms.aws_kms_alias.this["cluster"]: Creating...
module.eks.aws_iam_policy.cluster_encryption[0]: Creating...
module.eks.aws_eks_cluster.this[0]: Creating...
module.eks.module.kms.aws_kms_alias.this["cluster"]: Creation complete after 0s [id=alias/eks/aakulov-pwpjfq-eks]
module.eks.aws_iam_policy.cluster_encryption[0]: Creation complete after 1s [id=arn:aws:iam::247711370364:policy/aakulov-pwpjfq-eks-managed-node-group-ClusterEncryption2023081714434714040000000b]
module.eks.aws_iam_role_policy_attachment.cluster_encryption[0]: Creating...
module.eks.aws_iam_role_policy_attachment.cluster_encryption[0]: Creation complete after 0s [id=aakulov-pwpjfq-eks-managed-node-group-2023081714434779990000000c]
module.eks.aws_eks_cluster.this[0]: Still creating... [10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [20s elapsed]

[...]

module.eks.aws_eks_cluster.this[0]: Still creating... [8m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Creation complete after 8m33s [id=aakulov-pwpjfq-eks]
module.eks.data.aws_eks_addon_version.this["vpc-cni"]: Reading...
module.eks.data.aws_eks_addon_version.this["kube-proxy"]: Reading...
module.eks.data.tls_certificate.this[0]: Reading...
module.eks.data.aws_eks_addon_version.this["coredns"]: Reading...
module.eks.time_sleep.this[0]: Creating...
module.eks.data.aws_eks_addon_version.this["vpc-cni"]: Read complete after 0s [id=vpc-cni]
module.eks.data.tls_certificate.this[0]: Read complete after 0s [id=5007ea61dfb4fcd4db18c0c232d56bef3b07d3dc]
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creating...
module.eks.data.aws_eks_addon_version.this["coredns"]: Read complete after 0s [id=coredns]
module.eks.data.aws_eks_addon_version.this["kube-proxy"]: Read complete after 0s [id=kube-proxy]
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creation complete after 1s [id=arn:aws:iam::247711370364:oidc-provider/oidc.eks.eu-north-1.amazonaws.com/id/33FB4BB4720B437B9D81C271ED2BEC13]
data.aws_iam_policy_document.tfe_assume_role_policy: Reading...
data.aws_iam_policy_document.tfe_assume_role_policy: Read complete after 0s [id=3951726625]
aws_iam_role.tfe_pods_assume_role: Creating...
aws_iam_role.tfe_pods_assume_role: Creation complete after 0s [id=aakulov-pwpjfq-tfe-pods-assume-role]
aws_iam_policy_attachment.tfe_pods_assume_role: Creating...
aws_iam_policy_attachment.tfe_pods_assume_role: Creation complete after 0s [id=aakulov-pwpjfq-tfe-pods-assume-role]
module.eks.time_sleep.this[0]: Still creating... [10s elapsed]
module.eks.time_sleep.this[0]: Still creating... [20s elapsed]
module.eks.time_sleep.this[0]: Still creating... [30s elapsed]
module.eks.time_sleep.this[0]: Creation complete after 30s [id=2023-08-17T14:52:50Z]
module.eks.module.eks_managed_node_group["first"].aws_launch_template.this[0]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_launch_template.this[0]: Creation complete after 1s [id=lt-0fe0f5d98c7bb8650]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [10s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [20s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [30s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [40s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [50s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m0s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m10s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m20s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Creation complete after 1m29s [id=aakulov-pwpjfq-eks:aakulov-pwpjfq-ng-1-2023081714525096990000000f]
module.eks.aws_eks_addon.this["kube-proxy"]: Creating...
module.eks.aws_eks_addon.this["vpc-cni"]: Creating...
module.eks.aws_eks_addon.this["coredns"]: Creating...
module.eks.aws_eks_addon.this["kube-proxy"]: Creation complete after 4s [id=aakulov-pwpjfq-eks:kube-proxy]
module.eks.aws_eks_addon.this["coredns"]: Still creating... [10s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [10s elapsed]
module.eks.aws_eks_addon.this["coredns"]: Creation complete after 15s [id=aakulov-pwpjfq-eks:coredns]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [20s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [30s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Creation complete after 35s [id=aakulov-pwpjfq-eks:vpc-cni]
kubernetes_namespace.ingress-nginx: Creating...
kubernetes_namespace.ingress-nginx: Creation complete after 1s [id=ingress-nginx]
helm_release.ingress-nginx: Creating...
helm_release.ingress-nginx: Still creating... [10s elapsed]
helm_release.ingress-nginx: Still creating... [20s elapsed]
helm_release.ingress-nginx: Still creating... [30s elapsed]
helm_release.ingress-nginx: Still creating... [40s elapsed]
helm_release.ingress-nginx: Creation complete after 48s [id=ingress-nginx]

Apply complete! Resources: 34 added, 0 changed, 0 destroyed.

Outputs:

aws_eks_cluster_k8s_name = "aakulov-pwpjfq-eks"
aws_eks_k8s_certificate_authority = <sensitive>
aws_eks_k8s_endpoint = "https://33FB4BB4720B437B9D81C271ED2BEC13.gr7.eu-north-1.eks.amazonaws.com"
kubectl_get_update_credentials = "aws eks --region eu-north-1 update-kubeconfig --name aakulov-pwpjfq-eks"
tfe_pods_assume_role = "arn:aws:iam::247711370364:role/aakulov-pwpjfq-tfe-pods-assume-role"
```

- Update aws cli eks credentials for k8s cluster

```bash
# use output of the variable kubectl_get_update_credentials
aws eks --region eu-REGION_HERE update-kubeconfig --name aakulov-YOUR_EKS_CLUSTER_ID-eks
```

- Change folder to tf-aws-pes-eksk8s-activeactive-agents/terraform-enterprise

```bash
cd terraform-enterprise
```

- Create file terraform.tfvars with following contents

```
docker_repository_login = "hc-support-tfe-beta"
docker_repository_token = "put_docker_repository_token_here"
docker_image_tag        = "beta-1"
docker_repository       = "terraform-enterprise-beta.terraform.io"
tfe_hostname            = "tfe.mydomainname.com"
domain_name             = "mydomainname.com"
cloudflare_zone_id      = "put_zone_id_here"
cloudflare_api_token    = "put_cloudflare_token_here"
tfe_tls_version         = "tls_1_3"
tfe_license_path        = "upload/license.lic"
ssl_cert_path           = "/path/to/cert.pem"
ssl_key_path            = "/path/to/privkey.pem"
ssl_chain_path          = "/path/to/chain.pem"
ssl_fullchain_cert_path = "/path/to/fullchain.pem"
```

- Run the `terraform apply`

```bash
terraform apply 
```

Sample result:

```bash
% terraform apply --auto-approve
data.terraform_remote_state.main: Reading...
data.terraform_remote_state.kubernetes: Reading...
data.template_file.docker_config: Reading...
data.local_sensitive_file.sslchain: Reading...
data.local_sensitive_file.sslcert: Reading...
data.template_file.docker_config: Read complete after 0s [id=7495c722e4dab274eba4560fb16ff70092f48929e50ed02845d1421365e500c3]
data.terraform_remote_state.main: Read complete after 0s
data.local_sensitive_file.sslkey: Reading...
data.local_sensitive_file.sslchain: Read complete after 0s [id=35bea03aecd55ca4d525c6b0a45908a19c6986f9]
data.local_sensitive_file.sslcert: Read complete after 0s [id=ddcbc040de65e147fed005d4cdaa5b6f04a85452]
data.local_sensitive_file.sslkey: Read complete after 0s [id=01e293ac04d434108c6e14d05c13404d1217a6b9]
data.terraform_remote_state.kubernetes: Read complete after 0s
data.aws_eks_cluster_auth.cluster_auth: Reading...
data.aws_instances.tfc_agent: Reading...
data.aws_eks_cluster_auth.cluster_auth: Read complete after 0s [id=aakulov-pwpjfq-eks]
data.kubernetes_service.tfe: Reading...
data.aws_instances.tfc_agent: Read complete after 0s [id=eu-north-1]
data.kubernetes_service.tfe: Read complete after 1s

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # cloudflare_record.tfe will be created
  + resource "cloudflare_record" "tfe" {
      + allow_overwrite = false
      + created_on      = (known after apply)
      + hostname        = (known after apply)
      + id              = (known after apply)
      + metadata        = (known after apply)
      + modified_on     = (known after apply)
      + name            = "pwpjfqtfe.akulov.cc"
      + proxiable       = (known after apply)
      + ttl             = 1
      + type            = "CNAME"
      + value           = "0.0.0.0"
      + zone_id         = (sensitive value)
    }

  # helm_release.terraform-enterprise will be created
  + resource "helm_release" "terraform-enterprise" {
      + atomic                     = false
      + chart                      = "../terraform-enterprise-helm"
      + cleanup_on_fail            = true
      + create_namespace           = false
      + dependency_update          = false
      + disable_crd_hooks          = false
      + disable_openapi_validation = false
      + disable_webhooks           = false
      + force_update               = false
      + id                         = (known after apply)
      + lint                       = false
      + manifest                   = (known after apply)
      + max_history                = 0
      + metadata                   = (known after apply)
      + name                       = "terraform-enterprise"
      + namespace                  = (known after apply)
      + pass_credentials           = false
      + recreate_pods              = false
      + render_subchart_notes      = true
      + replace                    = true
      + reset_values               = false
      + reuse_values               = false
      + skip_crds                  = false
      + status                     = "deployed"
      + timeout                    = 800
      + values                     = (known after apply)
      + verify                     = false
      + version                    = "0.1.2"
      + wait                       = false
      + wait_for_jobs              = true
    }

  # kubernetes_namespace.terraform-enterprise will be created
  + resource "kubernetes_namespace" "terraform-enterprise" {
      + id                               = (known after apply)
      + wait_for_default_service_account = false

      + metadata {
          + annotations      = {
              + "meta.helm.sh/release-name"      = "terraform-enterprise"
              + "meta.helm.sh/release-namespace" = "terraform-enterprise"
            }
          + generation       = (known after apply)
          + labels           = {
              + "app" = "terraform-enterprise"
            }
          + name             = "terraform-enterprise"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # kubernetes_namespace.terraform-enterprise-agents will be created
  + resource "kubernetes_namespace" "terraform-enterprise-agents" {
      + id                               = (known after apply)
      + wait_for_default_service_account = false

      + metadata {
          + annotations      = {
              + "app.kubernetes.io/managed-by"   = "Helm"
              + "meta.helm.sh/release-name"      = "terraform-enterprise"
              + "meta.helm.sh/release-namespace" = "terraform-enterprise"
            }
          + generation       = (known after apply)
          + labels           = {
              + "app.kubernetes.io/managed-by" = "Helm"
            }
          + name             = "terraform-enterprise-agents"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # kubernetes_secret.docker_registry will be created
  + resource "kubernetes_secret" "docker_registry" {
      + data                           = (sensitive value)
      + id                             = (known after apply)
      + type                           = "kubernetes.io/dockerconfigjson"
      + wait_for_service_account_token = true

      + metadata {
          + generation       = (known after apply)
          + name             = "docker-registry"
          + namespace        = (known after apply)
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # random_id.enc_password will be created
  + resource "random_id" "enc_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.install_id will be created
  + resource "random_id" "install_id" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.user_token will be created
  + resource "random_id" "user_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_string.password will be created
  + resource "random_string" "password" {
      + id          = (known after apply)
      + length      = 16
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

Plan: 9 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + service_url  = "0.0.0.0"
  + tfe_hostname = "pwpjfqtfe.akulov.cc"
  + url          = (known after apply)
kubernetes_namespace.terraform-enterprise-agents: Creating...
kubernetes_namespace.terraform-enterprise: Creating...
cloudflare_record.tfe: Creating...
random_id.install_id: Creating...
random_id.user_token: Creating...
random_id.enc_password: Creating...
random_id.user_token: Creation complete after 0s [id=SAC4ugsOBso3FMXeDNYSqw]
random_string.password: Creating...
random_id.enc_password: Creation complete after 0s [id=bz8a1yPU050l9ubxO74rwg]
random_id.install_id: Creation complete after 0s [id=VusMREbj49BJOvlYm1bPzw]
random_string.password: Creation complete after 0s [id=Z0DI5EPBN49jhVQz]
kubernetes_namespace.terraform-enterprise: Creation complete after 1s [id=terraform-enterprise]
kubernetes_namespace.terraform-enterprise-agents: Creation complete after 1s [id=terraform-enterprise-agents]
kubernetes_secret.docker_registry: Creating...
helm_release.terraform-enterprise: Creating...
kubernetes_secret.docker_registry: Creation complete after 0s [id=terraform-enterprise/docker-registry]
helm_release.terraform-enterprise: Creation complete after 3s [id=terraform-enterprise]
╷
│ Error: failed to create DNS record: DNS Validation Error (1004)
│ 
│   with cloudflare_record.tfe,
│   on main.tf line 194, in resource "cloudflare_record" "tfe":
│  194: resource "cloudflare_record" "tfe" {
│ 
```

- Wait about 5-10 minutes until Terraform Enterprise is completelly provisioned and K8S service is linked with AWS Classic Load Balancer url. EXTERNAL-IP field should have ELB url assigned.

- Test k8s service

```bash
kubectl get services -n terraform-enterprise
```

Example output:

```bash
% kubectl get services -n terraform-enterprise                              
NAME                   TYPE           CLUSTER-IP       EXTERNAL-IP                                                                PORT(S)         AGE
terraform-enterprise   LoadBalancer   172.20.201.131   a3fa64da13a944f61b8a38a8706505f2-1072491901.eu-north-1.elb.amazonaws.com   443:30301/TCP   5m5s
```

- Run the `terraform apply` again to create DNS record

```bash
terraform apply
```

Example result:

```bash
% terraform apply --auto-approve
data.terraform_remote_state.kubernetes: Reading...
data.terraform_remote_state.main: Reading...
data.template_file.docker_config: Reading...
data.template_file.docker_config: Read complete after 0s [id=7495c722e4dab274eba4560fb16ff70092f48929e50ed02845d1421365e500c3]
data.terraform_remote_state.main: Read complete after 0s
random_id.user_token: Refreshing state... [id=SAC4ugsOBso3FMXeDNYSqw]
random_id.install_id: Refreshing state... [id=VusMREbj49BJOvlYm1bPzw]
data.terraform_remote_state.kubernetes: Read complete after 0s
random_string.password: Refreshing state... [id=Z0DI5EPBN49jhVQz]
random_id.enc_password: Refreshing state... [id=bz8a1yPU050l9ubxO74rwg]
data.local_sensitive_file.sslcert: Reading...
data.local_sensitive_file.sslchain: Reading...
data.local_sensitive_file.sslkey: Reading...
data.local_sensitive_file.sslcert: Read complete after 0s [id=ddcbc040de65e147fed005d4cdaa5b6f04a85452]
data.local_sensitive_file.sslchain: Read complete after 0s [id=35bea03aecd55ca4d525c6b0a45908a19c6986f9]
data.local_sensitive_file.sslkey: Read complete after 0s [id=01e293ac04d434108c6e14d05c13404d1217a6b9]
data.aws_eks_cluster_auth.cluster_auth: Reading...
data.aws_instances.tfc_agent: Reading...
data.aws_eks_cluster_auth.cluster_auth: Read complete after 0s [id=aakulov-pwpjfq-eks]
kubernetes_namespace.terraform-enterprise-agents: Refreshing state... [id=terraform-enterprise-agents]
data.kubernetes_service.tfe: Reading...
kubernetes_namespace.terraform-enterprise: Refreshing state... [id=terraform-enterprise]
data.aws_instances.tfc_agent: Read complete after 0s [id=eu-north-1]
data.kubernetes_service.tfe: Read complete after 1s [id=terraform-enterprise/terraform-enterprise]
kubernetes_secret.docker_registry: Refreshing state... [id=terraform-enterprise/docker-registry]
helm_release.terraform-enterprise: Refreshing state... [id=terraform-enterprise]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # cloudflare_record.tfe will be created
  + resource "cloudflare_record" "tfe" {
      + allow_overwrite = false
      + created_on      = (known after apply)
      + hostname        = (known after apply)
      + id              = (known after apply)
      + metadata        = (known after apply)
      + modified_on     = (known after apply)
      + name            = "pwpjfqtfe.akulov.cc"
      + proxiable       = (known after apply)
      + ttl             = 1
      + type            = "CNAME"
      + value           = "a3fa64da13a944f61b8a38a8706505f2-1072491901.eu-north-1.elb.amazonaws.com"
      + zone_id         = (sensitive value)
    }

Plan: 1 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  ~ service_url  = "0.0.0.0" -> "a3fa64da13a944f61b8a38a8706505f2-1072491901.eu-north-1.elb.amazonaws.com"
cloudflare_record.tfe: Creating...
cloudflare_record.tfe: Creation complete after 2s [id=cdb4072d64eaa58fe237e6dbe03138d0]

Apply complete! Resources: 1 added, 0 changed, 0 destroyed.

Outputs:

service_url = "a3fa64da13a944f61b8a38a8706505f2-1072491901.eu-north-1.elb.amazonaws.com"
tfe_hostname = "pwpjfqtfe.akulov.cc"
url = "https://pwpjfqtfe.akulov.cc/admin/account/new?token=redacted_token_here"
```

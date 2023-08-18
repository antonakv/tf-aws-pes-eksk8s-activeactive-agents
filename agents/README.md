# tf-aws-pes-eksk8s-activeactive-agents

Terraform Terraform Enterprise FDO EC2 based agents with AWS Autoscaling group

## Requirements

- Provisioned main folder of the repository 

- Provisioned folder `kubernetes` of the repository 

- Provisioned folder `terraform-enterprise` of the repository 

- AWS AMI image built using Packer repository
[packer-aws-ubuntujammy-terraform-agent](https://github.com/antonakv/packer-aws-ubuntujammy-terraform-agent)

## Preparation 

- Create `terraform.tfvars` file with following contents

```
agent_ami           = "ami-packer-aws-ubuntujammy-terraform-agent_IMAGE_ID"
instance_type_agent = "t3.medium"
agent_token         = "TFE_AGENT_TOKEN.atlasv1.HERE"
asg_min_agents      = 3
asg_max_agents      = 3
asg_desired_agents  = 3
```

- Open TFE Organisation settings - Security - Agents

- Click `Create agent pool`

- Set agent pool name and click `Continue`

- Set description and click `Create token`

- Copy new agent token and paste to the `agent_token` variable value in the `terraform.tfvars`

- Click Finish

- Run the `terraform init`

Example output 

```bash
% terraform init                

Initializing the backend...

Initializing provider plugins...
- terraform.io/builtin/terraform is built in to Terraform
- Reusing previous version of hashicorp/local from the dependency lock file
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/template from the dependency lock file
- Using previously-installed hashicorp/local v2.4.0
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

Example output:

```bash
% terraform apply --auto-approve
data.terraform_remote_state.main: Reading...
data.terraform_remote_state.terraform-enterprise: Reading...
data.terraform_remote_state.terraform-enterprise: Read complete after 0s
data.terraform_remote_state.main: Read complete after 0s
data.aws_iam_policy_document.instance_role: Reading...
data.aws_iam_policy_document.tfe_asg_discovery: Reading...
data.aws_instances.tfc_agent: Reading...
data.aws_iam_policy_document.tfe_asg_discovery: Read complete after 0s [id=3912694501]
data.aws_iam_policy_document.instance_role: Read complete after 0s [id=2851119427]
data.aws_instances.tfc_agent: Read complete after 1s [id=eu-north-1]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_iam_policy_document.secretsmanager will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "secretsmanager" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "secretsmanager:GetSecretValue",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
            ]
          + sid       = "AllowSecretsManagerSecretAccess"
        }
    }

  # aws_autoscaling_group.tfc_agent will be created
  + resource "aws_autoscaling_group" "tfc_agent" {
      + arn                              = (known after apply)
      + availability_zones               = (known after apply)
      + default_cooldown                 = (known after apply)
      + desired_capacity                 = 0
      + force_delete                     = false
      + force_delete_warm_pool           = false
      + health_check_grace_period        = 900
      + health_check_type                = "EC2"
      + id                               = (known after apply)
      + ignore_failed_scaling_activities = false
      + launch_configuration             = (known after apply)
      + load_balancers                   = (known after apply)
      + max_size                         = 0
      + metrics_granularity              = "1Minute"
      + min_size                         = 0
      + name                             = "aakulov-tqnhgf-asg-tfc_agent"
      + name_prefix                      = (known after apply)
      + predicted_capacity               = (known after apply)
      + protect_from_scale_in            = false
      + service_linked_role_arn          = (known after apply)
      + target_group_arns                = (known after apply)
      + vpc_zone_identifier              = [
          + "subnet-019636a66755969ba",
          + "subnet-08403c7a9aa8e2be5",
        ]
      + wait_for_capacity_timeout        = "10m"
      + warm_pool_size                   = (known after apply)

      + tag {
          + key                 = "Name"
          + propagate_at_launch = true
          + value               = "aakulov-tqnhgf-asg-tfc_agent"
        }
    }

  # aws_iam_instance_profile.tfe will be created
  + resource "aws_iam_instance_profile" "tfe" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "aakulov-tqnhgf-tfe"
      + path        = "/"
      + role        = (known after apply)
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.instance_role will be created
  + resource "aws_iam_role" "instance_role" {
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
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "aakulov-tqnhgf-tfe"
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # aws_iam_role_policy.secretsmanager will be created
  + resource "aws_iam_role_policy" "secretsmanager" {
      + id     = (known after apply)
      + name   = "aakulov-tqnhgf-tfe-secretsmanager"
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # aws_iam_role_policy.tfe_asg_discovery will be created
  + resource "aws_iam_role_policy" "tfe_asg_discovery" {
      + id     = (known after apply)
      + name   = "aakulov-tqnhgf-tfe-asg-discovery"
      + policy = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "autoscaling:Describe*"
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + role   = (known after apply)
    }

  # aws_launch_configuration.tfc_agent will be created
  + resource "aws_launch_configuration" "tfc_agent" {
      + arn                         = (known after apply)
      + associate_public_ip_address = (known after apply)
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = (known after apply)
      + id                          = (known after apply)
      + image_id                    = "ami-03ffc24bfada9dca4"
      + instance_type               = "t3.medium"
      + key_name                    = "aakulov2"
      + name                        = (known after apply)
      + name_prefix                 = "aakulov-tqnhgf-tfc_agent-launch-configuration"
      + security_groups             = [
          + "sg-0ae22998e03df8af7",
        ]
      + user_data_base64            = (known after apply)

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "optional"
        }

      + root_block_device {
          + delete_on_termination = true
          + encrypted             = (known after apply)
          + iops                  = 1000
          + throughput            = (known after apply)
          + volume_size           = 40
          + volume_type           = "io1"
        }
    }

  # aws_secretsmanager_secret.agent_token will be created
  + resource "aws_secretsmanager_secret" "agent_token" {
      + arn                            = (known after apply)
      + description                    = "TFC agent token"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = "aakulov-tqnhgf-agent_token"
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 0
      + tags_all                       = (known after apply)
    }

  # aws_secretsmanager_secret_version.agent_token will be created
  + resource "aws_secretsmanager_secret_version" "agent_token" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_id      = (known after apply)
      + secret_string  = (sensitive value)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

Plan: 8 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + agent_token           = (sensitive value)
  + aws_active_agents_ips = ""
  + aws_agent_ec2_ids     = []
aws_secretsmanager_secret.agent_token: Creating...
aws_iam_role.instance_role: Creating...
aws_secretsmanager_secret.agent_token: Creation complete after 0s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aakulov-tqnhgf-agent_token-w0l3Lv]
aws_secretsmanager_secret_version.agent_token: Creating...
aws_secretsmanager_secret_version.agent_token: Creation complete after 0s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aakulov-tqnhgf-agent_token-w0l3Lv|82903471-2C4B-4E18-920B-9CBB09296AC7]
data.aws_iam_policy_document.secretsmanager: Reading...
data.aws_iam_policy_document.secretsmanager: Read complete after 0s [id=1358423047]
aws_iam_role.instance_role: Creation complete after 1s [id=aakulov-tqnhgf-tfe20230818084332677000000001]
aws_iam_role_policy.secretsmanager: Creating...
aws_iam_role_policy.tfe_asg_discovery: Creating...
aws_iam_instance_profile.tfe: Creating...
aws_iam_role_policy.secretsmanager: Creation complete after 0s [id=aakulov-tqnhgf-tfe20230818084332677000000001:aakulov-tqnhgf-tfe-secretsmanager]
aws_iam_role_policy.tfe_asg_discovery: Creation complete after 0s [id=aakulov-tqnhgf-tfe20230818084332677000000001:aakulov-tqnhgf-tfe-asg-discovery]
aws_iam_instance_profile.tfe: Creation complete after 1s [id=aakulov-tqnhgf-tfe20230818084333675500000002]
aws_launch_configuration.tfc_agent: Creating...
aws_launch_configuration.tfc_agent: Creation complete after 9s [id=aakulov-tqnhgf-tfc_agent-launch-configuration20230818084334549900000003]
aws_autoscaling_group.tfc_agent: Creating...
aws_autoscaling_group.tfc_agent: Creation complete after 0s [id=aakulov-tqnhgf-asg-tfc_agent]

Apply complete! Resources: 8 added, 0 changed, 0 destroyed.

Outputs:

agent_token = <sensitive>
aws_active_agents_ips = ""
aws_agent_ec2_ids = toset([])
```

- Wait about 5 minutes

- Run the `terraform apply` again

Example output:

```bash
 % terraform apply --auto-approve
data.terraform_remote_state.terraform-enterprise: Reading...
data.terraform_remote_state.main: Reading...
data.terraform_remote_state.terraform-enterprise: Read complete after 0s
data.terraform_remote_state.main: Read complete after 0s
data.aws_iam_policy_document.tfe_asg_discovery: Reading...
data.aws_instances.tfc_agent: Reading...
aws_secretsmanager_secret.agent_token: Refreshing state... [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aakulov-tqnhgf-agent_token-9X71uk]
data.aws_iam_policy_document.instance_role: Reading...
data.aws_iam_policy_document.tfe_asg_discovery: Read complete after 0s [id=3912694501]
data.aws_iam_policy_document.instance_role: Read complete after 0s [id=2851119427]
aws_iam_role.instance_role: Refreshing state... [id=aakulov-tqnhgf-tfe20230818085108387700000001]
aws_secretsmanager_secret_version.agent_token: Refreshing state... [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aakulov-tqnhgf-agent_token-9X71uk|A18FAA1B-AB01-4284-8235-54470DEFAE69]
data.aws_iam_policy_document.secretsmanager: Reading...
data.aws_iam_policy_document.secretsmanager: Read complete after 0s [id=1790463900]
data.aws_instances.tfc_agent: Read complete after 1s [id=eu-north-1]
aws_iam_role_policy.tfe_asg_discovery: Refreshing state... [id=aakulov-tqnhgf-tfe20230818085108387700000001:aakulov-tqnhgf-tfe-asg-discovery]
aws_iam_role_policy.secretsmanager: Refreshing state... [id=aakulov-tqnhgf-tfe20230818085108387700000001:aakulov-tqnhgf-tfe-secretsmanager]
aws_iam_instance_profile.tfe: Refreshing state... [id=aakulov-tqnhgf-tfe20230818085109236800000002]
aws_launch_configuration.tfc_agent: Refreshing state... [id=aakulov-tqnhgf-tfc_agent-launch-configuration20230818085110226100000003]
aws_autoscaling_group.tfc_agent: Refreshing state... [id=aakulov-tqnhgf-asg-tfc_agent]

Changes to Outputs:
  ~ aws_active_agents_ips = "" -> "10.5.2.173, 10.5.1.209, 10.5.1.119"
  ~ aws_agent_ec2_ids     = [
      + "i-081ca85a8949b78f1",
      + "i-09313e8c71a866ed1",
      + "i-0f57d4c029a37eb81",
    ]

You can apply this plan to save these new output values to the Terraform state, without changing any real infrastructure.

Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:

agent_token = <sensitive>
aws_active_agents_ips = "10.5.2.173, 10.5.1.209, 10.5.1.119"
aws_agent_ec2_ids = toset([
  "i-081ca85a8949b78f1",
  "i-09313e8c71a866ed1",
  "i-0f57d4c029a37eb81",
])
```

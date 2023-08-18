data "terraform_remote_state" "main" {
  backend = "local"

  config = {
    path = "../terraform.tfstate"
  }
}

data "terraform_remote_state" "terraform-enterprise" {
  backend = "local"

  config = {
    path = "../terraform-enterprise/terraform.tfstate"
  }
}

locals {
  tfc_agent_user_data = templatefile(
    "templates/installagent.sh.tpl",
    {
      region           = data.terraform_remote_state.main.outputs.region
      tfcagent_service = filebase64("files/tfc-agent.service")
      agent_token_id   = aws_secretsmanager_secret.agent_token.id
      tfe_hostname     = data.terraform_remote_state.terraform-enterprise.outputs.tfe_hostname
    }
  )
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
  name   = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-tfe-secretsmanager"
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
  name_prefix        = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-tfe"
  assume_role_policy = data.aws_iam_policy_document.instance_role.json
}

resource "aws_iam_instance_profile" "tfe" {
  name_prefix = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-tfe"
  role        = aws_iam_role.instance_role.name
}

resource "aws_secretsmanager_secret" "agent_token" {
  description             = "TFC agent token"
  name                    = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-agent_token"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "agent_token" {
  secret_string = var.agent_token
  secret_id     = aws_secretsmanager_secret.agent_token.id
}

resource "aws_iam_role_policy" "tfe_asg_discovery" {
  name   = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-tfe-asg-discovery"
  role   = aws_iam_role.instance_role.id
  policy = data.aws_iam_policy_document.tfe_asg_discovery.json
}

resource "aws_launch_configuration" "tfc_agent" {
  name_prefix   = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-tfc_agent-launch-configuration"
  image_id      = var.agent_ami
  instance_type = var.instance_type_agent

  user_data_base64 = base64encode(local.tfc_agent_user_data)

  iam_instance_profile = aws_iam_instance_profile.tfe.name
  key_name             = data.terraform_remote_state.main.outputs.ssh_key_name
  security_groups      = [data.terraform_remote_state.main.outputs.internal_sg_id]

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
    http_tokens                 = "optional"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 40
    delete_on_termination = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "tfc_agent" {
  name                      = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-asg-tfc_agent"
  min_size                  = var.asg_min_agents
  max_size                  = var.asg_max_agents
  desired_capacity          = var.asg_desired_agents
  vpc_zone_identifier       = [data.terraform_remote_state.main.outputs.subnet_private1_id, data.terraform_remote_state.main.outputs.subnet_private2_id]
  health_check_grace_period = 900
  health_check_type         = "EC2"
  launch_configuration      = aws_launch_configuration.tfc_agent.name
  tag {
    key                 = "Name"
    value               = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-asg-tfc_agent"
    propagate_at_launch = true
  }
}

data "aws_instances" "tfc_agent" {
  instance_tags = {
    Name = "${data.terraform_remote_state.main.outputs.friendly_name_prefix}-asg-tfc_agent"
  }
  filter {
    name   = "instance.group-id"
    values = [data.terraform_remote_state.main.outputs.internal_sg_id]
  }
  instance_state_names = ["running"]
}

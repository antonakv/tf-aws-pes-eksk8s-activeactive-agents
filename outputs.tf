output "ssh_key_name" {
  value       = var.key_name
  description = "SSH key name"
}
output "vpc_id" {
  value       = aws_vpc.vpc.id
  description = "ID of aws vpc"
}
output "internal_sg_id" {
  value       = aws_security_group.internal_sg.id
  description = "ID of internal security group"
}
output "public_sg_id" {
  value       = aws_security_group.public_sg.id
  description = "ID of public security group"
}
output "friendly_name_prefix" {
  value       = local.friendly_name_prefix
  description = "Friendly name prefix"
}
output "subnet_public1_id" {
  value       = aws_subnet.subnet_public1.id
  description = "ID of aws public subnet 1"
}
output "subnet_public2_id" {
  value       = aws_subnet.subnet_public2.id
  description = "ID of aws public subnet 2"
}
output "subnet_private1_id" {
  value       = aws_subnet.subnet_private1.id
  description = "ID of aws private subnet 1"
}
output "subnet_private2_id" {
  value       = aws_subnet.subnet_private2.id
  description = "ID of aws private subnet 2"
}
output "region" {
  description = "AWS region"
  value       = var.region
}
output "aws_s3_bucket_arn" {
  value       = aws_s3_bucket.tfe_data.arn
  description = "TFE S3 bucket arn"
}

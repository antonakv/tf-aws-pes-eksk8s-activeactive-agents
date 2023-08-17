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
output "friendly_name_id" {
  value       = random_string.friendly_name.id
  description = "Friendly name id"
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
output "aws_s3_bucket_name" {
  value       = aws_s3_bucket.tfe_data.id
  description = "AWS S3 bucket name"
}
output "postgres_db_name" {
  value       = var.postgres_db_name
  description = "Postgresql DB name"
}
output "postgres_username" {
  value       = var.postgres_username
  description = "Postgresql username"
}
output "postgres_password" {
  value       = random_string.pgsql_password.result
  description = "Postgresql password"
  sensitive   = true
}
output "postgres_endpoint" {
  value       = aws_db_instance.tfe.endpoint
  description = "Postgresql host"
}
output "redis_password" {
  value       = random_id.redis_password.hex
  description = "Redis password"
}
output "redis_host" {
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  description = "Redis host"
}

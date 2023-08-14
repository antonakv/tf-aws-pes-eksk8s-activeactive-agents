variable "region" {
  type        = string
  description = "AWS region"
}
variable "cidr_vpc" {
  type        = string
  description = "Amazon EC2 VPC net"
}
variable "cidr_subnet_private_1" {
  type        = string
  description = "Amazon EC2 subnet 1 private"
}
variable "cidr_subnet_private_2" {
  type        = string
  description = "Amazon EC2 subnet 2 private"
}
variable "cidr_subnet_public_1" {
  type        = string
  description = "Amazon EC2 subnet 1 public"
}
variable "cidr_subnet_public_2" {
  type        = string
  description = "Amazon EC2 subnet 2 public"
}
variable "aws_az_1" {
  type        = string
  description = "Amazon AWS availability zone 1"
}
variable "aws_az_2" {
  type        = string
  description = "Amazon AWS availability zone 2"
}
variable "instance_type_redis" {
  description = "Amazon Elasticashe Redis instance type"
}
variable "key_name" {
  description = "Name of Amazon EC2 keypair for the specific region"
}
variable "db_instance_type" {
  description = "Amazon EC2 RDS instance type"
}
variable "postgres_db_name" {
  type        = string
  description = "Postgres database DB name"
}
variable "postgres_engine_version" {
  type        = string
  description = "Postgres engine version"
}
variable "postgres_username" {
  type        = string
  description = "Postgres database username"
}

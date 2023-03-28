// AWS Variables

variable "aws_region" {
  type    = string
  sensitive   = true
}

variable "aws_access_key" {
  type    = string
  sensitive   = true
}

variable "aws_secret_key" {
  type    = string
  sensitive   = true
}

variable "aws_key_pair" {
  type = string
  sensitive   = true
}

// OPA Enrollment Token

variable "opa_enrollment_token" {
  type = string
}
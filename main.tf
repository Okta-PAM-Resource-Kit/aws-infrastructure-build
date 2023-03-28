// Terraform Script to Build Basic AWS Infrastructure for OPA
// Author: Daniel Harris @ Okta

// Initial Configuration
// Required Terraform Providers

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.58.0"
    }
  }
}

// Terraform Provider Configuration
// Amazon Web Services
provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

// AWS - Create OPA Demo Network on AWS (VPC, Internet Gateway, Route, Subnet, Interfaces)
// AWS - Create VPC
resource "aws_vpc" "opa-vpc" {
  cidr_block = "172.20.0.0/16"

  tags = {
    Name = "opa-vpc"
    Project = "opa-terraform"
  }
}

// AWS - Create Internet Gateway
resource "aws_internet_gateway" "opa-internet-gateway" {
  vpc_id = "${aws_vpc.opa-vpc.id}"

  tags = {
  Name = "opa-internet-gateway"
  Project = "opa-terraform"
  }
}

// AWS - Create Route
resource "aws_route" "opa-route" {
  route_table_id         = "${aws_vpc.opa-vpc.main_route_table_id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${aws_internet_gateway.opa-internet-gateway.id}"
}

// AWS - Create Subnet
resource "aws_subnet" "opa-subnet" {
  vpc_id            = aws_vpc.opa-vpc.id
  cidr_block        = "172.20.10.0/24"
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "opa-subnet"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Linux-Target Network Interface
resource "aws_network_interface" "opa-linux-target-interface" {
  subnet_id   = aws_subnet.opa-subnet.id
  private_ips = ["172.20.10.200"]
  security_groups = [aws_security_group.opa-linux-target.id]

 tags = {
    Name = "opa-linux-interface"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Windows-Target Network Interface
resource "aws_network_interface" "opa-windows-target-interface" {
  subnet_id   = aws_subnet.opa-subnet.id
  private_ips = ["172.20.10.210"]
  security_groups = [aws_security_group.opa-windows-target.id]

 tags = {
    Name = "opa-windows-target-interface"
    Project = "opa-terraform"
  }
}

// AWS - Look Up Latest Ubuntu Image on AWS
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

// AWS - Look Up Latest Windows Image on AWS
data "aws_ami" "windows" {
  most_recent = true
  
  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base-*"]
 }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
 }
  owners = ["801119661308"] # Canonical
 }


// AWS - Create OPA-Linux-Target
resource "aws_instance" "opa-linux-target" {
  ami                           = data.aws_ami.ubuntu.id
  instance_type                 = "t2.micro"
  key_name                      = var.aws_key_pair
  user_data_replace_on_change   = true
  user_data                     = <<EOF
#!/bin/bash
echo "Retrieve information about new packages"
sudo apt-get update
sudo apt-get install -y curl

echo "Stable Branch"
echo "Add APT Key"
curl https://dist.scaleft.com/GPG-KEY-OktaPAM-2023 | gpg --dearmor | sudo cat >/usr/share/keyrings/oktapam-2023-archive-keyring.gpg
echo "Create List"
printf "deb [signed-by=/usr/share/keyrings/oktapam-2023-archive-keyring.gpg] https://dist.scaleft.com/repos/deb focal okta" | sudo tee /etc/apt/sources.list.d/oktapam-stable.list > /dev/null
sudo apt-get update

echo "Install Server Tools"
sudo mkdir -p /var/lib/sftd
sudo mkdir -p /etc/sft
echo ${var.opa_enrollment_token} > /var/lib/sftd/enrollment.token
echo "CanonicalName: opa-linux-target" | sudo tee /etc/sft/sftd.yaml
echo "Labels:" >> /etc/sft/sftd.yaml
echo "  role: devops" >> /etc/sft/sftd.yaml
echo "  env: staging" >> /etc/sft/sftd.yaml
sudo apt-get install scaleft-server-tools scaleft-client-tools
EOF
  
  tags = {
    Name        = "opa-linux-target"
    Project     = "opa-terraform"
  }

  network_interface {
    network_interface_id = aws_network_interface.opa-linux-target-interface.id
    device_index         = 0
  }
}

// AWS - Create OPA-Linux-Target Security Group
resource "aws_security_group" "opa-linux-target" {
  name        = "opa-linux-target"
  description = "Ports required for OPA Linux Target"
  vpc_id      = aws_vpc.opa-vpc.id
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow incoming SSH connections"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "opa-linux-target"
    Project = "opa-terraform"
  }
}


// AWS - Create OPA-Windows-Target
resource "aws_instance" "opa-windows-target" {
  ami = data.aws_ami.windows.id
  instance_type = "t2.micro"
  key_name = var.aws_key_pair
  user_data_replace_on_change = true
  user_data = <<EOF
<script>
mkdir C:\Windows\System32\config\systemprofile\AppData\Local\scaleft
echo CanonicalName: opa-windows-target > C:\Windows\System32\config\systemprofile\AppData\Local\scaleft\sftd.yaml
echo ${var.opa_enrollment_token}  > C:\windows\system32\config\systemprofile\AppData\Local\scaleft\enrollment.token
msiexec /qb /I https://dist.scaleft.com/server-tools/windows/latest/ScaleFT-Server-Tools-latest.msi
net stop scaleft-server-tools && net start scaleft-server-tools
</script>
  EOF
  
  tags = {
    Name        = "opa-windows-target"
    Project     = "opa-terraform"
  }

  network_interface {
    network_interface_id = aws_network_interface.opa-windows-target-interface.id
    device_index         = 0
  }
}

// AWS - Create OPA-Windows-Target Security Group
resource "aws_security_group" "opa-windows-target" {
  name        = "opa-windows-target"
  description = "Ports required for OPA Windows Target"
  vpc_id      = aws_vpc.opa-vpc.id
  
  ingress {
    from_port   = 4421
    to_port     = 4421
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow incoming Broker port connections"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "opa-windows-target"
    Project = "opa-terraform"
  }
}
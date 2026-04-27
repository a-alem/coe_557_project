// Key pairs
resource "aws_key_pair" "coe_557_project" {
  key_name   = "coe-557-project-key"
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5QuTPbqOJxxv27WAR9nnd5jgG5thSd+sO4t/77LdkY coe557 project"
}

// Instances EC2
resource "aws_instance" "coe_557_project_server" {
  ami = "ami-0281b0943230d40d1"
  instance_type = "t3.xlarge"
  availability_zone = var.av_zone
  subnet_id = aws_subnet.coe_557_subnet_public.id
  key_name = aws_key_pair.coe_557_project.key_name
  root_block_device {
    volume_size = 60
  }
  vpc_security_group_ids = [
    aws_security_group.allow_ssh_coe_557.id
  ]
  tags = {
    Name = "coe-557-project-instance"
  }
}
# Infrastructure

## Prerequistes 
- [Amazon CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
- [Set up AWS Profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.htm)
- [Install Terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli)

## Config

1) Configure AWS profile dev
    aws configure --profile dev 

1) Open Terminal and go to your profile 
    export AWS_profile=dev


## Terraform Commands

    1) Initialize terraform using following command

        terraform init

    2) Check terraform by verifying the resources without executing

        terraform plan --var-file=dev.tf.vars 

    3) Execute Terraform

        terraform apply --var-file=dev.tf.vars 

    4) Destroy Terraform

        terraform destroy --var-file=dev.tf.vars 

## Note - dev.tf.vars file is a variable file respective to this projects

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

## Import certificate to ACM to use for load balancer

Use Certificate Authority like Namecheap to get SSL certificate.
Follow the steps below to Request the certificate

1. Purchase certificate from CA 
2. Request certificate with CSR. Refer this [Namecheap Documentation](https://www.namecheap.com/support/knowledgebase/article.aspx/9592/14/generating-a-csr-on-amazon-web-services-aws/)
3. Once certificate is issued, you have two options: Import certificate to ACM or Upload the certificate. `AWS_PROFILE` environment variable needs to be exported first
4. Import certificate to ACM (Recommended):

    Follow this [instruction](https://docs.aws.amazon.com/acm/latest/userguide/import-certificate-api-cli.html#import-certificate-cli) to import to ACM. This is better approach because once certificate is imported, it can be seen in ACM of AWS Console.

        - $ aws acm import-certificate --certificate fileb://Certificate.pem \
            --certificate-chain fileb://CertificateChain.pem \
            --private-key fileb://PrivateKey.pem 

### Troubleshooting

https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html#server-certificate-troubleshooting
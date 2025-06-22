# cert-tracker

[![codecov](https://codecov.io/gh/gregalia/cert-tracker/graph/badge.svg?token=3AYX4VIB3L)](https://codecov.io/gh/gregalia/cert-tracker)

SSL/TLS certificate monitoring tool that continuously tracks certificate details for specified hostnames.

## Run Locally

### Prerequisites

- Docker
- Dual-stack internet connection
  - Not required, but you'll see errors in the logs

Before we run the app, let's see if we have IPv6 connectivity:

```sh
ping6 2606:4700:4700::1111
```

Create an IPv6 docker network and test:[^docker-ipv6]

```sh
docker network create --ipv6 --subnet=2001:db8:1::/64 ipv6net
docker run --rm --publish=80:80 --network=ipv6net --name=whoami --detach traefik/whoami
curl 'http://[::1]'
docker stop whoami
```

You should see IPv6 addresses in the output:

```txt
[...]
IP: 2001:db8:1::2
IP: fe80::9c72:3aff:feae:5520
[...]
```

Run the application with the IPv6 network:

```sh
cd app
docker buildx build --tag=cert-tracker .
docker run --network=ipv6net cert-tracker
```

## Run on AWS

You can deploy the application and infrastructure independently.

### Run CDK Deployment Locally

Build AWS infrastructure:

```sh
cd infra
docker buildx build --tag=cdk --target=cdk-run .
```

Before running a CDK app in an AWS account, you must bootstrap the CDK into that AWS account.[^cdk-bootstrap]

Once that's complete, you need to run the CDK app in the context of an authenticated AWS session.

To do that with environment variables:

```sh
aws configure export-credentials --format env-no-export >.env
docker run --interactive --tty --env-file=.env cdk <subcommand>
```

Show the CloudFormation Template to deploy with `cdk synth`; deploy it with `cdk deploy`; remove it with `cdk destroy`.[^cdk-cli]

[^docker-ipv6]: https://docs.docker.com/engine/daemon/ipv6
[^cdk-bootstrap]: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
[^cdk-cli]: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd.html

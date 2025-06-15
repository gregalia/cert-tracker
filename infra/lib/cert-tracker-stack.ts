import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export class CertTrackerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const isProd = this.node.tryGetContext("is-prod");
    if (!["true", "false", undefined].includes(isProd)) {
      throw new Error("is-prod context must be 'true' or 'false' if set");
    }
    const removalPolicy = isProd === "true" ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY;

    const repository = new ecr.Repository(this, "CertTrackerRepository", {
      repositoryName: "cert-tracker",
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.MUTABLE,
      removalPolicy,
    });

    // workaround for chicken/egg problem: ECS needs image but app image needs ECR
    const bootstrapECR = this.node.tryGetContext("bootstrap-ecr");
    if (!["true", "false", undefined].includes(bootstrapECR)) {
      throw new Error("bootstrap-ecr context must be 'true' or 'false' if set");
    }
    if (bootstrapECR) {
      cdk.Annotations.of(this).addInfo("✅ ECR repository created");
      cdk.Annotations.of(this).addInfo("📦 Next: Push your image, then redeploy without --context=bootstrap-ecr=true");
    } else {
      const vpc = new ec2.Vpc(this, "CertTrackerVpc", {
        maxAzs: 2,
        natGateways: 0,
        enableDnsHostnames: true,
        enableDnsSupport: true,
        subnetConfiguration: [
          {
            cidrMask: 24,
            name: "Public",
            subnetType: ec2.SubnetType.PUBLIC,
          },
        ],
      });

      // Steps to enable IPv6
      // 1. Associate IPv6 CIDR block with VPC
      const ipv6Block = new ec2.CfnVPCCidrBlock(this, "Ipv6CidrBlock", {
        vpcId: vpc.vpcId,
        amazonProvidedIpv6CidrBlock: true,
      });

      // 2: Auto-assign IPv6 to subnets and enable IPv6 address assignment
      vpc.publicSubnets.forEach((subnet, index) => {
        const cfnSubnet = subnet.node.defaultChild as ec2.CfnSubnet;
        cfnSubnet.assignIpv6AddressOnCreation = true;
        cfnSubnet.addDependency(ipv6Block);

        // 3. Set IPv6 CIDR on subnet
        cfnSubnet.ipv6CidrBlock = cdk.Fn.select(index, cdk.Fn.cidr(cdk.Fn.select(0, vpc.vpcIpv6CidrBlocks), 4, "64"));
      });

      // 4: Add IPv6 route to internet gateway
      vpc.publicSubnets.forEach((subnet, index) => {
        new ec2.CfnRoute(this, `Ipv6Route${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationIpv6CidrBlock: "::/0",
          gatewayId: vpc.internetGatewayId,
        });
      });

      const cluster = new ecs.Cluster(this, "CertTrackerCluster", {
        vpc,
        clusterName: "cert-tracker-cluster",
      });

      const logGroup = new logs.LogGroup(this, "CertTrackerLogGroup", {
        logGroupName: "/ecs/cert-tracker",
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy,
      });

      const taskDefinition = new ecs.FargateTaskDefinition(this, "CertTrackerTaskDef", {
        memoryLimitMiB: 512,
        cpu: 256,
        runtimePlatform: {
          operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
          cpuArchitecture: ecs.CpuArchitecture.ARM64,
        },
      });

      taskDefinition.addContainer("cert-tracker", {
        image: ecs.ContainerImage.fromRegistry(`${repository.repositoryUri}:latest`),
        logging: ecs.LogDrivers.awsLogs({
          streamPrefix: "cert-tracker",
          logGroup,
        }),
      });

      repository.grantPull(taskDefinition.executionRole!);

      const service = new ecs.FargateService(this, "CertTrackerService", {
        cluster,
        taskDefinition,
        desiredCount: 1,
        minHealthyPercent: 0,
        assignPublicIp: true,
        serviceName: "cert-tracker-service",
        platformVersion: ecs.FargatePlatformVersion.VERSION1_4, // required for IPv6
        vpcSubnets: {
          subnetType: ec2.SubnetType.PUBLIC,
        },
      });

      service.connections.allowTo(ec2.Peer.anyIpv6(), ec2.Port.tcp(443));
      service.connections.allowTo(ec2.Peer.anyIpv6(), ec2.Port.udp(53));
    }
  }
}

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
      throw new Error("is-prod context must be 'true' or 'false'");
    }
    const removalPolicy = isProd === "true" ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY;

    const repository = new ecr.Repository(this, "CertTrackerRepository", {
      repositoryName: "cert-tracker",
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.MUTABLE,
      removalPolicy,
    });

    // using public subnets for IPv6
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

    // running in public subnet for IPv6 connectivity
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

    service.connections.allowToAnyIpv4(ec2.Port.tcp(443));
    service.connections.allowTo(ec2.Peer.anyIpv6(), ec2.Port.tcp(443));
    service.connections.allowToAnyIpv4(ec2.Port.udp(53));
    service.connections.allowTo(ec2.Peer.anyIpv6(), ec2.Port.udp(53));
  }
}

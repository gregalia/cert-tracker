#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { CertTrackerStack } from './lib/cert-tracker-stack';

const app = new cdk.App();

const region = process.env.CDK_DEFAULT_REGION;
if (!region) {
  throw new Error('AWS region must be configured. Set AWS_REGION or run: aws configure set region <region>');
}

new CertTrackerStack(app, 'CertTrackerStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region,
  },
});

app.synth();
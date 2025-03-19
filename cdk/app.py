#!/usr/bin/env python3
import os
from aws_cdk import (
    App,
    Stack,
    aws_lambda as _lambda,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_ecr as ecr,
    Duration,
    RemovalPolicy,
    CfnOutput
)
from constructs import Construct

class ContainerImageManagementStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create ECR repository
        repository = ecr.Repository(
            self, "ContainerImageRepository",
            repository_name="container-images",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_images=True
        )

        # Create Lambda function
        lambda_function = _lambda.Function(
            self, "ImageScannerFunction",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.minutes(5),
            environment={
                "ECR_REPOSITORY_NAME": repository.repository_name,
                "MAX_IMAGE_AGE_DAYS": "30",
                "SEVERITY_THRESHOLD": "HIGH"
            },
            memory_size=1024,
            vpc=None  # Add VPC configuration if needed
        )

        # Grant Lambda permissions to ECR
        repository.grant_pull_push(lambda_function)
        lambda_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ecr:BatchGetImage",
                    "ecr:BatchDeleteImage",
                    "ecr:PutImage",
                    "ecr:DescribeImages"
                ],
                resources=[repository.repository_arn]
            )
        )

        # Create EventBridge rule to trigger Lambda daily
        rule = events.Rule(
            self, "DailyScanRule",
            schedule=events.Schedule.rate(Duration.days(1)),
            targets=[targets.LambdaFunction(lambda_function)]
        )

        # Output the repository URI
        CfnOutput(self, "RepositoryURI", value=repository.repository_uri)

app = App()
ContainerImageManagementStack(app, "ContainerImageManagementStack")
app.synth() 
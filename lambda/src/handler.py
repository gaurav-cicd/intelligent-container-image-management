import os
import json
import boto3
import subprocess
from datetime import datetime, timedelta
from dateutil import parser

# Initialize AWS clients
ecr = boto3.client('ecr')
s3 = boto3.client('s3')

def get_image_vulnerabilities(image_uri):
    """
    Scan container image using Trivy and return vulnerability information
    """
    try:
        # Run Trivy scan
        result = subprocess.run(
            ['trivy', 'image', '--format', 'json', image_uri],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error scanning image {image_uri}: {str(e)}")
        return None

def tag_image_by_severity(repository, image_digest, vulnerabilities):
    """
    Tag image based on vulnerability severity
    """
    severity_levels = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1
    }
    
    max_severity = 0
    for vuln in vulnerabilities:
        severity = vuln.get('Severity', 'LOW')
        max_severity = max(max_severity, severity_levels.get(severity, 0))
    
    severity_tag = f"severity-{max_severity}"
    
    try:
        ecr.put_image(
            repositoryName=repository,
            imageManifest=ecr.batch_get_image(
                repositoryName=repository,
                imageIds=[{'imageDigest': image_digest}]
            )['imageDetails'][0]['imageManifest'],
            imageTag=severity_tag
        )
        return severity_tag
    except Exception as e:
        print(f"Error tagging image: {str(e)}")
        return None

def cleanup_old_images(repository, max_age_days):
    """
    Clean up images older than specified days
    """
    try:
        images = ecr.describe_images(repositoryName=repository)['imageDetails']
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        
        for image in images:
            if 'imagePushedAt' in image:
                pushed_date = parser.parse(image['imagePushedAt'])
                if pushed_date < cutoff_date:
                    ecr.batch_delete_image(
                        repositoryName=repository,
                        imageIds=[{'imageDigest': image['imageDigest']}]
                    )
                    print(f"Deleted old image: {image['imageDigest']}")
    except Exception as e:
        print(f"Error cleaning up old images: {str(e)}")

def lambda_handler(event, context):
    """
    Main Lambda handler function
    """
    try:
        repository = os.environ['ECR_REPOSITORY_NAME']
        max_age_days = int(os.environ.get('MAX_IMAGE_AGE_DAYS', '30'))
        severity_threshold = os.environ.get('SEVERITY_THRESHOLD', 'HIGH')
        
        # Get all images in the repository
        images = ecr.describe_images(repositoryName=repository)['imageDetails']
        
        for image in images:
            image_uri = f"{repository}:{image['imageTags'][0] if 'imageTags' in image else 'latest'}"
            
            # Scan image for vulnerabilities
            vulnerabilities = get_image_vulnerabilities(image_uri)
            if vulnerabilities:
                # Tag image based on severity
                severity_tag = tag_image_by_severity(repository, image['imageDigest'], vulnerabilities)
                if severity_tag:
                    print(f"Tagged image {image_uri} with {severity_tag}")
        
        # Clean up old images
        cleanup_old_images(repository, max_age_days)
        
        return {
            'statusCode': 200,
            'body': json.dumps('Image scanning and cleanup completed successfully')
        }
        
    except Exception as e:
        print(f"Error in Lambda handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        } 
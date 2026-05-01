# AWS Lab: Automating EC2 Management with Lambda and EventBridge

## Overview
This lab focused on **Serverless Computing** and **Event-Driven Architecture**. I created an AWS Lambda function—a "Stopinator"—designed to automatically manage EC2 instance states without requiring a persistent server. By integrating Lambda with Amazon EventBridge, I established a scheduled trigger that ensures cost-optimization by automatically stopping target instances at defined intervals.



## Objectives
*   **Develop** an AWS Lambda function using the Python runtime.
*   **Implement** Least Privilege by associating the function with a specific IAM role (`myStopinatorRole`).
*   **Schedule** automated triggers using Amazon EventBridge (formerly CloudWatch Events).
*   **Script** automation using the **Boto3** library (AWS SDK for Python) to interact with EC2 resources.

---

## Technical Implementation Details

### 1. Function Logic & Environment
The core of the lab involved writing a Python-based Lambda function. This function utilizes the Boto3 client to send a `stop_instances` command to the AWS EC2 API.

*   **Runtime:** Python 3.11
*   **Permissions:** The function was granted specific permissions to modify EC2 states via an existing IAM execution role.

### 2. Event-Driven Triggering
Rather than manual execution, the function was tied to an **EventBridge Rule**. 
*   **Rule Type:** Schedule Expression.
*   **Rate:** `rate(1 minute)`.
*   **Context:** While a production environment would typically use a `cron` expression (e.g., stopping instances at 6:00 PM every Friday), the `rate` expression allowed for immediate verification of the automation logic.

### 3. Scripting and Deployment
I updated the boilerplate code with environment-specific variables to target the correct resources:

```python
import boto3

# Configuration
region = 'us-east-1' # Example Region
instances = ['i-0abcd1234efgh5678'] # Target Instance ID
ec2 = boto3.client('ec2', region_name=region)

def lambda_handler(event, context):
    ec2.stop_instances(InstanceIds=instances)
    print('stopped your instances: ' + str(instances))
```

---

## Recovery & Validation Workflow

### 4. Monitoring & Verification
I validated the success of the automation through two primary methods:
1.  **CloudWatch Metrics:** Checked the **Monitor** tab in the Lambda console to verify "Invocations" and "Success Rate" charts.
2.  **State Verification:** Manually attempted to "Start" the EC2 instance in the console. As expected, the EventBridge trigger detected the schedule and the Lambda function moved the instance back to a "Stopped" state within 60 seconds.

---

## Outcomes & Key Learnings
*   **Serverless Efficiency:** Confirmed that Lambda allows for complex infrastructure management tasks without the overhead of maintaining a management server.
*   **SDK Proficiency:** Gained experience using **Boto3** to programmatically control AWS resources, which is fundamental for DevOps and SysOps automation.
*   **Cost Optimization:** Learned a practical method for reducing AWS spend by ensuring non-production instances do not run outside of necessary hours.
*   **Execution Roles:** Reaffirmed the importance of IAM roles in providing secure, temporary credentials to serverless functions.
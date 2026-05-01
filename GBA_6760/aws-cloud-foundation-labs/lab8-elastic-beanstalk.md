# AWS Lab: Platform-as-a-Service with Elastic Beanstalk

## Overview
This lab focused on **Amazon Elastic Beanstalk**, a Platform-as-a-Service (PaaS) offering that simplifies the deployment and scaling of web applications. I transitioned from manual resource management to automated orchestration, deploying a Java Tomcat application and observing how AWS automatically provisions the underlying compute, load balancing, and scaling infrastructure.



## Objectives
*   **Deploy** a web application package (`.zip`) to a pre-configured Elastic Beanstalk environment.
*   **Validate** application availability using the provided environment Domain URL.
*   **Analyze** the management console to monitor environment health and performance metrics.
*   **Audit** the underlying AWS resources (EC2, ASG, ELB) created automatically by the service.

---

## Technical Implementation Details

### 1. Application Deployment
I performed an "Upload and Deploy" operation to transition the environment from an empty state (HTTP 404) to a functional web application.
*   **Source Bundle:** `tomcat.zip` (Sample Java application). 
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/samples/tomcat.zip
*   **Process:** Elastic Beanstalk handled the extraction of the code, service configuration, and the rolling update across the EC2 instances.

### 2. Environment Configuration
Through the Elastic Beanstalk Dashboard, I explored the managed configuration of the stack:
*   **Scaling:** Observed the Auto Scaling group settings (configured for a range of 2 to 6 instances).
*   **Monitoring:** Reviewed integrated CloudWatch metrics that track request latency, CPU utilization, and HTTP 2xx/4xx/5xx response codes.

---

## Infrastructure Exploration

### 3. Automated Resource Provisioning
While Elastic Beanstalk manages the "application" layer, it provisions standard AWS resources in the background. I verified the following components within the EC2 Console:

| Component | Purpose |
| :--- | :--- |
| **EC2 Instances** | Two running instances (prefixed with `samp`) acting as the web workers. |
| **Elastic Load Balancer (ELB)** | Distributes incoming traffic across the two web worker instances. |
| **Auto Scaling Group (ASG)** | Ensures high availability by maintaining the instance count and responding to load. |
| **Security Groups** | Automatically configured to permit inbound traffic on **Port 80** (HTTP). |

---

## Outcomes & Key Learnings
*   **Final Score:** 100%
*   **PaaS Efficiency:** Confirmed that Elastic Beanstalk significantly reduces the "heavy lifting" of infrastructure setup, allowing developers to focus entirely on code.
*   **Full Visibility:** Learned that even though the service is managed, the user retains full visibility and control over the underlying EC2 instances and networking components.
*   **Simplified Scaling:** Observed how easily a database can be attached or scaling rules can be modified through a single unified interface rather than configuring individual services.
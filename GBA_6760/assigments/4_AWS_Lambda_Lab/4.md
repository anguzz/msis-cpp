# AWS Lambda + Amazon S3 Thumbnail Generator Lab

## Objectives

URL: https://skillbuilder.aws/learn/G3BEYRFNPS/introduction-to-aws-lambda/5PSQXY58Y7 

By the end of this lab I did the following:

* Created an **AWS Lambda function**
* Configured an **Amazon S3 bucket as a Lambda event source**
* Trigger a **Lambda function by uploading an object to Amazon S3**
* Monitor **AWS Lambda executions using Amazon CloudWatch Logs**



# Why This Lab Exists

At first this architecture seemed **over-engineered** to me,  but after some research I found out it solves real problems that appear when systems need to scale.

This lab demonstrates a **serverless event-driven architecture** where cloud services automatically respond to events.


# Traditional Approach (Before Serverless)

Before serverless computing, image processing pipelines typically worked like this:

```
User Uploads file
      ↓
Web Server (Apache / Nginx / Node etc)
      ↓
Application resizes image
      ↓
Image stored in filesystem or database
```

### Problems with this approach

**1. Processing blocks the application**

If resizing images takes time, the web server becomes busy doing CPU work instead of serving users.


**2. Scaling becomes difficult**

If thousands of users upload images simultaneously:

* servers can become overloaded
* load balancers are required
* additional infrastructure must be deployed


**3. Infrastructure management**

Organizations must manage:

* server maintenance
* operating system updates
* scaling policies
* failure recovery


**4. Mixed responsibilities**

One server handles:

* user requests
* image processing
* file storage

This makes the architecture harder to maintain.


# Serverless Architecture Used in This Lab

This lab separates responsibilities between AWS services.

### Amazon S3

Handles **storage only**.

### AWS Lambda

Handles **compute only**.

### Event Trigger

Lambda runs **only when an upload event occurs**.


## Serverless Workflow

```
User uploads image
        ↓
Amazon S3 Source Bucket
        ↓
S3 Object Created Event
        ↓
AWS Lambda Function Executes
        ↓
Image resized to thumbnail
        ↓
Thumbnail saved to second S3 bucket
```


# Benefits of This Architecture

## Automatic Scaling

If:

```
1 image uploaded → 1 Lambda runs
10,000 images uploaded → AWS runs thousands of Lambdas
```

AWS handles scaling automatically.


## Cost Efficiency

You only pay for **milliseconds of compute time**.

Traditional servers cost money even when idle.


## Reliability

AWS automatically manages:

* infrastructure
* failover
* scaling
* availability


## Faster User Experience

Users upload an image and immediately continue using the application.

Image resizing occurs **asynchronously in the background**.


# Key Cloud Concept: Event-Driven Architecture

This architecture pattern is extremely common in modern cloud systems.

Examples include:

* image processing pipelines
* video transcoding
* log processing
* data pipelines
* automation workflows
* notifications


# How AWS Lambda Works

A Lambda function consists of:

* application code
* runtime environment (Python, Node, etc.)
* configuration (memory, timeout, permissions)

When an event occurs, AWS launches an **execution environment** to run the function.


# Lambda Execution Environments

Lambda runs inside **Firecracker micro-VMs**.

Firecracker provides:

* very fast startup times
* strong security isolation
* minimal system overhead

Conceptually:

```
Lambda invocation
        ↓
Firecracker micro-VM starts
        ↓
Runtime loads
        ↓
Lambda function executes
```

Each invocation runs in its **own isolated environment**.


# Lambda Scaling Model

When many events occur simultaneously:

```
S3 Upload Events
        ↓
Lambda service receives events
        ↓
Execution environments created

Environment 1 → process image A
Environment 2 → process image B
Environment 3 → process image C
Environment 4 → process image D
```

Important rule:

**One Lambda environment processes one request at a time.**


# Cold Starts vs Warm Starts

### Cold Start

```
Start micro-VM
Load runtime
Run function
```

### Warm Start

```
Reuse existing environment
Run function again
```

Warm starts are significantly faster.


# Lambda Concurrency

Default AWS account concurrency limit:

```
1000 concurrent executions
```

AWS can increase this limit if necessary.


# Firecracker Overview

Firecracker is a lightweight virtualization technology built by AWS.
```
| Technology            | Pros             | Cons             |
|                       |-                 |-                 |
| Virtual Machines      | strong isolation | slower startup   |
| Containers            | fast startup     | weaker isolation |
| Firecracker Micro-VMs | fast + isolated  | specialized use  |
```
Firecracker enables Lambda to launch thousands of secure environments extremely quickly.


# Understanding Amazon S3

Amazon S3 is an **object storage service**.

Structure:

```
Amazon S3
   ├── Bucket A
   ├── Bucket B
   └── Bucket C
```

A **bucket** is a container that stores files.

An **object** is the file stored in the bucket.


# S3 Analogy

Think of S3 like **Google Drive**.

```
| AWS Term | Real World Equivalent |
|----------|---------------------- |
| S3       | Google Drive          |
| Bucket   | Folder                |
| Object   | File                  |
```

# Why Two Buckets Are Used

The lab uses two buckets:

### Source Bucket

Stores the original uploaded image.

```
images-7777771
    HappyFace.jpg
```


### Target Bucket

Stores the resized thumbnail.

```
images-7777771-resized
    HappyFace.jpg
```


# Why Not Use One Bucket?

If the resized image were saved to the same bucket:

```
Upload image
   ↓
Lambda runs
   ↓
Thumbnail uploaded
   ↓
S3 detects upload again
   ↓
Lambda runs again
```

This would create an **infinite loop**.

Using two buckets prevents this.


# AWS Lambda Handler

The **handler** is the entry point of the Lambda function.

Format:

```
filename.function
```

Example used in this lab:

```
CreateThumbnail.handler
```

Meaning:

* `CreateThumbnail` → Python file
* `handler` → function inside the file

Example code:

```python
def handler(event, context):
```

Lambda starts execution here.


# Lambda Event Data

When S3 triggers Lambda, it sends an **event JSON** containing details about the upload.

Example:

```json
{
  "bucket": "images-7777771",
  "key": "HappyFace.jpg"
}
```

Lambda uses this data to:

1. Download the uploaded image
2. Resize it
3. Upload the thumbnail to another bucket


# Example Test Event Used in the Lab

```json
{
  "Records": [
    {
      "eventSource": "aws:s3",
      "eventName": "ObjectCreated:Put",
      "s3": {
        "bucket": {
          "name": "images-7777771",
          "arn": "arn:aws:s3:::images-7777771"
        },
        "object": {
          "key": "HappyFace.jpg"
        }
      }
    }
  ]
}
```


# Monitoring Lambda Functions

AWS Lambda logs are stored in **Amazon CloudWatch Logs**.

CloudWatch provides visibility into:

* function execution time
* invocation counts
* error rates
* memory usage
* log output

This helps developers debug serverless applications.


# Summary

In this lab I built a **serverless image processing pipeline** using AWS services.

Workflow:

```
User uploads image
        ↓
S3 source bucket
        ↓
S3 event triggers Lambda
        ↓
Lambda resizes image
        ↓
Thumbnail saved to second S3 bucket
        ↓
Logs monitored via CloudWatch
```

This architecture demonstrates **event-driven cloud design**, automatic scaling, and serverless compute.


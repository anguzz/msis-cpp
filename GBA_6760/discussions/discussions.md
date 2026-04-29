# Discussions

This file logs discussion questions and my responses for the course.

---

# Week 2 – Cloud Value Proposition

## Question
Cloud computing and cloud services have many value propositions. Please select one proposition and provide arguments to justify why this proposition is the most important. (200–300 words)

## Response
Cloud computing offers many value propositions, but the most important is operational resilience. Operational resilience refers to an organization’s ability to continue operating during hardware failures, cyber incidents, natural disasters, or sudden increases in demand. Traditional on-premises data centers are limited by physical hardware, minimal redundancy, and high maintenance overhead. These constraints make outages harder to prevent and slower to recover from.

Public cloud providers address these challenges by designing infrastructure that assumes failure will occur and builds recovery into the system. Operational resilience is supported by core cloud characteristics defined by NIST, including resource pooling, broad network access, and rapid elasticity. These features allow workloads to shift across infrastructure automatically when problems occur.

AWS identifies operational resilience as a key part of its Cloud Value Framework and notes that downtime can cost organizations hundreds of thousands to millions of dollars per hour. While cloud computing also improves cost efficiency and agility, those benefits depend on systems remaining available. Even the ability to scale quickly would not matter if cloud providers could not meet uptime guarantees through strong service level agreements (SLAs).

Without operational resilience, the other advantages of cloud computing lose much of their value. For that reason, resilience forms the foundation that makes the rest of the cloud value proposition possible.

## References
- Estrin, E. (2024). *Cloud Security Handbook* (2nd ed.). Packt Publishing.  
- National Institute of Standards and Technology. (2011). *The NIST Definition of Cloud Computing (SP 800-145).* https://csrc.nist.gov/pubs/sp/800/145/final  
- Amazon Web Services. *Business Value on AWS.* https://aws.amazon.com/executive-insights/content/business-value-on-aws/

---

# Week 3 – Cloud Security Risks

## Discussion Question(s)

- Identify at least two security risks that are particularly relevant to cloud environments and explain why they matter.  
- For each risk, propose specific mitigation strategies (technical, architectural, or governance-based).

## Response
Cloud environments introduce security risks that differ from traditional on-premises systems, especially in areas related to identity and visibility.

One major risk is excessive privileges in Identity and Access Management (IAM). In cloud systems, accounts and permissions form the primary security boundary. If users or services have more access than they require, a compromised credential could allow an attacker to modify systems, delete data, or view sensitive information. Because cloud environments scale rapidly, a single overly privileged account can potentially impact the entire organization.

To mitigate this risk, organizations should apply the principle of least privilege, implement role-based access control, require multifactor authentication, and regularly review permissions. Separating development, testing, and production environments into different accounts can also reduce the potential damage if credentials are compromised.

A second important risk is insufficient logging and monitoring. Without centralized logs and alerts, security teams may not detect attacks or configuration mistakes until after significant damage has occurred. Because cloud systems change frequently, manual monitoring is insufficient.

Cloud-native monitoring tools such as AWS CloudTrail, GuardDuty, and CloudWatch provide continuous logging and alerting. Storing logs in protected locations helps prevent tampering, and maintaining well-defined incident response procedures allows teams to respond quickly to threats. Together, these controls strengthen both prevention and detection capabilities in cloud environments.

## References
- Armstrong, J. (2020). *Migrating to AWS: A Manager's Guide.* O’Reilly Media.  
- AWS Identity and Access Management. https://aws.amazon.com/iam/  
- Amazon Web Services. *Security Products AWS.* https://aws.amazon.com/products/security/

---

# Week 4 – Discovery and Assessment

## Discussion Question(s)

The challenge of discovery and assessment is the process of figuring out what is going on right under the organization's nose. Of the different steps required to discover workloads, which step do you think is most appealing to you to participate in (if you had to participate in at least one step) and why? Justify your response.

## Response
The step I would most want to participate in is analyzing and understanding workloads. This stage focuses on identifying how applications actually operate, what systems they depend on, and how critical they are to the organization.

This step is appealing because it combines technical knowledge with analytical thinking. It is not simply about listing servers or applications, but about understanding how systems interact. For example, one application might depend on a database, storage service, or authentication system. If these dependencies are not identified early, problems may occur during migration.

Workload analysis is also important from a security perspective. By examining how applications process data and identifying who has access to them, organizations can detect potential risks before migrating systems to the cloud.

AWS explains that understanding application dependencies is critical for reducing migration risks and avoiding service disruptions. This highlights the importance of this step in ensuring a successful cloud migration process.

Overall, this stage is valuable because it influences planning, security decisions, and long-term system stability. Proper workload analysis helps ensure that migration decisions are informed, safe, and aligned with business needs.

## Reference
- Amazon Web Services. (2023). *Application discovery service overview.* https://docs.aws.amazon.com/application-discovery/

---

# Week 5 – Cloud Provider Comparison

## Discussion Question(s)

Research the offerings of major cloud providers (e.g., AWS, Azure, and Google Cloud) and evaluate them on the following criteria:

- Scalability, performance, and cost  
- Focus on specific use cases like AI/ML, big data analytics, or IoT  
- Analyze regional availability, security features, and compliance certifications  

Conclude with recommendations for different business scenarios.

## Response
Cloud providers differ most in how they balance scale, specialization, and cost control. AWS remains the strongest general-purpose option because of its global footprint, with 123 Availability Zones across 39 geographic regions. This makes it well suited for distributed applications and disaster recovery planning (Amazon Web Services, n.d.).

Microsoft Azure is also highly scalable and often fits organizations that already rely heavily on Microsoft technologies. Microsoft reports that Azure operates in more than 70 regions worldwide, providing strong support for global enterprises and hybrid cloud deployments (Microsoft, 2026).

Google Cloud is somewhat smaller in regional reach, but its 43 regions and 130 zones still offer broad coverage and strong infrastructure reliability (Google Cloud, 2026).

In terms of performance and cost, the best provider depends heavily on workload characteristics. The FinOps Foundation notes that cloud cost management has become an important operational discipline, emphasizing that governance and optimization matter as much as raw pricing (FinOps Foundation, 2025).

For AI and machine learning workloads, Google Cloud is especially compelling because its Vertex AI platform provides a unified environment for developing and scaling AI applications. Performance comparisons using MLPerf benchmarks provide a neutral way to evaluate machine learning performance across platforms (Google Cloud, n.d.-b; MLCommons, 2025). Google Cloud’s BigQuery service also offers strong advantages for big data analytics because it supports serverless, petabyte-scale queries (Google Cloud, n.d.-a).

Overall, AWS is best suited for large general-purpose enterprise environments, Azure is ideal for organizations deeply integrated with Microsoft ecosystems, and Google Cloud excels for companies focused on artificial intelligence and large-scale data analytics.

## References
- Amazon Web Services. (n.d.). *AWS global infrastructure.* https://aws.amazon.com/about-aws/global-infrastructure/  
- FinOps Foundation. (2025). *The state of FinOps report 2025.* https://data.finops.org/2025-report/  
- Google Cloud. (2026). *Global locations: Regions & zones.* https://cloud.google.com/about/locations  
- Google Cloud. (n.d.-a). *BigQuery.* https://cloud.google.com/bigquery  
- Google Cloud. (n.d.-b). *Overview of Vertex AI.* https://docs.cloud.google.com/vertex-ai/docs/start/introduction-unified-platform  
- MLCommons. (2025). *MLPerf Inference v5.0 benchmark results.* https://mlcommons.org/2025/04/mlperf-inference-v5-0-results/  
- Microsoft. (2026). *What are Azure regions?* https://learn.microsoft.com/en-us/azure/reliability/regions-overview  

---

# Week 6 – Zero Trust and NIST CSF

## Discussion Question(s)

- To what extent does meaningful alignment with NIST CSF require the adoption of Zero Trust principles?  
- Can an organization claim alignment with NIST CSF if it has not adopted Zero Trust principles for identity and access management? Why or why not?  
- Provide a real-world example (e.g., ransomware, insider threat, cloud breach) in your discussion.

## Response
Alignment with the NIST Cybersecurity Framework (CSF) does not strictly require implementing a full Zero Trust architecture. The framework is designed to be flexible and outcome-based rather than prescribing specific technologies or security models. CSF 2.0 organizes cybersecurity activities into six core functions: Govern, Identify, Protect, Detect, Respond, and Recover. These functions help organizations manage cybersecurity risk while allowing them to select controls that fit their environment and business requirements (NIST, 2024).

However, Zero Trust principles strongly support many of the framework’s security outcomes, particularly within the Protect function. The CSF emphasizes strong identity management, authentication, and access control to ensure that only authorized users and devices can access resources. These principles closely align with Zero Trust, which focuses on continuously verifying users, devices, and access requests instead of assuming trust based on network location (Rose et al., 2020).

An organization could technically claim alignment with NIST CSF without fully adopting Zero Trust principles, but the effectiveness of that alignment depends on how well identity and access risks are managed.

A real-world example is the 2022 Uber security breach linked to the Lapsus$ hacking group. Attackers used social engineering techniques to repeatedly send multifactor authentication requests to an employee until one was approved. This allowed attackers to gain access to internal systems and tools (BBC, 2023). Stronger identity validation, device trust checks, and continuous verification—principles associated with Zero Trust—could have reduced the likelihood or impact of this breach.

## References
- National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0.* https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf  
- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero Trust Architecture (NIST SP 800-207).* https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf  
- BBC News. (2023). *Lapsus$: Court finds teenagers carried out hacking spree.* https://www.bbc.com/news/technology-66590477  


# Week 8 – Amazon RDS vs EC2

## Discussion Question(s)

1. Between Amazon EC2 or Amazon RDS, which provides a managed service? What does managed service mean?  
2. Is there any advantage of deploying Microsoft SQL Server on Amazon EC2 instead of Amazon RDS? Justify.  
3. What advantage does the Quick Start provide over a manual installation on Amazon EC2?  
4. Which deployment option offers the best approach for all use cases?  
5. Which approach costs more: using Amazon EC2 or using Amazon RDS?  

## Response

Amazon RDS provides a managed service, while Amazon EC2 does not. A managed service means that AWS handles routine administrative tasks such as patching, backups, failover, and high availability. This reduces operational overhead and allows organizations to focus more on application development rather than infrastructure management.

There are advantages to deploying Microsoft SQL Server on Amazon EC2. EC2 provides full control over the operating system, database configuration, and installed software. This is useful for organizations that require custom configurations, third-party integrations, or administrative access that is not supported in RDS. It is also beneficial for migrating legacy systems that depend on specific system-level settings.

The AWS Quick Start provides a significant advantage over manual installation by automating the deployment process. It uses preconfigured templates to set up infrastructure, networking, and security best practices. This reduces human error, speeds up deployment, and ensures consistency across environments.

There is no single best deployment option for all use cases. RDS is ideal for most standard workloads due to its ease of use and reduced management burden, while EC2 is better suited for highly customized or specialized requirements.

In terms of cost, Amazon RDS is generally more expensive than EC2 because it includes managed services and automation features. However, the higher cost may be justified by reduced administrative effort and improved reliability.

## References
- Amazon Web Services. (n.d.-a). *What is Amazon RDS?* https://aws.amazon.com/rds/  
- Amazon Web Services. (n.d.-b). *What is Microsoft SQL Server on Amazon EC2?* https://docs.aws.amazon.com/sql-server-ec2/latest/userguide/sql-server-on-ec2-overview.html  
- Amazon Web Services. (2017). *The scoop on moving your Microsoft SQL Server to AWS.* https://aws.amazon.com/blogs/publicsector/the-scoop-on-moving-your-microsoft-sql-server-to-aws/  

---

# Week 9 – AWS Storage Security

## Discussion Question(s)

Amazon Web Services provides multiple storage solutions such as Amazon Elastic Block Store (EBS) and Amazon S3 object storage. Discuss the best practices for securing these storage services. In your response:

- Identify at least two security practices for EBS and two for S3.  
- Explain why these practices are important for protecting data.  
- Provide an example of a potential security risk if these best practices are not followed.  

## Response

Securing AWS storage services such as Amazon EBS and Amazon S3 depends heavily on proper configuration and access control. For Amazon EBS, one important security practice is enabling encryption for volumes and snapshots using AWS KMS. This ensures that stored data remains protected even if the underlying storage is accessed improperly. Another key practice is restricting access through IAM roles and policies so that only authorized users or systems can create, attach, or modify volumes.

For Amazon S3, a critical security practice is disabling public access at the bucket level unless it is explicitly required. Many data breaches occur due to misconfigured buckets that are unintentionally exposed to the internet. Additionally, enforcing encryption for both data at rest and in transit helps maintain confidentiality when storing and transferring data.

These practices are important because they reduce the risk of unauthorized access and data exposure. Without encryption, sensitive data could be read if storage resources are accessed or shared incorrectly. Weak access controls can also allow attackers to misuse storage resources.

For example, if an S3 bucket is left publicly accessible, confidential information such as financial records or user data could be exposed to anyone online. Similarly, if an unencrypted EBS snapshot is shared across accounts, another user could mount the volume and access sensitive system data.


## References
- Amazon Web Services. (2023). *AWS cloud security.* https://aws.amazon.com/security/  
- Amazon Web Services. (n.d.). *Security best practices for Amazon S3.* https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html  

---

# Week 13 

No discussions during weeks 10-12

## Discussion Question(s)

Looking ahead, do you think network-based controls (VPCs, subnets, VPNs) will become less important compared to identity-driven models like Zero Trust? Or will both continue to coexist? Defend your position with reasoning grounded in current cloud security trends.

## Response

Network-based controls such as VPCs, subnets, and VPNs will continue to coexist with identity-driven models like Zero Trust, rather than being replaced by them. While Zero Trust shifts security toward identity, authentication, and continuous verification, it does not eliminate the need for strong network controls. Instead, both approaches complement each other as part of a defense-in-depth strategy.

One key reason is that identity systems are not immune to compromise. If an attacker gains access to a privileged account or hijacks an active session, they may be able to execute actions that appear legitimate from an identity perspective. In these cases, network based controls act as a critical secondary layer of defense. For example, inspecting and restricting east west traffic within a VPC can help detect or block suspicious lateral movement, even if the attacker is operating under valid credentials. Similarly, network segmentation and firewall rules can prevent unauthorized communication between workloads and limit the attacker’s ability to move freely or exfiltrate data.

At the same time, Zero Trust enhances security by enforcing least privilege access and validating user and device context before granting access. This is especially important in cloud environments where traditional network perimeters are blurred. According to NIST, Zero Trust assumes that threats can exist both inside and outside the network, reinforcing the need for continuous verification (Rose et al., 2020).

In conclusion, identity-driven models will take a leading role in modern cloud security, but network-based controls remain essential. Together, they provide layered protection, reducing risk even when one control fails.

## References

- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). Zero trust architecture (NIST Special Publication 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207 

- Microsoft. (2023). Zero Trust security model. https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-overview

- Amazon Web Services. (2023). Security best practices in AWS: Identity and access management. https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html 

---

## AI Usage Statement
I used ChatGPT to help organize my ideas and improve clarity. The final writing and analysis are my own.




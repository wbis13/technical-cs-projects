# Week 05 Notes & Reflection

## Reflection

This week, I worked on understanding different IAM privilege escalation paths and how attackers could misuse certain IAM permissions to gain higher levels of access within an AWS account.

I learned more about IAM actions such as PassRole, CreatePolicyVersion and UpdateAssumeRolePolicy, and why it is important to monitor changes to permissions and role policies.

The task also helped me understand how EventBridge and Lambda can work together to identify suspicious IAM activities and trigger alerts. I also explored the importance of testing detection logic to make sure it identifies the expected events.

One thing I learned is that monitoring IAM activities is important because some actions may look normal on their own but could become risky depending on how they are used.

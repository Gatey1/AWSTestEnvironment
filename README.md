# Two-tier web app on AWS

A small test environment I built by hand in the AWS Management Console. It has a public web
server and a PostgreSQL database that the internet cannot reach. Every visit and every login
attempt goes to CloudWatch, and an email alarm fires on repeated failed logins.

![Architecture: visitors reach an EC2 web server in a public subnet through the internet gateway; the web server talks to RDS PostgreSQL in private subnets; Secrets Manager, Session Manager, CloudWatch and SNS sit beside the VPC](docs/architecture.svg)



## Access points

| | |
|---|---|
| **1** public entry point | Port 80 on the web server |
| **0** routes from the internet to the database | The private subnets' route table has only the local VPC route |
| **0** SSH ports open | Admin access goes through SSM Session Manager |
| **0** passwords in code | The database password is managed by RDS in Secrets Manager and read at run time through the instance's IAM role |

## What it does

- A public landing page, plus sign-up and login.
- An account page where each user saves a data, and sees only their own data.
  Every query uses the user ID from the signed session, never one the browser sends.
- Passwords are stored as salted hashes, every form carries a CSRF token, and all SQL is parameterised.
- nginx logs every request as JSON. The app logs sign-ups, logins (success or failure, with the reason) and logouts.
  The CloudWatch agent ships both logs.

## How it is built

| Layer | AWS service | Settings |
|---|---|---|
| Network | VPC | Two public and two private subnets across two Availability Zones, an internet gateway, no NAT gateway |
| Web server | EC2 | `t3.micro`, Amazon Linux 2023, in a public subnet; nginx → gunicorn → Flask; IMDSv2 required |
| Database | RDS for PostgreSQL 17 | `db.t4g.micro`, public access off, DB subnet group over both private subnets, storage encrypted |
| Firewall | Security groups | `web-sg` allows port 80 in; `db-sg` allows 5432 only from `web-sg` |
| Credentials | Secrets Manager and IAM | RDS-managed master password; an instance role with `AmazonSSMManagedInstanceCore`, `CloudWatchAgentServerPolicy` and `GetSecretValue` on that one secret |
| Admin access | Systems Manager | Session Manager shell, no SSH key or port 22 |
| Logging | CloudWatch Logs | `/webtest/access` and `/webtest/auth`, metric filters, saved Logs Insights queries |
| Alerting | CloudWatch alarms and SNS | 5 or more failed logins in 5 minutes sends an email |

### Build order in the console

1. **VPC → Create VPC → "VPC and more"**: 2 Availability Zones, 2 public and 2 private subnets, no NAT gateway.
2. **Security groups**: `web-sg` (HTTP 80 in), then `db-sg` (PostgreSQL 5432 from `web-sg`).
3. **RDS → Create database**: PostgreSQL 17, `db.t4g.micro`, credentials managed in Secrets Manager,
   the VPC above, public access **No**, security group `db-sg`, initial database name `webapp`.
4. **IAM → Roles**: an EC2 role with the two managed policies above, plus an inline policy allowing
   `secretsmanager:GetSecretValue` on the database's secret.
5. **EC2 → Launch instance**: Amazon Linux 2023, `t3.micro`, a public subnet, auto-assign public IP,
   `web-sg`, the IAM role, and the user data script (see below).
6. **CloudWatch**: log groups, metric filters on the auth log, the failed-login alarm, and an SNS topic
   with an email subscription.


## What I would change for production

- HTTPS through an Application Load Balancer with an ACM certificate.
- An Auto Scaling group with deletion protection on.
- A least-privilege database role for the app instead of the master user.
- AWS WAF rate limits on the login and sign-up routes.
- Rebuild the whole environment as infrastructure as code, and ship releases through a pipeline.



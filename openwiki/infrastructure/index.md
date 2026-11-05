# Files

- [HCP Terraform workspace integration](hcp-terraform-workspaces.md) - Explains the Git-managed HCP Terraform topology for rosa-boundary -- twelve L3 workspaces split evenly across the rosa-boundary-stage and rosa-boundary-prod AWS accounts, with identical six-workspace topologies in each account and auto-apply enabled everywhere except the production credentials bootstrap workspace -- along with ownership layers, AWS dynamic-credential trust, apply gating, and onboarding steps.
- [Regional AWS runtime infrastructure](regional-runtime.md) - Describes regional ECS, EFS, Lambda, audit and Bedrock resources, their shared account-IAM ownership contract, and the constraints for safely running multiple regional states.

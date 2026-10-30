# Files

- [HCP Terraform workspace integration](hcp-terraform-workspaces.md) - Explains the Git-managed HCP Terraform topology for rosa-boundary -- six auto-applying staging L3 workspaces in the rosa-boundary-stage AWS account, plus a separate, still-bootstrapping rosa-boundary-prod AWS account whose two live workspaces now carry the project's only manual-apply gate -- along with ownership layers, AWS dynamic-credential trust, apply gating, and onboarding steps.
- [Regional AWS runtime infrastructure](regional-runtime.md) - Describes regional ECS, EFS, Lambda, audit and Bedrock resources, their shared account-IAM ownership contract, and the constraints for safely running multiple regional states.

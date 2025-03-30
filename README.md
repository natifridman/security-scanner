# GitHub Security Scanner

A gRPC-based service that scans GitHub organizations and repositories for security policy violations. The service can scan access control policies, branch protection settings, and more to ensure compliance with security best practices.

## Features

- List repositories in a GitHub organization
- Get detailed repository information including collaborators, teams, branches, and protection settings
- Scan repositories for policy violations
- Scan entire organizations for policy violations
- Support for custom policies using Open Policy Agent (OPA) Rego

## Prerequisites

- Go 1.16 or higher
- A GitHub personal access token with appropriate permissions
- Protocol Buffers compiler (`protoc`)

## Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. Install Go dependencies:

```bash
go mod tidy
```

3. Create a `.env` file from the example:

```bash
cp .env.example .env
```

4. Edit the `.env` file and add your GitHub token:

```
GITHUB_TOKEN=your_github_personal_access_token
```

## Running the Service

### Start the Server

```bash
go run cmd/server/main.go
```

The server will start and listen on port 50051 by default. You can change the port with the `-port` flag:

```bash
go run cmd/server/main.go -port 8080
```

### Using the Client

The client can be used to interact with the server. Here are some examples:

List repositories in an organization:

```bash
go run cmd/client/main.go --org your-org-name --list
```

Scan a specific repository:

```bash
go run cmd/client/main.go --org your-org-name --repo your-repo-name --scan
```

Scan all repositories in an organization:

```bash
go run cmd/client/main.go --org your-org-name --scan-all
```

## Policy Configuration

The service comes with built-in policies, but you can add custom policies in the `policies` folder.

### Rego Policies

Create a file with a `.rego` extension in the `policies` folder. All policies use OPA Rego for consistent policy evaluation. Here's an example:

```rego
# METADATA: {"name": "my-custom-policy", "description": "Custom policy description", "severity": "HIGH"}
package github.security

deny[decision] {
    # Your policy logic here
    # ...

    decision := {
        "resource_type": "type",
        "resource_id": "id",
        "details": {
            "key": "value"
        }
    }
}

violations = x {
    x := count(deny) > 0
}
```

## Built-in Policies

The service comes with several built-in policies implemented in Rego:

1. **No admin for users**: Checks if regular users have admin access to repositories
2. **Protect main branch**: Ensures main branches have protection rules enabled
3. **Blacklisted collaborators**: Prevents specific users from having access to repositories
4. **Unsafe branch names**: Detects branch names that suggest temporary or development work
5. **Public repository security**: Enforces stricter security requirements for public repositories
6. **Collaborator permissions**: Enforces proper permission levels for collaborators and bots

### Example: Public Repository Security Policy

```rego
# Ensure default branches in public repositories are protected
deny[decision] {
    # Only apply this policy to public repos
    input.repository.private == false
    
    # Get the default branch
    default_branch := input.repository.default_branch
    
    # Find the branch in branches list
    branch := input.branches[_]
    branch.name == default_branch
    
    # Check if branch is not protected
    not branch.protected
    
    # Create a decision object
    decision := {
        "resource_type": "branch",
        "resource_id": default_branch,
        "details": {
            "branch_name": default_branch,
            "issue": "Default branch in public repository must be protected",
            "repository": input.repository.full_name,
            "is_protected": false
        }
    }
}
```

## API Reference

The service implements a gRPC API with the following methods:

- `ListRepositories`: Lists repositories in a GitHub organization
- `GetRepository`: Gets detailed information about a repository
- `ScanRepository`: Scans a repository for policy violations
- `ScanOrganization`: Scans all repositories in an organization

## Building for Production

Build the server binary:

```bash
go build -o scanner-server cmd/server/main.go
```

Build the client binary:

```bash
go build -o scanner-client cmd/client/main.go
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

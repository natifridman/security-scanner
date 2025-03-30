# METADATA: {"name": "collaborator-permissions", "description": "Enforces proper permission levels for collaborators", "severity": "HIGH"}
package github.security

# Define allowed bot accounts with admin access
allowed_admin_bots = {
  "dependabot",
  "github-actions",
  "renovate"
}

# Check for collaborators with admin access
deny[decision] {
  # Get collaborator information
  collaborator := input.collaborators[_]
  
  # Check if user has admin permission
  collaborator.permission == "admin"
  
  # Get user details
  user := collaborator.user
  login := user.login
  user_type := user.type
  
  # Check if this is a regular user (not a bot) with admin access
  user_type == "User"
  
  # Create a decision object
  decision := {
    "resource_type": "collaborator",
    "resource_id": login,
    "details": {
      "login": login,
      "user_type": user_type,
      "permission": collaborator.permission,
      "issue": "Regular users should not have admin access to repositories"
    }
  }
}

# Check for bot accounts with admin access that aren't in the allowed list
deny[decision] {
  # Get collaborator information
  collaborator := input.collaborators[_]
  
  # Check if bot has admin permission
  collaborator.permission == "admin"
  
  # Get user details
  user := collaborator.user
  login := user.login
  user_type := user.type
  
  # Check if this is a bot
  user_type == "Bot"
  
  # Check if bot is not in the allowed list
  not allowed_admin_bot(login)
  
  # Create a decision object
  decision := {
    "resource_type": "collaborator",
    "resource_id": login,
    "details": {
      "login": login,
      "user_type": user_type,
      "permission": collaborator.permission,
      "issue": "This bot is not in the allowed list of bots with admin access"
    }
  }
}

# Helper to check if a bot is in the allowed list (with case insensitive matching)
allowed_admin_bot(login) {
  lower_login := lower(login)
  lower_allowed := lower(allowed_admin_bots[_])
  contains(lower_login, lower_allowed)
}

# Return true if violations exist
violations = x {
  x := count(deny) > 0
} 
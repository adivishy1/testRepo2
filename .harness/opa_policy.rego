# Policy to deny access to services based on certain conditions
# This policy checks if the service is of type "Kubernetes" or if the service name starts with a specific blocked name.
# If either condition is met, access is denied.

# Try to change the service name to BLOCKED_SERVICE_NAME_1 or type to Kubernetes to see the policy fail
package service

# Deny access if the service definition type is Kubernetes
deny[msg] {
  input.serviceEntity.serviceDefinition.type == "Kubernetes"
  msg := "Service with Kubernetes deployment type is not allowed"
}

# Deny access if the service name starts with a blocked prefix
deny[msg] {
  startswith(input.serviceEntity.name, "BLOCKED_SERVICE_NAME")
  msg := "Service which starts with BLOCKED_SERVICE_NAME prefix is not allowed"
}
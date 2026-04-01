package main

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf("Container '%s' in Deployment '%s' is running as root", [container.name, input.metadata.name])
}

deny contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.securityContext.runAsUser == 0
  msg := sprintf("Pod in Deployment '%s' is running as root", [input.metadata.name])
}
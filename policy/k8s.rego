package main

deny contains msg if {
  input.kind == "Pod"
  some c
  container := input.spec.containers[c]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Le pod %v ne doit pas tourner en root", [input.metadata.name])
}

Load policy

root@controlplane ~ ✦ ➜  cat sample.rego 
package httpapi.authz
import input
default allow = false
allow {
 input.path == "home"
 input.user == "Sunil"
 } 
root@controlplane ~ ✦ ➜

root@controlplane ~ ✦ ✖ curl -X PUT --data-binary @sample.rego http://localhost:8181/v1/policies/samplepolicy
{"client_addr":"127.0.0.1:45362","level":"info","msg":"Received request.","req_id":1,"req_method":"PUT","req_path":"/v1/policies/samplepolicy","time":"2022-07-13T13:44:59Z"}
{"client_addr":"127.0.0.1:45362","level":"info","msg":"Sent response.","req_id":1,"req_method":"PUT","req_path":"/v1/policies/samplepolicy","resp_bytes":2,"resp_duration":1.900428,"resp_status":200,"time":"2022-07-13T13:44:59Z"}
{}

---------------------------------------------------------
root@controlplane ~ ➜  cat /root/untrusted-registry.rego

package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  image := input.request.object.spec.containers[_].image
  not startswith(image, "hooli.com/")
  msg := sprintf("image '%v' comes from untrusted registry", [image])
}

root@controlplane ~ ➜  cat /root/unique-host.rego
package kubernetes.admission
import data.kubernetes.ingresses

deny[msg] {
    some other_ns, other_ingress
    input.request.kind.kind == "Ingress"
    input.request.operation == "CREATE"
    host := input.request.object.spec.rules[_].host
    ingress := ingresses[other_ns][other_ingress]
    other_ns != input.request.namespace
    ingress.spec.rules[_].host == host
    msg := sprintf("invalid ingress host %q (conflicts with %v/%v)", [host, other_ns, other_ingress])
}

---------------------------------------------------------
root@controlplane ~ ➜  kubectl apply -f ingress-test-2.yaml 
Error from server: error when creating "ingress-test-2.yaml": admission webhook "validating-webhook.openpolicyagent.org" denied the request: invalid ingress host "initech.com" (conflicts with test-1/prod)

root@controlplane ~ ✖ cat unique-host.rego 
package kubernetes.admission
import data.kubernetes.ingresses

deny[msg] {
    some other_ns, other_ingress
    input.request.kind.kind == "Ingress"
    input.request.operation == "CREATE"
    host := input.request.object.spec.rules[_].host
    ingress := ingresses[other_ns][other_ingress]
    other_ns != input.request.namespace
    ingress.spec.rules[_].host == host
    msg := sprintf("invalid ingress host %q (conflicts with %v/%v)", [host, other_ns, other_ingress])


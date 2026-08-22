# 🐳 Docker Container Misconfiguration Scanner

An automated container security auditor written in Python. Evaluates running Docker containers, image configurations, daemon security flags, and host-level container settings against CIS Docker Benchmarks and container hardening standards.

---

## 📌 Overview

Containers running with root privileges, exposed sockets, or missing resource boundaries represent critical privilege escalation vectors. This scanner inspects container host environments and running container runtimes to flag security misconfigurations, offering actionable remediation steps.

---

## ✨ Key Features

- 🔑 **Privilege Audit**: Identifies containers running as root (`UID 0`) or configured with `--privileged`.
- 🔌 **Socket Exposure Detection**: Flags dangerous host bind-mounts of `/var/run/docker.sock`.
- 🛡️ **Linux Capabilities Inspection**: Audits dropped vs. retained Linux kernel capabilities (`CAP_SYS_ADMIN`, `NET_ADMIN`).
- 📁 **Filesystem Security**: Verifies if container root filesystems are mounted read-only (`--read-only`).
- ⚡ **Resource Limits Audit**: Detects missing CPU (`--cpus`) and memory (`--memory`) constraints to prevent Denial of Service (resource starvation).
- 🌐 **Network Exposure Checks**: Flags dangerous port bindings (e.g., binding container ports to `0.0.0.0` instead of `127.0.0.1`).
- 📦 **Fallback Dual Execution Engine**: Executes seamlessly via the Python Docker API or falls back to native system `docker` CLI subprocessing.

---

## 🏗️ Audit Workflow

```
┌────────────────────────────────────────────────────────┐
│              Docker Misconfiguration Scanner           │
└───────────────────────────┬────────────────────────────┘
                            │ Check Environment Access
                            ▼
┌────────────────────────────────────────────────────────┐
│     Dual Inspection Engine (Docker Socket / Subprocess) │
└───────────────────────────┬────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Privileges & │    │ Filesystem & │    │ Resource &   │
│ Root User    │    │ Socket Mounts│    │ Network Caps │
└───────┬──────┘    └───────┬──────┘    └───────┬──────┘
        └───────────────────┼───────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│        JSON Report Generation & Security Score          │
└────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequisites & Dependencies

- **Python 3.8+**
- **Docker Engine (Optional)**: If Docker is running on the host system, the scanner will execute active audits against live containers. If Docker is absent, mock containers are evaluated for demonstration purposes.

---

## 🚀 How to Use

### 1. Run Misconfiguration Scan
```bash
python3 main.py
```

### 2. Programmatic Python Execution
```python
from main import DockerScanner

scanner = DockerScanner()
results = scanner.run_scan()

print(f"Total Security Findings: {len(results)}")
for finding in results:
    print(f"[{finding.severity}] Container: {finding.container_name} | {finding.title}")
    print(f"  Remediation: {finding.remediation}")
```

---

## 📊 Sample Audit Finding Output

```json
{
  "container_name": "production_api",
  "severity": "HIGH",
  "title": "Container Running as Root",
  "description": "Container process executes with root privileges (UID 0).",
  "remediation": "Add 'USER nonroot' to Dockerfile or specify '--user 10001' at runtime.",
  "cis_benchmark": "CIS Docker Benchmark 4.1"
}
```

---

## 🛡️ Defensive Value

- **Container Hardening**: Ensures compliance with CIS Docker Benchmarks and DevSecOps container standards.
- **Privilege Escalation Prevention**: Prevents host compromise stemming from container breakout attacks.

# 🐳 Docker Container Misconfiguration Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Security Level](https://img.shields.io/badge/security-Container%20Hardening-red.svg)](#)
[![Benchmark](https://img.shields.io/badge/CIS-Docker%20Benchmark-blue.svg)](https://www.cisecurity.org/)

An automated container security auditor written in Python. Evaluates running Docker containers, image configurations, daemon security flags, and host-level container settings against CIS Docker Benchmarks and container hardening standards.

---

## 📌 Executive Overview

Containers running with root privileges, exposed sockets, or missing resource boundaries represent critical privilege escalation vectors. This scanner inspects container host environments and running container runtimes to flag security misconfigurations, offering actionable remediation steps.

---

## ✨ Advanced Features

- 🔑 **Privilege Audit**: Identifies containers running as root (`UID 0`) or configured with `--privileged`.
- 🔌 **Socket Exposure Detection**: Flags dangerous host bind-mounts of `/var/run/docker.sock`.
- 🛡️ **Linux Capabilities Inspection**: Audits dropped vs. retained Linux kernel capabilities (`CAP_SYS_ADMIN`, `NET_ADMIN`).
- 📁 **Filesystem Security**: Verifies if container root filesystems are mounted read-only (`--read-only`).
- ⚡ **Resource Limits Audit**: Detects missing CPU (`--cpus`) and memory (`--memory`) constraints to prevent Denial of Service.
- 🌐 **Network Exposure Checks**: Flags dangerous port bindings (e.g., binding container ports to `0.0.0.0` instead of `127.0.0.1`).
- 📦 **Dual Execution Engine**: Executes seamlessly via the Python Docker API or falls back to native system `docker` CLI subprocessing.

---

## 🏗️ Audit Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Docker Misconfiguration Scanner                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Check Host Docker Access
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│          Dual Inspection Engine (Docker Socket / CLI Subprocess)            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
┌──────────────┐               ┌──────────────┐               ┌──────────────┐
│ Privileges & │               │ Filesystem & │               │ Resource &   │
│ Root User    │               │ Socket Mounts│               │ Network Caps │
└───────┬──────┘               └───────┬──────┘               └───────┬──────┘
        └──────────────────────────────┼──────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│           JSON Audit Report Generation & CIS Alignment Summary              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequisites & Setup

```bash
pip install docker
```
*(Optional: Docker daemon running on host for live container scanning).*

---

## 🚀 Usage & Integration Guide

### 1. Direct Execution
```bash
python3 main.py
```

### 2. Programmatic Python Integration
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

## 🛡️ OWASP Alignment & Threat Mitigation Matrix

| Threat Vector | Attack Description | Engine Countermeasure |
|---|---|---|
| **Container Breakout** | Attacker leverages root privileges inside container to escape to host. | Flags UID 0 and `--privileged` flags. |
| **Docker Socket Abuse** | Mounting `/var/run/docker.sock` allows full control over host Docker. | Audits container volume mounts for socket paths. |
| **Resource Exhaustion** | Unbounded container consumes host CPU/Memory causing host crash. | Verifies CPU and memory limits on container runtime settings. |

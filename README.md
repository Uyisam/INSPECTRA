# Inspectra – Automated Vulnerability Management & Risk Intelligence Platform

Inspectra is a vulnerability management platform designed to help identify, analyze, prioritize, and track software security vulnerabilities. It integrates Trivy scanning with vulnerability management workflows to provide visibility into security risks and remediation progress.

## Features

- **Asset Management:** Register and manage repository and filesystem assets.
- **Vulnerability Scanning:** Scan software assets using Trivy.
- **Vulnerability Tracking:** View detected vulnerabilities and their details.
- **Risk Prioritization:** Organize findings using severity, CVSS, risk scores, and priority levels.
- **Remediation Management:** Create and track remediation tasks.
- **Remediation Verification:** Run verification scans to check whether vulnerabilities have been resolved.
- **Notifications:** View application notifications.
- **Dashboard:** Access project and security overview information.
- **CI Security Checks:** GitHub Actions workflow for backend checks, frontend linting/building, and Trivy filesystem scanning.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI |
| Database | SQLite |
| ORM | SQLAlchemy |
| Vulnerability Scanner | Trivy |
| CI/CD | GitHub Actions |
| Containerization | Docker, Docker Compose |

## System Architecture

```text
             Inspectra Web Interface
                 React + TypeScript
                        |
                        v
                 FastAPI Backend
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
       SQLite         Trivy       NVD API
       Database       Scanner     Enrichment
          |             |
          +-------------+
                        |
                        v
             Vulnerability Management
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
       Findings     Remediation   Notifications
                    Verification
```

## Application Modules

1. **Dashboard** – Overview of projects and vulnerability information.
2. **Projects** – Manage security projects.
3. **Assets** – Register repositories and filesystem targets.
4. **Vulnerabilities** – Review and track detected security findings.
5. **Remediation** – Manage remediation tasks and verify fixes.
6. **Notifications** – View application notifications.

**Backend API:** Includes scan creation and scan history endpoints.

## Prerequisites

- Docker Desktop with Docker Compose
- Git
- GitHub account (for repository access)
- Trivy (required for local scanning; Docker deployment should use the configured scanner environment)

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Uyisam/INSPECTRA.git
cd INSPECTRA
```

### 2. Configure the scan path

Open `docker-compose.yml` and update `SCAN_HOST_ROOT` to the absolute path of your cloned Inspectra directory.

For Windows, use a path similar to:

```yaml
SCAN_HOST_ROOT: 'C:\path\to\INSPECTRA'
```

### 3. Build and start the application

```bash
docker compose up -d --build
```

### 4. Access Inspectra

Open the application in your browser:

**http://localhost:8081**

FastAPI documentation is available at:

**http://localhost:8081/docs**

### 5. Stop the application

```bash
docker compose down
```

Application database files are stored in the `docker-data` directory and persist across container restarts.

## GitHub Actions

Inspectra includes a GitHub Actions workflow that runs on pushes and pull requests targeting the `main` branch.

The workflow includes:

- Backend dependency installation and Python compilation checks.
- Frontend dependency installation, ESLint checks, and production build.
- Trivy filesystem scanning for HIGH and CRITICAL severity vulnerabilities, with unfixed vulnerabilities ignored.

## Project Structure

```text
INSPECTRA/
├── .github/
│   └── workflows/
│       └── ci.yml
├── backend/
│   ├── api/
│   ├── database/
│   ├── models/
│   ├── schemas/
│   └── services/
├── data/
├── docker-data/
├── frontend/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Current Implementation Status

- Docker Compose deployment tested successfully.
- Backend API endpoints verified.
- Frontend production build completed successfully.
- All six frontend sections checked.
- Trivy vulnerability scanning tested.
- Remediation task management and verification tested.
- GitHub Actions CI workflow executed successfully.

## Future Improvements

- Role-based access control and user authentication.
- Enhanced reporting and export capabilities.
- Expanded scanner integrations.
- Improved deployment configuration for different environments.
- Advanced vulnerability analytics and historical trends.

## Author

**Aboobakkar Uyisam**

B.Tech – Computer Science and Technology  
DevOps Specialization

## License

This project is currently maintained as an academic and portfolio project. Licensing terms can be added when a license is selected.

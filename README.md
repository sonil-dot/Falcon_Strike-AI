# Falcon Strike-AI
### Cloud Attack Path Analysis and Adversary Emulation Framework

## About the Project

Falcon Strike-AI is a cybersecurity project that helps identify possible attack paths in a cloud environment and test whether security monitoring can detect suspicious activity.

The main idea behind this project is simple: instead of waiting for an actual attacker to discover a weakness, we can create a controlled lab, identify risky access paths, simulate selected attacker techniques, and check how well the security rules respond.

I developed this project to understand how cloud misconfigurations, excessive permissions and weak security monitoring can create opportunities for attackers.

The project uses Moto to simulate AWS services during testing. This allowed me to experiment with cloud resources, permissions and attack-path scenarios without needing a real AWS account.

## Project Objectives

- Identify possible attack paths through cloud identities and permissions.
- Understand how one compromised identity could lead to access to more privileged roles.
- Simulate selected attacker techniques in a controlled environment.
- Check whether security detection rules identify the simulated activities.
- Generate reports that help explain detection gaps.
- Maintain audit records and verify cleanup after live simulations.

## How the Project Works

The project follows a sequence of steps:

1. **Environment collection:** Collects information about the lab environment using read-only operations.
2. **Attack graph creation:** Builds a graph showing relationships between identities, roles and permissions.
3. **Attack path analysis:** Identifies and ranks potentially risky paths to privileged access.
4. **Campaign planning:** Creates a sequence of selected techniques to test.
5. **Safety validation:** Checks the proposed actions against the project's security restrictions.
6. **Attack emulation:** Runs the approved simulation in dry-run or controlled live mode.
7. **Cleanup and verification:** Removes temporary resources and checks whether the environment has returned to its original state.
8. **Detection analysis:** Evaluates which simulated activities were detected and generates reports.

## Technologies Used

- Python
- AWS-related APIs and Boto3
- Moto for mock AWS testing
- NetworkX for graph-based attack path analysis
- Flask / local listener components for beacon testing
- MITRE ATT&CK framework
- Pytest for automated testing
- Terraform for infrastructure configuration
- HTML, JSON and Markdown for reports

## Attack Techniques Implemented

The project includes five selected techniques based on MITRE ATT&CK.

| Technique ID | Technique | Purpose |
|---|---|---|
| T1580 | Cloud Infrastructure Discovery | Identify cloud resources and configurations |
| T1098 | Account Manipulation / Role Chaining | Test movement through existing role relationships |
| T1552 | Unsecured Credentials | Access a deliberately planted test marker |
| T1136 | Create Account | Simulate creation of a temporary role |
| T1071 | Application Layer Protocol | Generate beacon-like communication with a local lab listener |

These are limited, controlled simulations. The project does not implement the complete MITRE ATT&CK framework.

## Safety Measures

Safety was an important part of the development process. The project includes several controls to prevent testing outside the intended lab.

- **Account allowlist:** Only the approved lab account is accepted.
- **Dry-run by default:** The normal run command simulates the planned actions without making changes.
- **Signed token:** Live execution requires a valid, time-limited token.
- **Live confirmation:** An additional confirmation flag is required before live execution.
- **Technique validation:** Only approved techniques can be included in a campaign.
- **Scope validation:** The project checks account and destination restrictions.
- **Kill switch:** A live run can be stopped using the emergency stop command.
- **Resource limits:** Limits are applied to execution time, resource creation and repeated failures.
- **Audit logging:** Actions are recorded in a hash-chained audit log.
- **Cleanup verification:** Temporary resources are removed and teardown is checked.

## Installation and Setup

### Requirements

- Windows, Linux or macOS
- Python 3.11 or newer
- Git (optional, for cloning the repository)

### 1. Clone the repository

```bash
git clone https://github.com/sonil-dot/Falcon_Strike-AI.git
cd Falcon_Strike-AI
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the automated tests

```bash
python -m pytest -q --basetemp=.pytest_tmp
```

This checks the main project components, including the audit system, safety controls, attack graph, simulation and reporting features. Some tests may be skipped if optional dependencies are unavailable.

## Running the Project

### View the attack paths

```bash
python -m falcon.cli paths --top 3
```

This displays the highest-ranked attack paths found in the sample lab environment.

### Run a dry-run simulation

```bash
python -m falcon.cli run
```

This is the default execution mode. It goes through the planned actions without performing live changes.

### Run the benchmark

```bash
python -m falcon.cli bench
```

This tests attack-path analysis using a larger generated graph.

### Test the safety controls

```bash
python -m falcon.cli run --account 999999999999
```

This demonstrates how the project rejects an account outside the approved allowlist.

```bash
python -m falcon.cli run --demo-bad unknown_technique
```

This demonstrates how an unapproved technique is blocked.

Other available demonstration cases include:

- `foreign_account`
- `bad_sink`

### Generate evidence

```bash
python scripts/make_evidence.py --backend moto
```

This runs the evidence-generation workflow using the mock AWS backend and saves supporting output in the `evidence` directory.

## Reports and Evidence

The repository contains supporting project outputs.

- **Evidence:** Contains execution logs and outputs from demonstrations, including blocked actions, dry-runs, live-run audit records, kill-switch testing and performance testing.
- **Reports:** Contains generated reports in HTML, JSON and Markdown formats.
- **Documentation:** Contains the architecture diagram, runbook, audit log schema and project write-up.
- **Samples:** Contains sample environment data used for testing.

The reports help explain the simulated activities, detection results and areas where security monitoring could be improved.

## Project Structure

```text
Falcon_Strike-AI/
│
├── falcon/          Main Python application
├── tests/           Automated test cases
├── evidence/        Execution evidence and logs
├── reports/         Generated reports
├── docs/            Project documentation
├── infra/           Terraform configuration
├── scripts/         Supporting scripts
├── samples/         Sample lab data
│
├── requirements.txt
├── README.md
└── .gitignore
```

## Limitations

This project is a controlled lab implementation and has some limitations:

- It implements five selected attack techniques rather than the complete MITRE ATT&CK framework.
- The detection component is a simulated monitoring system, not a production SIEM.
- Beacon communication uses HTTP with a local listener; advanced C2 techniques such as DNS signalling and TLS fingerprinting are not implemented.
- The project was tested using Moto's mock AWS environment and was not validated against a real  AWS account. Therefore, its behaviour may differ from an actual AWS deployment.
- The mock AWS environment does not represent every behaviour of a real AWS account.
- The Terraform configuration and AWS backend have not been validated against a real AWS account.
- IAM policy analysis does not cover every possible AWS policy condition and restriction.
- The optional LLM-based planner was tested using canned responses rather than a full production integration.

## Future Improvements

Some possible improvements for future versions include:

- Integrating with a real SIEM or CloudTrail.
- Adding more cloud attack techniques.
- Supporting Azure and Google Cloud.
- Improving IAM policy analysis.
- Adding stronger network isolation through containers.
- Exploring graph databases for larger environments.
- Developing a more advanced monitoring dashboard.

## What I Learned

Working on Falcon Strike-AI helped me understand how cloud identities, permissions and role relationships can create security risks. I also gained practical experience with Python, graph-based analysis, automated testing, audit logging and security controls.

One of the most important parts of this project was learning that attack simulation is not only about executing techniques. It is equally important to control where they run, record what happens, stop them safely and verify that temporary resources are cleaned up.

This project gave me an opportunity to connect different cybersecurity concepts and understand how they can work together in a practical lab environment.

---

**Project:** Falcon Strike-AI – Cloud Attack Path Analysis and Adversary Emulation Framework  
**Developed by:** Sneha Philip

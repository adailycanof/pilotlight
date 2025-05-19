# Pilot Light - EKS Cluster Health Checker

![Cartoon Pilot Light](./pilot_light_cartoon_half.png)

Pilot Light is a comprehensive health checking tool for EKS clusters that provides insights into cluster configuration, node health, networking, security policies, and more.

## Features

- EKS cluster status and version information
- Nodegroup analysis
- Core Kubernetes system component health checking
- RBAC configuration verification
- Networking (CNI and CoreDNS) status
- Auto-scaling configuration detection
- Ingress controller verification
- Security policy analysis (PSPs and NetworkPolicies)

## Requirements

- Python 3.6+
- AWS credentials with EKS access
- kubectl configured with access to your EKS cluster

## Installation

1. Clone this repository:
```bash
git clone https://github.com/adailycanof/pilot-light.git
cd pilot-light
```

2. Create and activate a virtual environment (optional but recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Ensure your AWS credentials are properly configured either through:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`)
- AWS credentials file (~/.aws/credentials)
- IAM role attached to your EC2 instance or container

Your kubeconfig should be configured with access to the EKS cluster you want to analyze.

## Usage

Run the script with your EKS cluster name:

```bash
python pilot_light.py --cluster your-eks-cluster-name --region us-west-2
```

Options:
- `--cluster`, `-c`: EKS cluster name (required)
- `--region`, `-r`: AWS region (default: us-west-2)
- `--kubeconfig`, `-k`: Path to kubeconfig file (optional, defaults to ~/.kube/config)

## Output

The script will output logs to the console and generate a detailed `results.json` file with the health check results.

Example output:
```json
{
  "cluster": {
    "status": "ACTIVE",
    "version": "1.24",
    "endpoint": "https://example.eks.amazonaws.com"
  },
  "nodegroups": [...],
  "kubernetesVersion": "1.24",
  "coreSystemPods": [...],
  "rbac": {...},
  "networking": {...},
  "autoscaler": [...],
  "ingressController": [...],
  "security": {...}
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

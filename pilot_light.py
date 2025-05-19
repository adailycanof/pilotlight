import argparse
import logging
import sys
import json

from kubernetes import client as k8s_client, config as k8s_config
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def describe_eks_cluster(eks_client, cluster_name):
    try:
        resp = eks_client.describe_cluster(name=cluster_name)
        c = resp['cluster']
        info = {
            'status': c['status'],
            'version': c['version'],
            'endpoint': c.get('endpoint'),
        }
        logger.info(f"Cluster status: {info['status']}, version: {info['version']}")
        return info
    except ClientError as e:
        logger.error(f"Error describing cluster: {e}")
        sys.exit(1)


def list_nodegroups(eks_client, cluster_name):
    try:
        resp = eks_client.list_nodegroups(clusterName=cluster_name)
        ngs = resp.get('nodegroups', [])
        logger.info(f"Found nodegroups: {ngs}")
        return ngs
    except ClientError as e:
        logger.error(f"Error listing nodegroups: {e}")
        sys.exit(1)


def describe_nodegroup(eks_client, cluster_name, nodegroup_name):
    try:
        resp = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        ng = resp['nodegroup']
        info = {
            'name': nodegroup_name,
            'status': ng['status'],
            'desiredSize': ng['scalingConfig']['desiredSize'],
        }
        logger.info(f"NodeGroup {nodegroup_name}: {info['status']}")
        return info
    except ClientError as e:
        logger.error(f"Error describing nodegroup {nodegroup_name}: {e}")
        return {'name': nodegroup_name, 'error': str(e)}


def init_k8s_clients(kubeconfig_path=None):
    try:
        if kubeconfig_path:
            k8s_config.load_kube_config(config_file=kubeconfig_path)
        else:
            k8s_config.load_kube_config()
        core = k8s_client.CoreV1Api()
        apps = k8s_client.AppsV1Api()
        rbac = k8s_client.RbacAuthorizationV1Api()
        networking = k8s_client.NetworkingV1Api()  # Added NetworkingV1Api client
        return core, apps, rbac, networking
    except Exception as e:
        logger.error(f"Error loading kubeconfig: {e}")
        sys.exit(1)


def check_core_system_components(core_api):
    results = []
    pods = core_api.list_namespaced_pod('kube-system')
    for pod in pods.items:
        ready = all([c.ready for c in pod.status.container_statuses or []])
        results.append({
            'name': pod.metadata.name,
            'namespace': pod.metadata.namespace,
            'status': pod.status.phase,
            'ready': ready,
        })
        if not ready:
            logger.warning(f"Pod {pod.metadata.name} not ready")
    return results


def check_iam_roles_rbac(rbac_api):
    rbs = rbac_api.list_role_binding_for_all_namespaces().items
    crbs = rbac_api.list_cluster_role_binding().items
    info = {
        'roleBindings': len(rbs),
        'clusterRoleBindings': len(crbs)
    }
    logger.info(f"RBAC: RBs={info['roleBindings']}, CRBs={info['clusterRoleBindings']}")
    return info


def check_networking(core_api, apps_api):
    info = {}
    try:
        ds = apps_api.read_namespaced_daemon_set('aws-node', 'kube-system')
        info['cni'] = {
            'desired': ds.status.desired_number_scheduled,
            'ready': ds.status.number_ready
        }
    except Exception:
        info['cni'] = 'Not found'
        logger.warning("aws-node DaemonSet not found")
    try:
        dns = apps_api.read_namespaced_deployment('coredns', 'kube-system')
        info['coredns'] = {
            'desired': dns.status.replicas,
            'ready': dns.status.ready_replicas
        }
    except Exception:
        info['coredns'] = 'Not found'
        logger.warning("CoreDNS deployment not found")
    return info


def check_autoscaler(core_api):
    pods = core_api.list_namespaced_pod('kube-system', label_selector='app=cluster-autoscaler').items
    if pods:
        return [{'name': p.metadata.name, 'status': p.status.phase} for p in pods]
    logger.info("Cluster Autoscaler not deployed")
    return []


def check_ingress_controller(core_api):
    pods = core_api.list_pod_for_all_namespaces(label_selector='app.kubernetes.io/name=ingress-nginx').items
    if pods:
        return [{'namespace': p.metadata.namespace, 'name': p.metadata.name, 'status': p.status.phase} for p in pods]
    logger.warning("Ingress controller not found")
    return []


def check_security_policies(core_api, networking_api):
    sec = {}
    try:
        psp = k8s_client.PolicyV1beta1Api().list_pod_security_policy().items
        sec['podSecurityPolicies'] = len(psp)
    except Exception:
        sec['podSecurityPolicies'] = 'N/A'
        logger.warning("PSP API unavailable or none defined")
    sec['networkPolicies'] = {}
    for ns in core_api.list_namespace().items:
        try:
            nps = networking_api.list_namespaced_network_policy(ns.metadata.name).items
            if nps:
                sec['networkPolicies'][ns.metadata.name] = len(nps)
        except Exception as e:
            logger.warning(f"Error getting network policies for namespace {ns.metadata.name}: {e}")
    return sec


def parse_args():
    parser = argparse.ArgumentParser(description="Pilot Light - EKS cluster health checker")
    parser.add_argument('--cluster', '-c', required=True, help='EKS cluster name')
    parser.add_argument('--region', '-r', default='us-west-2', help='AWS region')
    parser.add_argument('--kubeconfig', '-k', default=None, help='Path to kubeconfig')
    return parser.parse_args()


def main():
    args = parse_args()
    eks = boto3.client('eks', region_name=args.region)
    core, apps, rbac, networking = init_k8s_clients(args.kubeconfig)  # Updated to include networking client

    results = {}
    results['cluster'] = describe_eks_cluster(eks, args.cluster)
    ngs = list_nodegroups(eks, args.cluster)
    results['nodegroups'] = [describe_nodegroup(eks, args.cluster, ng) for ng in ngs]
    results['kubernetesVersion'] = results['cluster'].get('version')
    results['coreSystemPods'] = check_core_system_components(core)
    results['rbac'] = check_iam_roles_rbac(rbac)
    results['networking'] = check_networking(core, apps)
    results['autoscaler'] = check_autoscaler(core)
    results['ingressController'] = check_ingress_controller(core)
    results['security'] = check_security_policies(core, networking)  # Updated to pass networking client

    with open('results.json', 'w') as f:
        json.dump(results, f, indent=2)
    logger.info("Results written to results.json")

if __name__ == '__main__':
    main()

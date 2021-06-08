#!/usr/bin/env python

import argparse
import sys
import requests
import os
from enum import Enum
from datetime import datetime
from dateutil.parser import parse

TEKTON_GROUP = "tekton.dev"
PIPELINERUNS = "pipelineruns"

INLINE_PIPELINE = "inline_pipeline"


class PipelineRunStatus(Enum):
    Succeeded = 1
    Failed = 2
    Other = 3


class PipelineRunNamespaceHolder:

    def __init__(self):
        self.namespaces = {}

    def add_pipelinerun(self, pipelinerun):
        if pipelinerun.namespace not in self.namespaces:
            self.namespaces[pipelinerun.namespace] = {}

        if pipelinerun.pipeline not in self.namespaces[pipelinerun.namespace]:
            self.namespaces[pipelinerun.namespace][pipelinerun.pipeline] = PipelineRunHolder()

        if pipelinerun.status == PipelineRunStatus.Succeeded:
            self.namespaces[pipelinerun.namespace][pipelinerun.pipeline].successful.append(pipelinerun)
        elif pipelinerun.status == PipelineRunStatus.Succeeded:
            self.namespaces[pipelinerun.namespace][pipelinerun.pipeline].failed.append(pipelinerun)


class PipelineRunHolder:
    def __init__(self):
        self.successful = []
        self.failed = []


class PipelineRun:
    def __init__(self, pipelinerun):
        self.name = pipelinerun['metadata']['name']
        self.namespace = pipelinerun['metadata']['namespace']

        self.pipeline = self.__get_pipelinerun_pipeline(pipelinerun)

        self.status = self.__get_pipelinerun_status(pipelinerun)

        if 'status' in pipelinerun and 'completionTime' in pipelinerun['status']:
            self.completion_time = parse(pipelinerun['status']['completionTime'])

    def __get_pipelinerun_pipeline(self, pipelinerun):
        if 'pipelineRef' not in pr['spec']:
            return INLINE_PIPELINE
        else:
            return pr['spec']['pipelineRef']['name']

    def __get_pipelinerun_status(self, pipelinerun):

        if 'status' in pipelinerun and 'conditions' in pipelinerun['status'] and len(pipelinerun['status']['conditions']) > 0:
            if pipelinerun['status']['conditions'][0]['status'] == 'True':
                return PipelineRunStatus.Succeeded
            elif pipelinerun['status']['conditions'][0]['status'] == 'False':
                return PipelineRunStatus.Failed

        return PipelineRunStatus.Other

    def print(self):
        return f"Namespace: {self.namespace} - Name: {self.name} - Completion Time: {self.completion_time}"


def is_pipelinerun_in_api_group(api_resources_list):
    for resource in api_resources_list['resources']:

        if resource['name'] == PIPELINERUNS:
            return True

    return False


def make_get_json_request(session, url):

    json_request = session.get(url)
    json_request.raise_for_status()

    return json_request.json()


def discover_tekton_api_group_version(session):

    preferred_version_request = make_get_json_request(session, f"{server}/apis/{TEKTON_GROUP}")

    preferred_version = preferred_version_request['preferredVersion']['version']

    # Attempt to check preferred version first
    preferred_version_response = make_get_json_request(session, f"{server}/apis/{TEKTON_GROUP}/{preferred_version}")

    if is_pipelinerun_in_api_group(preferred_version_response):
        return f"{TEKTON_GROUP}/{preferred_version}"

    # Try to find version by looping through all api versions
    for version in preferred_version_request['versions']:
        version_url_response = make_get_json_request(session, f"{server}/apis/{TEKTON_GROUP}/{version['version']}")

        if is_pipelinerun_in_api_group(version_url_response):
            return f"{TEKTON_GROUP}/{version}"

    return None


def prune_pipelineruns(session, base_group_version_url, num_to_keep, pipelineruns):
    if num_to_keep < 0 or num_to_keep >= len(pipelineruns):
        return

    # Sort List by CompletionTime
    pipelineruns.sort(key=lambda x: x.completion_time, reverse=True)

    for pipelinerun in pipelineruns[max(0, num_to_keep):]:
        print(f"Deleting PipelineRun - {pipelinerun.print()}")
        delete_pipelinerun = session.delete(f"{base_group_version_url}/namespaces/{pipelinerun.namespace}/{PIPELINERUNS}/{pipelinerun.name}")
        delete_pipelinerun.raise_for_status()


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='Prunes PipelineRun resources',
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--server', action='store', dest='server', help='Kubernetes API Server', default="https://kubernetes.default.svc")

parser.add_argument('--token', action='store', dest='token', help='Kubernetes API Token')
parser.add_argument('--token-file', action='store', dest='token_file',
                    help='Location of the file containing the Kubernetes API Server Token', default="/var/run/secrets/kubernetes.io/serviceaccount/token")

parser.add_argument('--ignore-tls-verify', action='store', dest='ignore_tls_verify', type=str2bool, nargs='?', const=True, help='Ignore SSL Verification')
parser.add_argument('--certificate-file', action='store', dest='certificate_file',
                    help='Location for the HTTPS Certificate File', default="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

namespaces_group = parser.add_mutually_exclusive_group()
namespaces_group.add_argument('--all-namespaces', action='store', dest='all_namespaces', type=str2bool, nargs='?', const=True,
                              help='Prune all namespaces')
namespaces_group.add_argument('--namespace', action='append', dest='namespaces',
                              help='Namespace to prune')

parser.add_argument('--keep-failed', action='store', dest='keep_failed', help='Number of Failed PipelineRuns to keep', default=-1, type=int)
parser.add_argument('--keep-successful', action='store', dest='keep_successful', help='Number of Successful PipelineRuns to keep', default=-1, type=int)


args = parser.parse_args()

server = args.server
token = args.token
token_file = args.token_file
all_namespaces = args.all_namespaces
namespaces = args.namespaces
keep_failed = args.keep_failed
keep_successful = args.keep_successful
ignore_tls_verify = args.ignore_tls_verify
certificate_file = args.certificate_file


if not token:
    if not os.path.exists(token_file):
        print(f"Unable to locate token file: '{token_file}'")
        sys.exit(1)

    with open(token_file) as f:
        token = f.read().replace("\n", "")

auth_header = {
    "Authorization": f"Bearer {token}"
}

session = requests.Session()
session.headers.update(auth_header)

if ignore_tls_verify:
    session.verify = False
else:
    if not os.path.exists(certificate_file):
        print(f"Warning: Unable to locate certificate file: '{certificate_file}'")
    else:
        session.verify = certificate_file


group_version = discover_tekton_api_group_version(session)

base_group_version_url = f"{server}/apis/{group_version}"

if group_version is None:
    print("Error: Unable to locate PipelineRun Tekton version")
    sys.exit(1)

pipeline_run_resources = []

# Obtain the list of PipelineRun Resources
if all_namespaces:
    all_namespaces_response = make_get_json_request(session, f"{base_group_version_url}/{PIPELINERUNS}")
    pipeline_run_resources.extend(all_namespaces_response['items'])
elif namespaces is not None:
    for namespace in namespaces:
        namespace_response = make_get_json_request(session, f"{base_group_version_url}/namespaces/{namespace}/{PIPELINERUNS}")
        pipeline_run_resources.extend(namespace_response['items'])

# Create a PipelineRun Holder
pipelinerun_namespace_holder = PipelineRunNamespaceHolder()

# Break out PipelineRuns by namespace, pipeline and successful and failed runs
for pr in pipeline_run_resources:

    pipelinerun = PipelineRun(pr)

    pipelinerun_namespace_holder.add_pipelinerun(pipelinerun)

# Iterate through PipelineRun Resources to Prune
for namespace_key in pipelinerun_namespace_holder.namespaces.keys():
    for namepace_pipelinerun_key in pipelinerun_namespace_holder.namespaces[namespace_key].keys():
        # Prune Failed PipelineRuns
        prune_pipelineruns(session, base_group_version_url, keep_failed,
                           pipelinerun_namespace_holder.namespaces[namespace_key][namepace_pipelinerun_key].failed)

        # Prune Successful PipelineRuns
        prune_pipelineruns(session, base_group_version_url, keep_successful,
                           pipelinerun_namespace_holder.namespaces[namespace_key][namepace_pipelinerun_key].successful)

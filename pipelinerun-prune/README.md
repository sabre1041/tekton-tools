# Pipeline Pruning

Tooling to support pruning of Completed PipelineRun resources

## Overview

By default, Tekton does not implement any form of removal of _PipelineRun_ resources upon their completion. This can lead to resources beginning to accumulate. The tooling contained here provide a method to remove _PipelineRun_ resources by retaining only a set number of successful and failed completions.

## Tooling

The following tools are available:

1. Python script to remove _PipelineRuns_ from specific namespaces or all namespaces in the Kubernetes cluster
2. CronJob to execute the Python pruning script on a periodic basis

### Pruning Script

A script called `pipeline_prune.py` is available to prune _PipelineRuns_ and includes the following capabilities:

1. Removal of _PipelineRun_ resources from specific namespaces or all namespaces in the Kubernetes cluster
2. Support for removing Successful and/or Failed _PipelineRun_ resources by each _Pipeline_

### CronJob

A [CronJob](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/) and associated RBAC resources are available to execute the PipelineRun pruning script on a route basis. 

## Deployment to Cluster

A set of [Kustomize](https://kustomize.io/) based tooling is available for deploying to a Kubernetes. While this example is designed to be integrated with OpenShift Pipelines, it can be modified to be deployed on any cluster with Tekton installed. Once deployed, the following will be created:

* A namespace called `openshift-pipelines`.
* Service Account.
* ClusterRole with access to `PipelineRun` resources.
* ClusterRoleBinding that provides access to the _ServiceAccount_ to access privileges provided by the _ClusterRole_.
* CronJob that executes the script each day at Midnight
    * Retains 5 Successful and Failed _PipelineRuns_ per associated _Pipeline_

Execute the following command to deploy to a cluster:

```shell
kustomize build . | kubectl apply -f-
```

To avoid waiting for the _CronJob_ to execute, manually create a _Job_ based on the CronJob to perform the pruning process immediately

```shell
kubectl -n openshift-pipelines create job cronjob-prune-tekton-pipelinerun-job --from=cronjob/cronjob-prune-tekton-pipelinerun
```
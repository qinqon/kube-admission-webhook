#!/usr/bin/env bash

set -xe

KUBECTL=${KUBECTL:-kubectl}
POD_NAMESPACE=${POD_NAMESPACE:-kubemacpool-system}
POD_APP_LABEL=${POD_APP_LABEL:-kubemacpool-leader=true}
WEBHOOK_TYPE=${WEBHOOK_TYPE:-mutatingWebhookConfiguration}
WEBHOOK_NAME=${WEBHOOK_NAME:-kubemacpool-mutator}
TEMP_FOLDER=${TEMP_FOLDER:-_tmp}

WEBHOOK_CONFIG_YAML_DIR=$(pwd)/${TEMP_FOLDER}/
WEBHOOK_YAML_FILE=${WEBHOOK_CONFIG_YAML_DIR}/${WEBHOOK_TYPE}_${WEBHOOK_NAME}.yaml

mkdir -p ${WEBHOOK_CONFIG_YAML_DIR}

# get webhook config in yaml format
${KUBECTL} get ${WEBHOOK_TYPE} -n ${POD_NAMESPACE} ${WEBHOOK_NAME} -oyaml > ${WEBHOOK_YAML_FILE}

#remove the caBundle from the webhook config
sed '/caBundle:/d' ${WEBHOOK_YAML_FILE} > ${WEBHOOK_YAML_FILE}.out

#force update the webhook config
${KUBECTL} replace -f ${WEBHOOK_YAML_FILE}.out

#restart pods to force rotation of certs
${KUBECTL} delete pod -n ${POD_NAMESPACE} -l ${POD_APP_LABEL}

rm -rf ${WEBHOOK_CONFIG_YAML_DIR}

echo "please wait for pod to restart and certs are rotated"

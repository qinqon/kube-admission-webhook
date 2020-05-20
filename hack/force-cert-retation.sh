#!/usr/bin/env bash

set -ex

function usage {
cat <<- EOF
Usage example:
  HANDLER_NAMESPACE=kubemacpool-system HANDLER_POD_LABEL=kubemacpool-leader=true WEBHOOK_CONFIG_NAME=kubemacpool-mutator WEBHOOK_SECRET_NAME=kubemacpool-service ./force-cert-rotation.sh

Mandatory Arguments:
  HANDLER_NAMESPACE     namespace of the pod operating the kube-admission's library.
  HANDLER_POD_LABEL     specific label corresponding to the pod operating the kube-admission's library.
  WEBHOOK_CONFIG_NAME   webhook config name.
  WEBHOOK_SECRET_NAME   the name of the secret created by kube-admission.
EOF
}

# input parameter parsing
function parse_input_param {
  while [[ ! -z "$1" ]]; do
    case "$1" in
      --help)
          usage
          exit
          ;;
      *)
          break
          ;;
      esac
      shift
  done
}

# check mandatory env variables
function check_input_env_var {
  if [[ -z "${HANDLER_NAMESPACE}" || -z "${HANDLER_POD_LABEL}" || -z "${WEBHOOK_CONFIG_NAME}" || -z "${WEBHOOK_SECRET_NAME}" ]]; then
    echo "Error: Not all env parameters are set."
    usage
    exit
  fi
}

# get number of webhooks in webhook config instance
function get_number_of_webhooks_in_webhook_config {
  echo $(${KUBECTL} get ${WEBHOOK_TYPE} -n ${HANDLER_NAMESPACE} ${WEBHOOK_CONFIG_NAME} -o jsonpath={.webhooks[*].name} | wc -w)
}

# retrive data from secret data
function get_secret_data {
  echo "$(${KUBECTL} get secret -n ${HANDLER_NAMESPACE} ${WEBHOOK_SECRET_NAME} -o jsonpath={.data})"
}

# retreive caBundle from webhook config
function get_ca_bundle {
  echo "$(${KUBECTL} get ${WEBHOOK_TYPE} -n ${HANDLER_NAMESPACE} ${WEBHOOK_CONFIG_NAME} -o jsonpath={.webhooks[$1].clientConfig.caBundle})"
}

# get the components to compare later
function get_components_prior_to_rotation {
  OLD_CA_BUNDLE=$(get_ca_bundle 0) 2>/dev/null

  OLD_SECRET_DATA=$(get_secret_data) 2>/dev/null
}

# patch webhook config to remove caBundle
function remove_ca_bundle_from_webhook_config {
  for i in $(seq 0 $(( $number_of_webhooks - 1 )) ); do
    ${KUBECTL} patch ${WEBHOOK_TYPE} -n ${HANDLER_NAMESPACE} ${WEBHOOK_CONFIG_NAME} --type json -p "[{\"op\": \"remove\", \"path\": \"/webhooks/$i/clientConfig/caBundle\"}]" || true
  done
}

function restart_handler_pods {
  # restart pods to force rotation of certs
  ${KUBECTL} delete pod -n ${HANDLER_NAMESPACE} -l ${HANDLER_POD_LABEL}
}

function eventually {
    timeout=100
    interval=10
    cmd=$@
    echo "Checking eventually $cmd"
    while ! $cmd; do
        sleep $interval
        timeout=$(( $timeout - $interval ))
        if [ $timeout -le 0 ]; then
            return 1
        fi
    done
}

function is_secret_rotated {
  NEW_SECRET_DATA=$(get_secret_data) 2>/dev/null

  [ "${NEW_SECRET_DATA}" != "${OLD_SECRET_DATA}" ]
}

function is_ca_bundle_rotated {
  for i in $(seq 0 $(( $number_of_webhooks - 1 )) ); do
      CA_BUNDLE=$(get_ca_bundle $i) 2>/dev/null

      if [[ -z "${CA_BUNDLE}" || "${CA_BUNDLE}" == ${OLD_CA_BUNDLE} ]]; then
        return 1
      fi
  done

  return 0
}

# wait until caBundle is rotated and updated to webhook config
function wait_for_ca_bundle_rotation {
  if ! eventually is_ca_bundle_rotated; then
    echo "caBundle haven't rotated in the given timeout"
    exit 1
  else
    echo "caBundle in $WEBHOOK_TYPE/$WEBHOOK_CONFIG_NAME rotated successfuly"
  fi
}

# wait until secret is rotated
function wait_for_secret_rotation {
    if ! eventually is_secret_rotated; then
      echo "secret haven't rotated in the given timeout"
      exit 1
    else
      echo "secret $WEBHOOK_SECRET_NAME rotated successfuly"
    fi
}

function wait_for_components_rotation {
  wait_for_ca_bundle_rotation

  wait_for_secret_rotation
}

KUBECTL=${KUBECTL:-kubectl}

parse_input_param

check_input_env_var

for WEBHOOK_TYPE in "validationWebhookConfiguration" "mutatingWebhookConfiguration"; do
  number_of_webhooks=$(get_number_of_webhooks_in_webhook_config)

  if [[ $number_of_webhooks > 0 ]]; then
    get_components_prior_to_rotation

    remove_ca_bundle_from_webhook_config

    restart_handler_pods

    wait_for_components_rotation
  fi
done

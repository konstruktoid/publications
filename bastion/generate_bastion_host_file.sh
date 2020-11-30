#!/bin/bash
set -x -o pipefail

if ! command -v ansible 1>/dev/null; then
  exit 1
fi

NETWORK="$(ansible localhost -m setup -a "filter=ansible_default_ipv4" 2>/dev/null | grep "network" | awk '{print $NF}' | tr -d '",')/24"
KNOWN_HOSTS="$HOME/.ssh/known_hosts"
HOSTFILE="./hosts"

if [ -z "${NETWORK}" ]; then
  echo "Missing network."
  exit 1
elif [ ! -r "${KNOWN_HOSTS}" ]; then
  echo "Verify the ${KNOWN_HOSTS} file."
fi

if ! command -v vagrant 1>/dev/null; then
  exit 1
fi

if ! vagrant validate Vagrantfile; then
  exit 1
fi

if [ "$(vagrant status | grep -c 'running.*virtualbox')" -le 0 ]; then
  echo "No vagrant boxes are running. Exiting."
  exit 1
fi

echo "Generating Ansible hosts file."
echo "# $(date)" > "${HOSTFILE}"

if [ "${NETWORK}" == '0.0.0.0/24' ]; then
  NETWORK="0.0.0.0/0"
fi

if [ ! -d ./group_vars ]; then
  mkdir ./group_vars
fi

{
  echo
  echo "[bastion]"
  for VM in $(vagrant status | grep -iE 'running.*virtualbox' | grep 'bastion' | awk '{print $1}'); do
    mapfile -t VAGRANT_SSH < <(vagrant ssh-config "$VM" | awk '{print $NF}')
    ANSIBLE_HOST_IP=$(vagrant ssh "$VM" -c "hostname -I | cut -f2 -d' '" | tr -d '\r' | sed 's/ //g')
    ANSIBLE_INTERNAL_HOST_IP=$(vagrant ssh "$VM" -c "hostname -I | cut -f3 -d' '" | tr -d '\r' | sed 's/ //g')
    mapfile -t VAGRANT_SSH < <(vagrant ssh-config "$VM" | awk '{print $NF}')
    echo "${VAGRANT_SSH[0]} ansible_host=${ANSIBLE_HOST_IP} ansible_user=${VAGRANT_SSH[2]}"

    yes | ssh-keygen -R "${ANSIBLE_HOST_IP}" &>/dev/null
    ssh-keyscan -H "${ANSIBLE_HOST_IP}" >> "${KNOWN_HOSTS}"

    {
      echo "---"
      echo "ansible_ssh_common_args: '-o ProxyCommand=\"ssh -A -W %h:%p ${VAGRANT_SSH[2]}@${ANSIBLE_HOST_IP}\"'"
      echo "sshd_admin_net: [${ANSIBLE_INTERNAL_HOST_IP}]"
      echo "sshd_allow_groups: \"vagrant sudo ubuntu\""
      echo "sshd_max_sessions: 10"
      echo "..."
    } > "./group_vars/internal.yml"

    {
      echo "---"
      echo "ansible_ssh_common_args: '-o ControlMaster=auto -o ControlPersist=60s'"
      echo "sshd_admin_net: [${NETWORK}]"
      echo "sshd_allow_groups: \"vagrant sudo ubuntu\""
      echo "sshd_allow_agent_forwarding: 'yes'"
      echo "sshd_allow_tcp_forwarding: 'yes'"
      echo "sshd_max_sessions: 10"
      echo "..."
    } > "./group_vars/bastion.yml"
  done
} >> "${HOSTFILE}"

{
  echo
  echo "[internal]"
  for VM in $(vagrant status | grep -iE 'running.*virtualbox' | grep -v 'bastion' | awk '{print $1}'); do
    mapfile -t VAGRANT_SSH < <(vagrant ssh-config "$VM" | awk '{print $NF}')
    ANSIBLE_HOST_IP=$(vagrant ssh "$VM" -c "hostname -I | cut -f2 -d' '" | tr -d '\r' | sed 's/ //g')
    echo "${VAGRANT_SSH[0]} ansible_host=${ANSIBLE_HOST_IP} ansible_user=${VAGRANT_SSH[2]}"
  done
} >> "${HOSTFILE}"

host_details() {
  {
    echo
    echo "[${1}]"
    for VM in $(vagrant status | grep -iE 'running.*virtualbox' | grep "$1" | awk '{print $1}'); do
      mapfile -t VAGRANT_SSH < <(vagrant ssh-config "$VM" | awk '{print $NF}')
      ANSIBLE_HOST_IP=$(vagrant ssh "$VM" -c "hostname -I | cut -f2 -d' '" | tr -d '\r' | sed 's/ //g')
      echo "${VAGRANT_SSH[0]} ansible_host=${ANSIBLE_HOST_IP} ansible_user=${VAGRANT_SSH[2]}"
    done
  } >> "${HOSTFILE}"
}

host_details loadbalancer
host_details webserver

ssh-add -l | grep '\.vagrant' | awk '{print $3".pub"}' | while read -r SSHPUB; do
  if [ -r "${SSHPUB}" ]; then
    ssh-add -d "${SSHPUB}"
  fi
done

grep 'bastion' "${HOSTFILE}" | awk '{print $1}' | while read -r BASTION; do
  vagrant ssh-config "${BASTION}" | grep IdentityFile | awk '{print $NF}' | while read -r PRIVATE_KEY; do
    ssh-keygen -y -f "${PRIVATE_KEY}" > "${PRIVATE_KEY}.pub"
    ssh-add "${PRIVATE_KEY}"

    for VM in $(vagrant status | grep -iE 'running.*virtualbox' | grep -v "bastion" | awk '{print $1}'); do
      if [ -f "${PRIVATE_KEY}.pub" ]; then
        grep -v '^#' "${PRIVATE_KEY}.pub" | vagrant ssh "${VM}" -c "cat >> \${HOME}/.ssh/authorized_keys"
      else
        echo "${PRIVATE_KEY}.pub doesn't exists."
      fi
    done

    for SCAN in $(grep -vE '^#|bastion' "${HOSTFILE}" | awk '{print $2}' | grep -v '^$' | sort | uniq | sed 's/.*=//g'); do
      yes | ssh-keygen -R "${SCAN}" &>/dev/null
      vagrant ssh "${BASTION}" -c "yes | ssh-keygen -R ${SCAN}"
    done
  done
done

if command -v dos2unix 2>/dev/null; then
  dos2unix "${HOSTFILE}"
fi

if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
  xargs -0 yamllint -d "{extends: default, rules: {line-length: {level: warning}}}"; then
    echo "yamllint failed."
    exit 1
fi

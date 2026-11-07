#!/bin/sh
# swtpm as the vault's TPM, the vault created at the first start (its pin
# and recovery key go to the container's log), then served - the machines'
# interface on 8443, the operators' on 8444.
set -e
mkdir -p /var/lib/swtpm /run/kira-vault
swtpm socket --tpm2 --tpmstate dir=/var/lib/swtpm \
    --server type=unixio,path=/run/swtpm.sock \
    --ctrl type=unixio,path=/run/swtpm.ctrl \
    --flags startup-clear --daemon
i=0
while [ ! -S /run/swtpm.sock ] && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
if [ ! -d /var/lib/kira-vault ]; then
    kira-vault init --url "$VAULT_URL" --listen :8443 --operator-listen :8444 --pcrs 7 --tpm /run/swtpm.sock
fi
exec kira-vault serve

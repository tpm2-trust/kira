#!/bin/sh
# swtpm as the vault's TPM, the vault created at the first start (its pin
# and backup go to the container's log), then served - the machines'
# interface on 8443, the operators' on 8444.
set -e
mkdir -p /var/lib/swtpm /run/kira-vault
swtpm socket --tpm2 --tpmstate dir=/var/lib/swtpm \
    --server type=unixio,path=/run/swtpm.sock \
    --ctrl type=unixio,path=/run/swtpm.ctrl \
    --flags startup-clear --daemon
i=0
while [ ! -S /run/swtpm.sock ] && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
# The approval PIN through the pipe; PCR 23 alone, as a software TPM has no
# firmware log that PCR 7 could be approved from. Both test machines reach the
# vault from one address and boot again and again within a minute: the limit of
# challenges per address (3 a minute by default) is out of the scenarios' way.
if [ ! -d /var/lib/kira-vault ]; then
    printf 'vmtest-pin\nvmtest-pin\n' | kira-vault init --url "$VAULT_URL" --listen :8443 --operator-listen :8444 --pcrs 23 --tpm /run/swtpm.sock --challenge-rate 1000
fi
exec kira-vault serve

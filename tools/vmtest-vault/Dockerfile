# The vault of tools/vmtest.py: kira-vault with a software TPM of its
# own. vmtest.py builds kira-vault (static) into this directory's
# build context and runs the image with the vault's port published.
FROM archlinux:latest
RUN pacman -Sy --noconfirm --needed swtpm && pacman -Scc --noconfirm
COPY kira-vault /usr/bin/kira-vault
COPY entrypoint.sh /entrypoint.sh
EXPOSE 8443 8444
ENTRYPOINT ["/entrypoint.sh"]

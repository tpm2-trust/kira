# The vault of tools/vmtest.py: kira-vault with a software TPM of its
# own. vmtest.py builds kira-vault (static) into this directory's
# build context and runs the image with the vault's port published.
FROM archlinux:latest
# -Syu, never -Sy alone: a package installed onto an image that is not upgraded with it
# links against libraries the image does not have yet (swtpm, libcrypto.so.4).
RUN pacman -Syu --noconfirm --needed swtpm && pacman -Scc --noconfirm
COPY kira-vault /usr/bin/kira-vault
COPY entrypoint.sh /entrypoint.sh
EXPOSE 8443 8444
ENTRYPOINT ["/entrypoint.sh"]

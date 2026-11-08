SSH agent for TPM
=================

> **nabbi fork.** This branch tracks
> [Foxboron/ssh-tpm-agent](https://github.com/Foxboron/ssh-tpm-agent) master
> and carries hardening fixes that are not upstream, plus the Go dependency
> tarballs for the `app-crypt/ssh-tpm-agent` ebuild in
> [oubliette-overlay](https://github.com/nabbi/oubliette-overlay). Each
> `v*` tag pushed here gets a release with `-deps.tar.xz` and
> `-vendor.tar.xz` from `.github/workflows/golang-dist.yml`.
>
> Upstream releases are mirrored too: `.github/workflows/mirror.yml`
> ([projg2/golang-dist-mirror-action](https://github.com/projg2/golang-dist-mirror-action))
> copies new upstream tags into this repository and gives each a release with
> the same tarballs. It runs by hand only, when bumping the ebuild to an
> upstream version (before `pkgdev manifest`): `scripts/golang-dist-deps
> nabbi/ssh-tpm-agent vX.Y.Z` in oubliette-overlay, or `gh workflow run
> mirror.yml -R nabbi/ssh-tpm-agent`. It needs the `PUSH_TOKEN` secret, a
> fine-grained token for this repository with Contents and Workflows read and
> write. Tags older than v0.9.0 were added without a workflow, so no release
> is built for them. Fork releases are tagged `v<upstream version>-nabbi<N>`.
>
> Fixes on top of upstream, one commit each:
>
> * Cached passphrases live in a possessor-only thread keyring instead of a
>   named session keyring any same-user process could link and read.
> * A key's confirm constraint (`ssh-tpm-add -c`, `--confirm-loaded`) can only
>   be dropped with the user's approval, not by a client re-adding the key.
> * The agent never sends an empty passphrase to the TPM when it has nowhere
>   to prompt, so clients can not drive the TPM into dictionary-attack lockout.
> * Malformed `tpm-add-key` messages are rejected instead of crashing the agent.
> * The passphrase authorises the key through a salted HMAC session, so it no
>   longer crosses the TPM bus in cleartext.

`ssh-tpm-agent` is a ssh-agent compatible agent that allows keys to be created
by the Trusted Platform Module (TPM) for authentication towards ssh servers.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in `.tpm` suffixed files. They are bound to the hardware they
are produced on and can't be transferred to other machines.

This allows you to utilize a native client instead of having to side load
existing PKCS11 libraries into the ssh-agent and/or ssh client.

The project uses [TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)
implemented through the [`go-tpm-keyfiles`](https://github.com/Foxboron/go-tpm-keyfiles) project.

# Features

* A working `ssh-agent`.
* Create shielded ssh keys on the TPM.
* Creation of remotely wrapped SSH keys for import.
* PIN support, dictionary attack protection from the TPM allows you to use low entropy PINs instead of passphrases.
* TPM session encryption.
* Proxy support towards other `ssh-agent` servers for fallbacks.

# SWTPM support

Instead of utilizing the TPM directly, you can use `--swtpm` or `export
SSH_TPM_AGENT_SWTPM=1` to create an identity backed by
[swtpm](https://github.com/stefanberger/swtpm) which will be stored under
`/var/tmp/ssh-tpm-agent`.

Note that `swtpm` provides no security properties and should only be used for
testing.

## Installation

The simplest way of installing this plugin is by running the following:

```text
go install github.com/foxboron/ssh-tpm-agent/cmd/...@latest
```

Alternatively download the [pre-built binaries](https://github.com/Foxboron/ssh-tpm-agent/releases).

# Usage

```text
# Create key
$ ssh-tpm-keygen
Generating a sealed public/private ecdsa key pair.
Enter file in which to save the key (/home/fox/.ssh/id_ecdsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/fox/.ssh/id_ecdsa.tpm
Your public key has been saved in /home/fox/.ssh/id_ecdsa.pub
The key fingerprint is:
SHA256:NCMJJ2La+q5tGcngQUQvEOJP3gPH8bMP98wJOEMV564
The key's randomart image is the color of television, tuned to a dead channel.

$ cat /home/fox/.ssh/id_ecdsa.pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOTOsMXyjTc1wiQSKhRiNhKFsHJNLzLk2r4foXPLQYKR0tuXIBMTQuMmc7OiTgNMvIjMrcb9adgGdT3s+GkNi1g=

# Using the socket
$ ssh-tpm-agent -l /var/tmp/tpm.sock

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

$ ssh git@github.com
```

**Note:** For `ssh-tpm-agent` you can specify the TPM owner password using the
command line flags `-o` or `--owner-password`, which are preferred.
Alternatively, you can use the environment variable
`SSH_TPM_AGENT_OWNER_PASSWORD`.

### Import existing key

Useful if you want to back up the key to a remote secure storage while using the key day-to-day from the TPM.

```text
# Create a key, or use an existing one
$ ssh-keygen -t ecdsa -f id_ecdsa
Generating public/private ecdsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in id_ecdsa
Your public key has been saved in id_ecdsa.pub
The key fingerprint is:
SHA256:bDn2EpX6XRX5ADXQSuTq+uUyia/eV3Z6MW+UtxjnXvU fox@framework
The key's randomart image is:
+---[ECDSA 256]---+
|           .+=o..|
|           o. oo.|
|          o... .o|
|       . + ..  ..|
|        S .   . o|
|       o * . oo=*|
|        ..+.oo=+E|
|        .++o...o=|
|       .++++. .+ |
+----[SHA256]-----+

# Import the key
$ ssh-tpm-keygen --import id_ecdsa
Sealing an existing public/private ecdsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in id_ecdsa.tpm
The key fingerprint is:
SHA256:bDn2EpX6XRX5ADXQSuTq+uUyia/eV3Z6MW+UtxjnXvU
The key's randomart image is the color of television, tuned to a dead channel.
```

### Install user service

Socket activated services allow you to start `ssh-tpm-agent` when it's needed by your system.

```text
# Using the socket
$ ssh-tpm-agent --install-user-units
Installed /home/fox/.config/systemd/user/ssh-tpm-agent.socket
Installed /home/fox/.config/systemd/user/ssh-tpm-agent.service
Enable with: systemctl --user enable --now ssh-tpm-agent.socket

$ systemctl --user enable --now ssh-tpm-agent.socket

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

$ ssh git@github.com
```


### Proxy support

```text
# Start the usual ssh-agent
$ eval $(ssh-agent)

# Create a strong RSA key
$ ssh-keygen -t rsa -b 4096 -f id_rsa -C ssh-agent
...
The key fingerprint is:
SHA256:zLSeyU/6NKHGEvyZLA866S1jGqwdwdAxRFff8Z2N1i0 ssh-agent

$ ssh-add id_rsa
Identity added: id_rsa (ssh-agent)

# Print looonnggg key
$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc[...]8TWynQ== ssh-agent

# Create key on the TPM
$ ssh-tpm-keygen -C ssh-tpm-agent
Generating a sealed public/private ecdsa key pair.
Enter file in which to save the key (/home/fox/.ssh/id_ecdsa):
Enter passphrase (empty for no passphrase):
Confirm passphrase:
Your identification has been saved in /home/fox/.ssh/id_ecdsa.tpm
Your public key has been saved in /home/fox/.ssh/id_ecdsa.pub
The key fingerprint is:
SHA256:PoQyuzOpEBLqT+xtP0dnvyBVL6UQTiQeCWN/EXIxPOo
The key's randomart image is the color of television, tuned to a dead channel.

# Start ssh-tpm-agent with a proxy socket
$ ssh-tpm-agent -A "${SSH_AUTH_SOCK}" &

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

# ssh-tpm-agent is proxying the keys from ssh-agent
$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc[...]8TWynQ== ssh-agent
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNo[...]q4whro= ssh-tpm-agent
```

### ssh-tpm-add

```text
$ ssh-tpm-agent --no-load &
2023/08/12 13:40:50 Listening on /run/user/1000/ssh-tpm-agent.sock

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

$ ssh-add -L
The agent has no identities.

$ ssh-tpm-add $HOME/.ssh/id_ecdsa.tpm
Identity added: /home/user/.ssh/id_ecdsa.tpm

$ ssh-add -L
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJCxqisGa9IUNh4Ik3kwihrDouxP7S5Oun2hnzTvFwktszaibJruKLJMxHqVYnNwKD9DegCNwUN1qXCI/UOwaSY= test
```

### Create and Wrap private key for client machine on remote server

On the client side create one a primary key under an hierarchy. This example
will use the owner hierarchy with an SRK.

The output file `srk.pem` needs to be transferred to the remote end which
creates the key. This could be done as part of client provisioning.

```text
$ tpm2_createprimary -C o -G ecc -g sha256 -c prim.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' -f pem -o srk.pem
```

On the remote end we create a p256 ssh key, with no password, and wrap it with
`ssh-tpm-keygen` with the `srk.pem` from the client side.

```text
$ ssh-keygen -t ecdsa -b 256 -N "" -f ./ecdsa.key
# OR with openssl
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ecdsa.key

# Wrap with ssh-tpm-keygen
$ ssh-tpm-keygen --wrap-with srk.pub --wrap ecdsa.key -f wrapped_id_ecdsa
```

On the client side we can unwrap `wrapped_id_ecdsa` to a loadable key.

```text
$ ssh-tpm-keygen --import ./wrapped_id_ecdsa.tpm -f id_ecdsa.tpm
$ ssh-tpm-add id_ecdsa.tpm
```

### ssh-tpm-hostkey

`ssh-tpm-agent` also supports storing host keys inside the TPM.

```text
$ sudo ssh-tpm-keygen -A
2023/09/03 17:03:08 INFO Generating new ECDSA host key
2023/09/03 17:03:08 INFO Wrote /etc/ssh/ssh_tpm_host_ecdsa_key.tpm
2023/09/03 17:03:08 INFO Generating new RSA host key
2023/09/03 17:03:15 INFO Wrote /etc/ssh/ssh_tpm_host_rsa_key.tpm

$ sudo ssh-tpm-hostkeys --install-system-units
Installed /usr/lib/systemd/system/ssh-tpm-agent.service
Installed /usr/lib/systemd/system/ssh-tpm-agent.socket
Installed /usr/lib/systemd/system/ssh-tpm-genkeys.service
Enable with: systemctl enable --now ssh-tpm-agent.socket

$ sudo ssh-tpm-hostkeys --install-sshd-config
Installed /etc/ssh/sshd_config.d/10-ssh-tpm-agent.conf
Restart sshd: systemd restart sshd

$ systemctl enable --now ssh-tpm-agent.socket
$ systemd restart sshd

$ sudo ssh-tpm-hostkeys
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCLDH2xMDIGb26Q3Fa/kZDuPvzLzfAH6CkNs0wlaY2AaiZT2qJkWI05lMDm+mf+wmDhhgQlkJAHmyqgzYNwqWY0= root@framework
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAoMPsv5tEpTDFw34ltkF45dTHAPl4aLu6HigBkNnIzsuWqJxhjN6JK3vaV3eXBzy8/UJxo/R0Ml9/DRzFK8cccdIRT1KQtg8xIikRReZ0usdeqTC+wLpW/KQqgBLZ1PphRINxABWReqlnbtPVBfj6wKlCVNLEuTfzi1oAMj3KXOBDcTTB2UBLcwvTFg6YnbTjrpxY83Y+3QIZNPwYqd7r6k+e/ncUl4zgCvvxhoojGxEM3pjQIaZ0Him0yT6OGmCGFa7XIRKxwBSv9HtyHf5psgI+X5A2NV2JW2xeLhV2K1+UXmKW4aXjBWKSO08lPSWZ6/5jQTGN1Jg3fLQKSe7f root@framework

$ ssh-keyscan -t ecdsa localhost
# localhost:22 SSH-2.0-OpenSSH_9.4
localhost ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCLDH2xMDIGb26Q3Fa/kZDuPvzLzfAH6CkNs0wlaY2AaiZT2qJkWI05lMDm+mf+wmDhhgQlkJAHmyqgzYNwqWY0=
```

# ssh-config

It is possible to use the public keys created by `ssh-tpm-keygen` inside ssh
configurations.

The below example uses `ssh-tpm-agent` and also passes the public key to ensure
not all identities are leaked from the agent.

```sshconfig
Host example.com
    IdentityAgent $SSH_AUTH_SOCK

Host *
    IdentityAgent /run/user/1000/ssh-tpm-agent.sock
    IdentityFile ~/.ssh/id_ecdsa.pub
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or https://opensource.org/licenses/MIT

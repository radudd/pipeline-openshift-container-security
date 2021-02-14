# About

This workshop will showcase the integration of container images scanning and signing to a Jenkins CI/CD pipeline.

For the image signing, we will use skopeo/buildah/podman with GPG keys: https://www.openshift.com/blog/filtering-external-registry-images-by-signature-in-openshift-4

For image scanning, we will be using Red Hat Quay, which relies on the opensource tool called Clair for static image scanning. 

Additionally, we will explore container security best practices and we will introduce a new tool for Cloud-Native security: Stackrox

> :warning: **Jenkins pipeline integration is work in progress**

# Prerequisites

* Quay Container Registry version 3.4. This was installed to OpenShift using Quay Operator https://docs.projectquay.io/deploy_quay_on_openshift_op_tng.html
* S3 backend storage. In this example we will use Red Hat Noobaa. This opensource tool is part of OpenShift Container Storage. Noobaa was installed to OpenShift using the following Ansible playbooks: https://github.com/rflorenc/openshift-backup-infra. The S3 storage is required for backend storage for Quay 
* a Jenkins instance. This was installed to OpenShift using OpenShift templates: https://www.openshift.com/blog/deploying-jenkins-on-openshift-part-1
* GPG keypair. Check the [Generate GPG keypair](#generate-gpg-keypair) section


# Image Signing

Signing and trusting container images relies on GPG trust mechanism.

The signing process works as follows: The GPG private key are used to sign the container images by encrypting their digest, while the public key will be distributed to the systems which will need to check the signature (i.e. will decrypt the signatures to obtain the digest and compare it with its actual digest). In this way, if trusting the owner of GPG key, there is a guarantee that the images are not tampered.

## Generate GPG Keypair

First generate a GPG keypair

```
gpg2 --gen-key
```

```
... 
Real name: radu
Email address: radu@example.com
You selected this USER-ID:
    "radu <radu@example.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
pub   rsa2048 2021-02-13 [SC] [expires: 2023-02-13]
      XXXX
uid                      radu <radu@example.com>
sub   rsa2048 2021-02-13 [E] [expires: 2023-02-13]
```

```
gpg2 --edit-key XXXX trust
```
```
...
Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y
```

```
gpg> quit
```

As the GPG keys are now generated, export both the private key and public key.

```
gpg2 --armor --export-secret-keys radu@example.com > gpg-private.pem

gpg2 --armor --export radu@example.com > gpg-public.pem
```

## Configure Web Server

Let's install an nginx server that will host the signstore. If using manual signing(no pipeline), we will use the same host. For a CICD pipeline, we'll add an extra step that after the signing to sync the signatures to the webserver. 

The webserver will need to be accessible from the hosts that we'll verify signatures (OpenShift nodes)

```
dnf install -y nginx
```

```
cat <<EOF > /etc/nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

    server {
        listen       5600 default_server;
        listen       [::]:5600 default_server;
        server_name  _;
        root         /var/www/signatures;

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;

        location / {
        }
    }
}
EOF
```

Enable firewallD and create directory

```
firewall-cmd --add-port=5600/tcp --permanent
firewall-cmd --reload
mkdir -p /var/www/signatures
```

## OPTION 1: Configure Jenkins CICD pipeline for image signing (work in progress)

### Configure GPG keys in Jenkins

The CICD tool will be used to sign the container images during the pipeline. For this, it will need to GPG private key created before and its passphrase. Go to `Jenkins/Credentials/System/Global Credential` and create two new secrets: `gpg-key` and `gpg-passphrase`

Those secrets can be then accessed in the Jenkins pipelines, using the following synthax

```
    environment {
        gpg_key = credentials("gpg-secret")
        gpg_passphrase = credentials("gpg-passphrase")
    }
```


## Dedicated Jenkins agent

Since we will build a Java application, we will need a Jenkins Maven agent. However, as we want to have skopeo/buidah/podman and gpg2 for signing images, as well as an s3 cli which will allow us to communicate with the s3 bucket for syncing the sigstore, then we'll need to create a custom Jenkins Maven Agent

---
**NOTE**

Use a subscribed RHEL box for building

---

```
buildah bud -t jenkins-agent-imagesigner -f jenkins/agent/Dockerfile
```

```
buildah push jenkins-agent-imagesigner quay.apps.ocp.bdmsky.net/jenkins-agent-imagesigner
```

Finally, create a pullsecret in the Jenkins namespace in order for the master to be able to fetch the image from Quay registry.

For this create a robot account in Quay, and then craete a secret using its token.

```
cat EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: development-rhel-pull-secret
data:
  .dockerconfigjson: xxx
type: kubernetes.io/dockerconfigjson
EOF
```

Then link the pull secret to `jenkins` service account.

```
oc secrets link jenkins development-rhel-pull-secret --for=pull
```

Because Buildah will need to push the image to the registry this secret will also need to be mounted

```
oc secrets link jenkins development-rhel-pull-secret 
```

## OPTION 2: Manual Image Signing 

### Containers config
Let's configure signature store location. When the images will be signed they will store the signature at the path configured here.

```
cat <<EOF > /etc/containers/registries.d/quay.apps.rd.bdmsky.yaml
docker:
  quay.apps.rd.bdmsky.net:
    sigstore: file:///var/www/signatures/sigstore
    sigstore-staging: file:///var/www/signatures/sigstore
EOF
```

### Build application
First build the application
```
cd pipeline-openshift-container-security/app/hello-world
./mvnw clean install -DskipTests
```

To build 

```
cd pipeline-openshift-container-security/app/hello-world
buildah bud -t quay.apps.rd.bdmsky.net/development/quarkus-hello:signed .
```

To push

```
podman login quay.apps.rd.bdmsky.net
podman push --sign-by radu@test.com  quay.apps.rd.bdmsky.net/development/hello-world:signed
```

### Do a local test

Create a policy to accept only signed images from that registry.

```
cat <<EOF > /etc/containers/policy.json
{
    "default": [
        {
            "type": "insecureAcceptAnything"
        }
    ],
    "transports":
        {
            "docker": {
              "quay.apps.rd.bdmsky.net": [
                {
                  "type": "signedBy",
                  "keyType": "GPGKeys",
                  "keyPath": "/etc/pki/containers/signer-key.pub"
                }
              ]
            },
            "docker-daemon":
                {
                    "": [{"type":"insecureAcceptAnything"}]
                }
        }
}
EOF
```

Then let's export the GPG public key to the referenced location
```
gpg2 --armor --export radu@example.com > /etc/pki/containers/signer-key.pub
```

Pull an unsigned image...


## Configure OpenShift 

### Initial test

Before deploying let's do the initial test to deploy a not signed image

```
oc new-app quay.apps.ocp.bdmsky.net/development/quarkus-hello:unsigned
```

### Configure

OpenShift nodes will need to be configured to enforce a policy that allows users to deploy only signed images by a specific GPG key for defined registries. The signature store for those images will also need to be accessible from OpenShift for it to be able to verify the authenticity of the images.

Basically, we need to configure the following files:

- `/etc/containers/policy.json` : enforcing to allow only signed images from specific registries. Reference the GPG public key for decrypting the digest of the signed images.
- `/etc/containers/registries.d/quay.apps.rd.bdmsky.net.yaml`: defining the location of registry signstore
- `/etc/pki/developers/signer-key.pub`: GPG public key. It'll be referenced in the first config file.


All of those will be configured using MachineConfig Operator. Now let's define and generate those files.

```
gpg2 --armor --export radu@example.com > signer-key.pub

cat > policy.json <<EOF
{
  "default": [
    {
      "type": "insecureAcceptAnything"
    }
  ],
  "transports": {
    "docker": {
      "quay.apps.rd.bdmsky.net": [
        {
            "type": "signedBy",
            "keyType": "GPGKeys",
            "keyPath": "/etc/pki/containers/signer-key.pub"
        }
      ]
    },
    "docker-daemon": {
      "": [
        {
          "type": "insecureAcceptAnything"
        }
      ]
    }
  }
}
EOF

cat <<EOF > quay.apps.rd.bdmsky.net.yaml
docker:
     quay.apps.rd.bdmsky.net:
         sigstore: http://server/signstore
EOF

export DOCKER_REG=$(cat quay.apps.rd.bdmsky.net.yaml | base64 -w0 )
export SIGNER_KEY=$(cat signer-key.pub | base64 -w0 )
export POLICY_CONFIG=$(cat policy.json | base64 -w0 )
```

Then apply using Machine Config

```
cat > worker-custom-registry-trust.yaml <<EOF
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: worker
  name: worker-custom-registry-trust
spec:
  config:
    ignition:
      config: {}
      security:
        tls: {}
      timeouts: {}
      version: 2.2.0
    networkd: {}
    passwd: {}
    storage:
      files:
      - contents:
          source: data:text/plain;charset=utf-8;base64,${DOCKER_REG}
          verification: {}
        filesystem: root
        mode: 420
        path: /etc/containers/registries.d/quay.apps.rd.bdmsky.net.yaml
      - contents:
          source: data:text/plain;charset=utf-8;base64,${POLICY_CONFIG}
          verification: {}
        filesystem: root
        mode: 420
        path: /etc/containers/policy.json
      - contents:
          source: data:text/plain;charset=utf-8;base64,${SIGNER_KEY}
          verification: {}
        filesystem: root
        mode: 420
        path: /etc/pki/containers/signer-key.pub
  osImageURL: ""
EOF
oc apply -f worker-custom-registry-trust.yaml
```

### Deploying application manually after config

First a not signed image

```
oc new-app quay.apps.ocp.bdmsky.net/development/quarkus-hello:notsigned
```

Then a signed image
```
oc new-app quay.apps.ocp.bdmsky.net/development/quarkus-hello:signed
```

# Image Scanning

For this, we'll deploy Quay Operator in an OpenShift environment. As of Quay 3.4, the operator can manage all the required resources for you including the S3 storage. For this first you'll need an S3 endpoint provided by Noobaa.

Reference: https://docs.projectquay.io/deploy_quay_on_openshift_op_tng.html

Let's start by deploying Noobaa. We'll use the following playbooks: https://github.com/rflorenc/openshift-backup-infra

```
ansible-playbook -e env=private main.yml -vv --tags="noobaa"
```

Then install Quay operator using OperatorHub and deploy a QuayRegistry custom resource.

NOTE: Check exactly what the scanning covers

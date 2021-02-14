## Install Clair secret manually

If Quay Operator fails to populate clair config to the clair secret, i.e. it will deploy an empty secret, then the Clair deployment will fail.
To workaround this, you'll need to install the secret manually

```
cat config.yaml|base64 -w0
```

Add this base64 form of the secret to clair config secret, i.e. *clair-config-secret*
```
data: 
  config.yaml: >-
    <base64config>
```


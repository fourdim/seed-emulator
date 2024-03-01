# Create your own Certificate Authority

## Generate a password

```bash
tr -dc "A-Za-z0-9" < /dev/urandom | head -c 64 > password.txt
```

## Generate CA

```bash
step ca init --deployment-type "standalone" --name "SEEDEMU Internal" \
--dns "{caDomain}" --address ":443" --provisioner "admin" --with-ca-url "https://{caDomain}" \
--password-file password.txt --provisioner-password-file password.txt --acme
rm -r ./step
mv -r $(step path) ./step
```

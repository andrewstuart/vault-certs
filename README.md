A simple CLI tool for easily generating a local RSA private key, creating a CSR,
and getting the CSR signed by a vault server.

Usage:

```
Usage of vault-certs:
  -alt string
    	server alternate names, comma-separated
  -csr string
    	certificate signing request file name
  -ips string
    	ip server alternate names, comma-separated
  -k	allow insecure vault serving certificate
  -mount string
    	the vault mount to use (default "pki")
  -org string
    	subject org
  -profile string
    	the vault endpoint/profile to use
  -ttl string
    	the ttl for the certificate (default "8760h")
```

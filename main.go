package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"astuart.co/vpki"
	homedir "github.com/mitchellh/go-homedir"
)

func usage() {
	fmt.Printf(`
	usage: %s [options] <common_name> [cert_prefix]

	Options:
	-k 
	-ttl <hours>
	-alt <comma-separated-altnames>
	-ips <comma-separated-ipsans>
	-org <csr org>
	-csr <csr-file-name>
	-profile <vault mount point/profile>

	Environment:
	VAULT_PKI_PROFILE will be used and can be overridden with the -profile option.
	`, os.Args[0])
}

var (
	mount    = flag.String("mount", "pki", "the vault mount to use")
	profile  = flag.String("profile", os.Getenv("VAULT_PKI_PROFILE"), "the vault endpoint/profile to use")
	ttl      = flag.String("ttl", "8760h", "the ttl for the certificate")
	alt      = flag.String("alt", "", "server alternate names, comma-separated")
	org      = flag.String("org", "", "subject org")
	ips      = flag.String("ips", "", "ip server alternate names, comma-separated")
	csr      = flag.String("csr", "", "certificate signing request file name")
	insecure = flag.Bool("k", false, "allow insecure vault serving certificate")
)

func init() {
	flag.Parse()

	if *profile == "" {
		*profile = "pki"
	}
}

func main() {
	args := flag.Args()

	if len(args) < 1 {
		usage()
		os.Exit(1)
		return
	}

	pfx := args[0]
	if len(args) > 1 {
		pfx = args[1]
	}

	home, err := homedir.Dir()
	if err != nil {
		log.Fatal(err)
	}

	t, err := ioutil.ReadFile(path.Join(home, ".vault-token"))
	if err != nil {
		log.Fatal(err)
	}

	a := os.Getenv("VAULT_ADDR")
	if a == "" {
		log.Fatal("no VAULT_ADDR set; no vault server to get information from")
	}

	cli := vpki.Client{
		Mount: *mount,
		Role:  *profile,
		Addr:  a,
	}

	if *insecure {
		cli.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	if *ttl != "" {
		t, err := time.ParseDuration(*ttl)
		if err != nil {
			log.Fatal(err)
		}
		cli.TTL = t
	}

	cli.SetToken(string(t))

	if *csr != "" {
		bs, err := ioutil.ReadFile(*csr)
		if err != nil {
			log.Fatal("CSR Read Error", err)
		}

		certFile, err := os.OpenFile(fmt.Sprintf("%s.crt", pfx), os.O_RDWR|os.O_CREATE, 0640)
		if err != nil {
			log.Fatal("Output file open error", err)
		}

		res, err := cli.RawSignCSRBytes(bs, pfx, cli.TTL)
		if err != nil {
			log.Fatal("CSR Sign error", err)
		}

		_, err = certFile.Write(res)
		if err != nil {
			log.Fatal("File write error", err)
		}

		certFile.Close()
		return
	}

	names := strings.Split(*alt, ",")

	names = append(names, pfx)

	crtR := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: pfx},
		DNSNames: names,
	}

	if *org != "" {
		orgs := strings.Split(*org, ",")
		crtR.Subject.Organization = orgs
		crtR.Subject.OrganizationalUnit = orgs
	}

	if *ips != "" && len(*ips) > 0 {
		crtR.IPAddresses = []net.IP{}
		for _, addr := range strings.Split(*ips, ",") {
			crtR.IPAddresses = append(crtR.IPAddresses, net.ParseIP(addr))
		}
	}

	certs, err := cli.GenCert(crtR)
	if err != nil {
		log.Fatal(err)
	}

	certFile, err := os.OpenFile(fmt.Sprintf("%s.crt", pfx), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		log.Fatal("Error opening certificate file ", err)
	}
	defer certFile.Close()

	keyFile, err := os.OpenFile(fmt.Sprintf("%s.key", pfx), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal("Error opening key file ", err)
	}
	defer keyFile.Close()

	_, err = certFile.Write(certs.Public)
	if err != nil {
		log.Fatal("Error writing certificate ", err)
	}

	_, err = keyFile.Write(certs.Private)
	if err != nil {
		log.Fatal("Error writing key file ", err)
	}
}

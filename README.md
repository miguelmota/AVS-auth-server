# WIP
<!--
# Run

```bash
npm start
```

# Generating Self-Signed Certificate

AVS requires all requests to be made over https so we have to use a SSL Certificate.

Follow these instructions to generate a self-signed certificate.

```
Update ssl.cnf

CountryName must be 2 characters. Update or add additional IPs.
```

ssl.cnf

```
[req]
distinguished_name      = req_distinguished_name
prompt                  = no

[v3_req]
subjectAltName          = @alt_names

[alt_names]
DNS.1                   = localhost
IP.1                    = 127.0.0.1
IP.2                    = 10.0.2.2

[req_distinguished_name]
commonName              = $ENV::COMMON_NAME                 # CN=
countryName             = US                                # C=
stateOrProvinceName     = CA                                # ST=
localityName            = Los Angeles                       # L=
organizationName        = My Organiztion                    # O=
organizationalUnitName  = 1                                 # OU=
``

Make generation script executable.

```
chmod +x generate.sh
```

```
./generate.sh
```

You will be prompted for `Product ID`.
Find it under `Device Type Info`

You can find this information on the [Amazon Developer Portal](https://developer.amazon.com/edw/home.html)

`Serial Number`

Generate a serial number (ie. 123456)

`Password for Keystores`

Type in a password and remember it!

The output will look something like

```bash
$ ./generate.sh
Product ID: my_device
Serial Number: 123456
Password for Keystores (won't echo): Generating RSA private key, 4096 bit long modulus
........................................................................++
......................................................................................................................................++
e is 65537 (0x10001)
Generating RSA private key, 2048 bit long modulus
........................+++
................................................................+++
e is 65537 (0x10001)
Signature ok
subject=/CN=my_device:123456/C=US/ST=CA/L=Los Angeles/O=My Organiztion/OU=1
Getting CA Private Key
Generating RSA private key, 2048 bit long modulus
......................................................................+++
.......................+++
e is 65537 (0x10001)
Signature ok
subject=/CN=localhost/C=US/ST=CA/L=Los Angeles/O=My Organiztion/OU=1
Getting CA Private Key
Generating RSA private key, 2048 bit long modulus
............................................+++
....+++
e is 65537 (0x10001)
Signature ok
subject=/CN=localhost/C=US/ST=CA/L=Los Angeles/O=My Organiztion/OU=1
Getting CA Private Key
```

After generation there will a new directory `certs` containing certs.

move `certs/server/node.key` to ssl/server.key
move certs/server/node.crt to ssl/server.crt
move certs/server/node.csr to ssl/server.csr


Set your clientId and client Secret as well as products in `config.js`

You can find this information on the [Amazon Developer Portal](https://developer.amazon.com/edw/home.html) under `Security Profile`.

, // Fill in with valid device values, eg: 'testdevice1': ['DSN1234', 'DSN5678']

For more information visit the [Reference Implementation Guide](https://developer.amazon.com/public/solutions/alexa/alexa-voice-service/docs/reference-implementation-guide).
-->
# License

MIT

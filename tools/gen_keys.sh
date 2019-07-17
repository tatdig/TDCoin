openssl ecparam -genkey -name secp256k1 -out $1.pem
openssl ec -in testnetalert.pem -text > $1.hex

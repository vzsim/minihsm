#!/bin/bash

export HSM_LIB="/opt/safenet/protecttoolkit7/ptk/lib/libcryptoki.so"
export HSM_TOKEN="SMDP"
export HSM_SLOT_ID="0"
export HSM_PIN="3333"

export CURVE="prime256v1"
# export CURVE="brainpoolP256r1"

export HSM_CI_LABEL="CI_ECDSA_NIST_TEST"
export HSM_CI_ID="A3B0"
# export HSM_EUM_LABEL="EUM"
# export HSM_EUM_ID="b1"
export HSM_DP_AUTH_LABEL="DPauth_ECDSA_NIST"
export HSM_DP_AUTH_ID="A3B1"
export HSM_DP_PB_LABEL="DPpb_ECDSA_NIST"
export HSM_DP_PB_ID="A3B2"
# export HSM_DP_TLS_LABEL="DP_TLS"
# export HSM_DP_TLS_ID="b4"

mkdir -p out

hsm () {
  pkcs11-tool --module $HSM_LIB --login --pin $HSM_PIN --token $HSM_TOKEN $@
}

openssl-pkcs11 () {
  OPENSSL_CONF=ssl/openssl-pkcs11.cnf openssl $@
}

hsm-delete-object () {
   $HSM --delete-object --type $1 --label $2
}

## CI
# Keypair
hsm --keypairgen --key-type "EC:${CURVE}" --mechanism ECDSA-KEY-PAIR-GEN --id "${HSM_CI_ID}" --label "${HSM_CI_LABEL}"
# CSR
openssl-pkcs11 req -new -x509 -sha256 -engine pkcs11 -keyform engine \
              -key "slot_${HSM_SLOT_ID}-label_${HSM_CI_LABEL}" \
              -config ssl/CI_csr.cnf -extensions extend \
              -out out/CI_csr.pem
# Certificate
openssl-pkcs11 req -x509 -sha256 -days 7305 -engine pkcs11 -keyform engine \
               -key "slot_${HSM_SLOT_ID}-label_${HSM_CI_LABEL}" \
               -config ssl/CI_csr.cnf -extensions extend \
               -out out/CI_cert.pem
# Convert PEM to DER and TXT
openssl x509 -text -inform PEM -in out/CI_cert.pem > out/CI_cert.txt
openssl x509 -inform PEM -outform DER -in out/CI_cert.pem -out out/CI_cert.der
# Write to HSM
hsm --type cert --write-object out/CI_cert.der --id "${HSM_CI_ID}" --label "${HSM_CI_LABEL}" 

## DBAuth
# Keypair
hsm --keypairgen --key-type "EC:${CURVE}" --mechanism ECDSA-KEY-PAIR-GEN --id "${HSM_DP_AUTH_ID}" --label "${HSM_DP_AUTH_LABEL}"
# CSR
openssl-pkcs11 req -new -nodes -sha256 -engine pkcs11 -keyform engine \
               -key "slot_${HSM_SLOT_ID}-label_${HSM_DP_AUTH_LABEL}" \
               -config ssl/DPauth_csr.cnf -out out/DPauth_csr.pem
# Certificate
openssl-pkcs11 x509 -req -sha256 -days 7305 -engine pkcs11 -CAkeyform engine \
               -CA out/CI_cert.pem -CAkey "slot_${HSM_SLOT_ID}-label_${HSM_CI_LABEL}" \
               -set_serial 200010007001 \
               -in out/DPauth_csr.pem -extfile ssl/DPauth_ext.cnf \
               -out out/DPauth_cert.pem
# Convert PEM to DER and TXT
openssl x509 -outform DER -in out/DPauth_cert.pem -out out/DPauth_cert.der
openssl x509 -text -inform PEM -in out/DPauth_cert.pem  > out/DPauth_cert.txt
# Write to HSM
hsm --type cert --write-object out/DPauth_cert.der --id "${HSM_DP_AUTH_ID}" --label "${HSM_DP_AUTH_LABEL}" 

## DPpb
# Keypair
hsm --keypairgen --key-type "EC:${CURVE}" --mechanism ECDSA-KEY-PAIR-GEN --id "${HSM_DP_PB_ID}" --label "${HSM_DP_PB_LABEL}"
# CSR
openssl-pkcs11 req -new -nodes -sha256 -engine pkcs11 -keyform engine \
               -key "slot_${HSM_SLOT_ID}-label_${HSM_DP_PB_LABEL}" \
               -config ssl/DPpb_csr.cnf -out out/DPpb_csr.pem
# Certificate
openssl-pkcs11 x509 -req -sha256 -days 7305 -engine pkcs11 -CAkeyform engine \
               -CA out/CI_cert.pem -CAkey "slot_${HSM_SLOT_ID}-label_${HSM_CI_LABEL}" \
               -set_serial 200010007001 \
               -in out/DPpb_csr.pem -extfile ssl/DPpb_ext.cnf \
               -out out/DPpb_cert.pem
# Convert PEM to DER and TXT
openssl x509 -outform DER -in out/DPpb_cert.pem -out out/DPpb_cert.der
openssl x509 -text -inform PEM -in out/DPpb_cert.pem  > out/DPpb_cert.txt
# Write to HSM
hsm --type cert --write-object out/DPpb_cert.der --id "${HSM_DP_PB_ID}" --label "${HSM_DP_PB_LABEL}" 

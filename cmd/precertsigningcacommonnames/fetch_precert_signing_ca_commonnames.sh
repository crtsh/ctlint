#!/bin/bash

cat <<SQL | tr -d '\n' | psql -h crt.sh -p 5432 -U guest -d certwatch -v ON_ERROR_STOP=1 -X
\COPY (
SELECT DISTINCT x509_commonName(c.CERTIFICATE)
  FROM ccadb_certificate cc
         JOIN certificate c ON (cc.CERTIFICATE_ID = c.ID)
         JOIN x509_extKeyUsages(c.CERTIFICATE) ON (x509_extKeyUsages = '1.3.6.1.4.1.11129.2.4.4')
  WHERE cc.INCLUDED_CERTIFICATE_OWNER IS NOT NULL
  ORDER BY x509_commonName(c.CERTIFICATE)
) TO '../../files/precert_signing_ca_commonnames.txt'
SQL

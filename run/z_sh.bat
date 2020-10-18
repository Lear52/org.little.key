@echo off
java -cp little-key-1.0.0-SNAPSHOT-little-shade.jar  -Duser.region=US  -Dencoding=Cp866 -Dfile.encoding=UTF8  org.little.key.kMessageX509 CERT_DER.cer 
java -cp little-key-1.0.0-SNAPSHOT-little-shade.jar  -Duser.region=US  -Dencoding=Cp866 -Dfile.encoding=UTF8  org.little.key.kMessageX509 CRL_DER.crl 
java -cp little-key-1.0.0-SNAPSHOT-little-shade.jar  -Duser.region=US  -Dencoding=Cp866 -Dfile.encoding=UTF8  org.little.key.kMessageX509 CSR_DER.csr 


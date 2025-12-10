# ONCE (OpenId Connect eID)

El objetivo de este proyecto es replicar el sistema de autenticación utilizado por las
diferentes administraciones públicas para acreditar la identidad real de los usuarios
que acceden al sistema informático.

Este servidor solicita al cliente su certificado de autenticación y lo comprueba con la
cadena de certificados que tenga configurada según el archivo `.env`.

Debido a los mecanismos soportados por la plataforma PKCS#11 del DNIe, el servidor está
configurado para utilizar solo el protocolo TLSv1.2 con las siguientes suites de cifrado:

- TLS ECDHE RSA AES256 GCM SHA384
- TLS ECDHE RSA AES128 GCM SHA256
- TLS ECDHE ECDSA AES256 GCM SHA384
- TLS ECDHE ECDSA AES128 GCM SHA256

Por el mismo motivo solo se pueden utilizar los siguientes algoritmos de firma para
verificar al cliente:

- RSA+SHA512
- RSA+SHA384
- RSA+SHA256
- ECDSA+SHA512
- ECDSA+SHA384
- ECDSA+SHA256

Una vez validado el certificado cliente, el servidor responde con un JWT firmado con la
clave privada que se especifique en el archivo de configuración `.env`.

# Limitaciones

- Actualmente el servidor no comprueba la validez del certificado con OCSP ni CRL.

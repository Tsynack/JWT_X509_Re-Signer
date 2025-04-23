This is purely an example API that should only ever be run locally. Nothing about this is hardened and is intended to demonstrate vulnerabilities in JWS.

You will need an x509 key pair for this API to work properly. Generate with the below command. 
    The private_key.pem should be put in the Example_API directory.
    The cert.pem should be placed in Example_API/content directory.

`openssl req -newkey rsa:2048 -nodes -keyout private_key.pem -x509 -days 365 -out cert.pem`
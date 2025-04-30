This is an example for exploiting JSON Web Signatures using X.509 certificates. The Example API is purposefully vulnerable and allows for the token to be re-signed using an attacker's key pair. 

The Burp extension provides UI functionality for re-signing a token using an imported private key and certificate. 

## Setup
Setup a python virtual environment so that you can install the requirements without messing up any other packages.

```
mkdir X509_API
python3 -m venv X509_API
source X509_API/bin/activate
cd X509_API
git clone https://github.com/Tsynack/JWT_X509_Re-Signer.git
cd JWT_X509_Re-Signer
pip3 install -r requirements.txt
```

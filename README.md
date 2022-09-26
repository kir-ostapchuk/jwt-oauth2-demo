To run the application these actions are required:
* create public and private keys
* set up environment variables

** To Create public and private keys:
1. Create folder certs under resources
2. cd src/main/resources/certs/
3. openssl genrsa -out keypair.pem 2048
4. openssl rsa -in keypair.pem -pubout -out public.pem
5. openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem 

** Set up the environment variables. They are required for both docker-compose and application run.

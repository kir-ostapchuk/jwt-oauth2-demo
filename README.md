<h3>Implementation Conclusion</h3>
In-built JWT implementation could not be used properly from my perspective.
This is why:
It works but not properly. The biggest problems:

1. 401 that is thrown by filter I am not able to handle with custom message
2. access token is validating by default but for refresh token I have to write custom validation
As a result, it's not so difficult to use from here https://github.com/kir-ostapchuk/carrent-backend/tree/master/src/main/java/com/ostapchuk/car/rent/security (refresh token logic is not present right now)


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

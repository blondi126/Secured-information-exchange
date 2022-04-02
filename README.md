Client-Server application running on sockets.

When a connection is established, the server and client receive a shared secret key using the Diffie-Hellman protocol:
1. The server and the client generate 128-bit private keys a and b. 
2. The server generates a large prime number p and g, which is a primitive root modulo p. Also calculate public key A.
3. Sends p, g and A to the client.
4. The client calculates the public key B and sends it to the server. 
5. Both parties calculate a shared secret key K.

After the shared secret is set, data exchange begins with encryption using the symmetric RC4 algorithm:
1. Initialize the permutation in the array "S" (Key-Scheduling Algorithm).
2. Pseudo-random word generation K (PRGA) and XOR it with part of the message (as many times as needed).

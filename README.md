## jsse-dtls-server
A rough DTLS echo server used for testing the JSSE implementation of DTLS.
Support for DTLS was added in Java 9, though that support is limited to the SSLEngine, which is now DTLS-capable.
The program was used to test JSSE as part of the state fuzzing work published in [USENIX 20][usenix]. 
As we extended the program for clients, we moved development to a [new repository][new-jsse].

One could say SSLEngine  implements the core state machine or brain of the (D)TLS implementation.
It is left to the user to connect this brain to the application by:
* sending network data generated by the brain to the corresponding peer;
* receiving and supplying network data to the brain, particularly when the brain is expecting this data;
* running any tasks the brain issues;
* sending/receiving application data, with the brain used for encrypting it into/decrypting it from network data.

For an in-depth description, I refer you to Oracle's [SSLEngine page][oracle].

*run.sh* is added for convenience to compile and run the program on a POSIX system. 
For Windows, just run the commands as they are in the script file replacing $@ with arguments.

The SSLEngine architecture is truly fascinating and something I want to more deeply explore at some point.
That is NOT the purpose of this project however, this is just meant to be a dirty server implementation that just works.

I refer you to [sslengine.example][sslengine] for a nicely coded example of a TLS client/server implemented using SSLEngine. 
A nice project would be extending that also for DTLS.

[usenix]:https://www.usenix.org/conference/usenixsecurity20/presentation/fiterau-brostean
[sslengine]:https://github.com/alkarn/sslengine.example
[oracle]:https://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLEngine.html
[new-jsse]:https://github.com/assist-project/jsse-dtls-clientserver

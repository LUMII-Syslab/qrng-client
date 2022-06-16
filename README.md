# QRNG Client

Providing true randomness to Linux and Windows programs via a remote QRNG (quantum random number generator) device.
The communication with the remote QRNG is performed by means of web sockets, where for authentication and key exchange, quantum-resistant algorithms are used.

For Linux, we provide the "qrng" systemd service and the "qrng" Linux kernel module, which creates the /dev/qrandom0 device, which communicates with a remote QRNG web service.

On Windows, our qrng.dll provides hooks for Windows API functions CryptGenRandom, BCryptGenRandom, and RtlGenRandom. These functions are used by programs compiled for Windows (e.g., openssl.exe) for obtaining random numbers. We re-implement these functions by returning random numbers obtained from a remote QRNG device.

#### Contributors

* Sergejs Kozlovičs

  (Institute of Mathematics and Computer Science, University of Latvia)

#### License

MIT + third-party licenses for third-party code (e.g., Apache 2.0 license for the `nl.altindag.ssl` package, GPLv2 with Classpath exception for GraalVM-related code that will be compiled into the client, etc.)


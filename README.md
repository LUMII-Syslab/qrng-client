# QRNG Native Client

(work in progress, some parts working)

Providing true randomness to Linux and Windows programs via a remote QRNG (quantum random number generator) device.

The communication with the remote QRNG is performed by means of web sockets, where for authentication and key exchange, quantum-resistant algorithms (PQC) are used.

An example of such remote QRNG service is our [qrng.lumii.lv](qrng.lumii.lv).

## Prerequisites

You will need GraalVM based on JDK16+ to compile the native client library ("qrng.dll", "qrng.dylib", "libqrng.so"). You can download GraalVM by means of [our scripts](https://github.com/sergejskozlovics/get_sdk). Add (as the first element) `/path/to/graalvm/bin` to your `PATH` variable. In Windows, use the semicolon `;` as PATH delimiter. In other operating systems, use the colon `:`.

On Linux, specify the `LD_LIBRARY_PATH=/path/to/graalvm/lib` environment variable.

On MacOS, specify the `DYLD_LIBRARY_PATH=/path/to/graalvm/lib` environment variable.

## Building the Native Library

```bash
./gradlew nativeCompile
```

## Testing the Native Library

In order to test the native library, put the configuration file as well as PQC keys/certificates into the same directory, where the native library has been built (i.e., into `build/native/nativeCompile`). You will need these files:

* `ca.truststore` (the root CA certificate used to sign the QRNG server HTTPS certificate and client sertificates)
* `token.keystore` (your client certificate, signed by the CA that serves the QRNG server)
* `qrng.properties` (key passwords and other settings)

As these files from the administrator of the remote QRNG service.

Then run (from the project root):

```bash
./gradlew testNative
```

That will build the test program (from `src/test/cpp`) that tries (twice) to get random numbers from the remote QRNG via a quantum-safe link. The first try is expected to return 10 random bytes. The second try is expected to return an error message.

## Work in Progress...

For Linux, we are going to provide the "qrng" systemd service and the "qrng" Linux kernel module, which creates the /dev/qrandom0 device, which communicates with a remote QRNG web service.

On Windows, we are working on qrng.dll, which will provide hooks for Windows API functions CryptGenRandom, BCryptGenRandom, and RtlGenRandom. These functions are used by programs compiled for Windows (e.g., openssl.exe) for obtaining random numbers. We re-implement these functions by returning random numbers obtained from a remote QRNG device.

#### Contributors

* Sergejs Kozlovičs

  (Institute of Mathematics and Computer Science, University of Latvia)

#### License

MIT + third-party licenses for third-party code (e.g., Apache 2.0 license for the `nl.altindag.ssl` package, GPLv2 with Classpath exception for GraalVM-related code that will be compiled into the client, etc.)


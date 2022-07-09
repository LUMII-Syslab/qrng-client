# QRNG Native Client

(work in progress, some parts working)

Providing true randomness to Linux and Windows programs via a remote QRNG (quantum random number generator) device.

The communication with the remote QRNG is performed by means of web sockets, where for authentication and key exchange, quantum-resistant algorithms (PQC) are used.

An example of such remote QRNG service is our [qrng.lumii.lv](https://qrng.lumii.lv).

## Prerequisites

#### GraalVM

You will need GraalVM based on JDK16+ to compile the native client library ("qrng.dll", "qrng.dylib", "libqrng.so"). You can download GraalVM by means of [our scripts](https://github.com/sergejskozlovics/get_sdk). Add (as the first element) `/path/to/graalvm/bin` to your `PATH` variable. In Windows, use the semicolon `;` as PATH delimiter. In other operating systems, use the colon `:`.

In Linux, specify the `LD_LIBRARY_PATH=/path/to/graalvm/lib` environment variable.

In MacOS, specify the `DYLD_LIBRARY_PATH=/path/to/graalvm/lib` environment variable.

#### Native Image for GraalVM

```bash
gu install native-image
```

#### Dev Tools

In Windows, you will need

* [Git for Windows](https://gitforwindows.org/)

* [Visual Studio Community](https://visualstudio.microsoft.com/free-developer-offers/) with C++ tools.
  Visual Studio is free for academic reseach and open source development. However, it is a paid software, if used for commercial purposes.

* CMake tools: https://marketplace.visualstudio.com/items?itemName=ms-vscode.cmake-tools

* 

In other operating systems, install dev tools and `git` using the appropriate package manager (such as `apt` or `brew`). See [Native Image docs](https://www.graalvm.org/22.1/reference-manual/native-image/).

#### Clone the Sources

```bash
git clone https://github.com/LUMII-Syslab/qrng-client.git
```

## Building the Native Library in Windows

Launch `cmd` and initialize Visual Studio environment variables (use your version in the path):

```bash
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cd C:\path\to\qrng-client
gradlew nativeCompile
```

If  you get an error like

```bash
Fatal error: Unsupported OptionOrigin: C:\Users\SysLab\AppData\Local\Temp\native-image822152195599878649args
```

then this is a GraalVM bug. Split the path shown in the error message into two parts, and invoke:

```bash
cd C:\Users\SysLab\AppData\Local\Temp
native-image @native-image822152195599878649args
```

In `build.gradle`, comment the line (otherwise you won't be able to run tests due to the bug mentioned above):

    // dependsOn nativeCompile 

## Building the Native Library in UNIX (Linux/MacOS)

```bash
cd /path/to/qrng-client
./gradlew nativeCompile
```

## Testing the Native Library

You will need these files:

- `ca.truststore` (the root CA certificate used to sign the QRNG server HTTPS certificate and client sertificates)
- `token.keystore` (your client certificate, signed by the CA that serves the QRNG server)
- `qrng.properties` (key passwords and other settings)

Obtain these files from the administrator of the remote QRNG service and put them into the same directory, where the native library has been built (i.e., into `build/native/nativeCompile`). 

Then run (from the project root):

```bash
./gradlew testNative
```

That will build the `test.exe` program (from `src/test/cpp/test.cpp`) that tries (twice) to get random numbers from the remote QRNG via a quantum-safe link. The first try is expected to return 10 random bytes. The second try is expected to return an error message.

## Work in Progress...

For Linux, we are going to provide the "qrng" systemd service and the "qrng" Linux kernel module, which creates the /dev/qrandom0 device, which communicates with a remote QRNG web service.

On Windows, we are working on qrng.dll, which will provide hooks for Windows API functions CryptGenRandom, BCryptGenRandom, and RtlGenRandom. These functions are used by programs compiled for Windows (e.g., openssl.exe) for obtaining random numbers. We re-implement these functions by returning random numbers obtained from a remote QRNG device.

## Contributors

* Sergejs Kozlovičs
  
  (Institute of Mathematics and Computer Science, University of Latvia)

## License

MIT + third-party licenses for third-party code (e.g., Apache 2.0 license for the `nl.altindag.ssl` package, GPLv2 with Classpath exception for GraalVM-related code that will be compiled into the client, etc.)

# QRNG Client with SmartCard Authentication

This repository contains additional (proprietary) files that provide support for QRNG client authentication using smartcards (Java cards). The files are located in the `lv.lumii.smartcard` Java package (directory inside `src/main`).

## What to do after `git clone`

When you clone this repository for the first time, configure the `upstream` remote:

```bash
git remote add upstream https://github.com/LUMII-Syslab/qrng-client
git remote set-url --push upstream DISABLE
```

Then you will be able to update your clone from the upstream as follows:

```bash
git fetch upstream
git rebase upstream/main
```

## How to install Linux libraries for smartcard support

On Ubuntu, install the prerequisites and restart `pcscd`:

```
sudo apt-get install libccid pcscd libpcsclite-dev libpcsclite1
sudo service pcscd start
```

## How to configure the QRNG client for using the private key stored on a smartcard

In the `qrng.properties` file, specify the `token` setting with the `smartcard:` prefix. 

> If you are on Linux, specify also the `smartcardLibrary` property contating the full path of the `libpcsclite.so.1` library  (the value will be mapped to the JVM property `sun.security.smartcardio.library` used by Java to access smart card readers).

Example:

```
token=smartcard:*
smartcardLibrary=/usr/lib/x86_64-linux-gnu/libpcsclite.so.1
```

The asterisk denotes "any smart card reader". If you have multiple readers, replace the asterisk with any substring of the name of the desired smartcard reader.

On Linux, you can list your smart card readers by invoking the command:

```bash
opensc-tool -l
```

If you don't have the opensc-tool, install it via:

```bash
sudo apt install opensc
```

## How to create a smart card with a private key and a PQC certificate

This step is needed only for QRNG service providers, who write private keys and their corresponding certificates to smartcards.

[TODO]

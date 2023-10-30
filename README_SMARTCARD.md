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

### How to install the authentication applet on the smart card

#### What you will need

1. Java Card Development Kit, version 3.0.4 - for compiling the applet code into a .CAP file. This kit can be downloaded here: https://download.oracle.com/otn-pub/java/java_card_kit/3.1/java_card_tools-win-bin-b_17-06_jul_2021.zip.
2. Global Platform Pro - for installing the .CAP file onto the smart card. This tool can be downloaded here: https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar

Both tools are also included in this repository.

#### How to compile and install the applet on Linux

1. Configure the file `src/javacard/compileAndInstall` by providing the correct paths to the Java Card Development Kit and the Global Platform Pro tool if you have downloaded them manually. If you wish to exploit the tools included in this repository, you don't have to alter this file.
2. Run the file `src/javacard/compileAndInstall`. It will perform the necessary steps to compile the applet source code into a .CAP file and install it onto your smart card (be sure the smart card in inserted into the smart card reader that is attached to your computer and that there is enough free space on the smart card).

### How to send your private key and your PQC certificate to the installed applet

#### What you will need

The Smart Card Shell Tool - it can be downloaded here: https://www.openscdp.org/scsh3/download.html. This tool allows executing scripts that interacts with the applets on smart cards. After installing the Smart Card Shell on Linux, open the file `scsh3gui`. Here, a script file can be executed like this:

`load("myScript.js");`

The script files to be executed are located in the folder `scr/javacard/scripts` of this repository.

#### Sending the data to the applet

To send the private key and the PQC certificate to the applet that has been installed on the smart card, the scripts need to be executed in this order in the Smart Card Shell Tool (be sure the smart card in inserted into the smart card reader that is attached to your computer):

1. `select.js`

   This script will select the correct applet on the smart card

2. `sendData.js`

   This script sends all the data to the applet. Before executing this script, you need to alter it by assigning the correct values to these variables:

   - `cert`: the PQC certificate
   - `pubk`: the public key
   - `pub_exp`: the public key exponent
   - `priv_exp`: the private key exponent
   - `mod`: the modulus

3. `closeCard.js`

   This script safely closes the connection with the applet

#### Testing out the applet

After you have sent the key and the certificate to the applet, you can test whether everything works fine, i.e., you can try to sign a message and to verify a signature. To sign a message, you have to run the script `sign.js`. To verify a signature, you have to run the script `verify.js` (before that, you have to alter the values of the variables `s` and `sign` that are the message and the signature, accordingly). Before running the signing and/or verifying scripts, you have to run the `select.js` script to connect to the applet, and afterwards you need to run the `closeCard.js` script to close the connection safely.


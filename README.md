Atonomi Device SDK
================================================================================
Atonomi's Embedded Device SDK is a software library providing mechanisms to
communicate with the Atonomi network. Atonomi provides a network solution which
tackles the question of how to establish identity, trust, and reputation of IoT
devices. The blockchain-based approach allows companies to securely exchange
services and data to, from, and involving these devices.

The Embedded Device SDK provides a small-footprint code implementation of
messaging routines for communications between an IoT device and the Atonomi
Identity Registration Network (IRN). Aimed at embedded systems, this library
is intended to be easy to use, integrate, and deploy, and provides support
for vast numbers of SoCs and operating environments, especially those which
leverage ARM Cortex-M or Cortex-A IP cores.


### Getting the Code
The SDK is made available via a GitHub-hosted git repository
[here](https://github.com/atonomi/device-sdk), where it can easily be cloned
or otherwise downloaded for use.

```bash
git clone git@github.com:atonomi/device-sdk atonomi-device-sdk
```


### Project Layout
The SDK is currently distributed as a pre-compiled static library for
various architectures, along with a header file providing a C language
API for use by developers to construct packetized messages for
the Atonomi network.

All libraries are located within the _lib/_ subdirectory, and all include
files are located within the _include/_ subdirectory.

A usage example of pack and unpack routines for an endpoint is present within
the _example/_ subdirectory. Alongside this is a shell script which
uses the _curl_ utility to demonstrate a successful HTTP transaction
with Atonomi servers and the receipt of a response to the submitted request.


### Implementation Requirements
In order to be used properly, this SDK has two primary requirements:

- Developers are required to implement a callback to obtain random data from
a Hardware Random Number Generator.
- The SDK functions use up to four kilobytes (4096 bytes) of stack space.
Developers are responsible for ensuring this space is available
in order to prevent a stack overflow or stack-heap collision.
- errno-compatible declarations must be available. Developers may either
include errno.h from a platform's libc, or instead use the provided
atmi_errno.h file. The SDK is careful to restrict itself to those
values which are consistent across all major UNIX platforms (Linux, BSD,
Solaris, AIX, IRIX, etc.), so the source of errno declarations that is
most convenient should be preferred.


### Further Documentation
For more details, see the PDF document located within the _doc/_ subdirectory.


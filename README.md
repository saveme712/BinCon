# BinCon
A library to assist with memory &amp; code protection. This is not meant to be a drop in replacement for anything, but as an example for how to provide an 
increased layer of protection on top of virtualization or code mutation.

The example project provides an example of a simple console application hardened against memory scans, memory modifications, debuggers, and other things.

# Features

## Obfuscated Variables
Support for transparent obfuscation of native data types, including pointers, and integers.

## VEH Pointer Obfuscation
Support for transparent obfuscation of pointers, where the decryption is handled by a custom VEH routine that will
emulate the memory read with the real decrypted address.

## Build Time Randomization
The expression used to obfuscate variables will be randomized before a build is started.

## Encrypted Sections
Keep your code sections encrypted and unavailable in memory until they're accessed, with periodic re-encryption.

## Memory Allocator
A very poorly made memory allocator that supports randomizing the allocated blocks. Will be redone soon TM.
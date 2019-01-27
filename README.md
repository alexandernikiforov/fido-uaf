[![Coverage Status](https://coveralls.io/repos/github/alexandernikiforov/fido-uaf/badge.svg?branch=master)](https://coveralls.io/github/alexandernikiforov/fido-uaf?branch=master) [![Build Status](https://travis-ci.com/alexandernikiforov/fido-uaf.svg?branch=master)](https://travis-ci.com/alexandernikiforov/fido-uaf)
# FIDO UAF 1.1 Protocol anf Assertion Parser Support
The goal of this small project was to practise creating a library to parse TLV structures as defined in FIDO Authenticator Commands Specification. From there the full support for building and parsing the FIDO assertions has been implemented. There is also some basic support for de- and serialization of the FIDO UAF 1.1. Protocol structures from and to JSON.

This is also an example how to build a multi-project Gradle-based project on Travis CI, with the test coverage sampled by Jacoco and published to Coveralls.

The source code is licensed under GPL 3.0.

Technologies used:
 * Java 8
 * Google AutoValue
 * Jackson (JSON)
 * Guava

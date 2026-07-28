# Preliminary U.S. encryption export review

Review date: July 27, 2026

Scope: RedactLens source code and the Windows x64 release architecture described in this
repository.

This document records a good-faith technical screening under the U.S. Export Administration
Regulations (EAR). It is not a Commodity Classification Automated Tracking System (CCATS)
determination, legal opinion, export license, or guarantee that a particular transaction is
authorized. The person or organization making an export remains responsible for the destination,
end user, end use, release artifact, and law in effect on the export date.

## Technical facts reviewed

RedactLens:

- is a local file-scanning and redaction application, not a cryptographic product;
- does not implement proprietary, unpublished, or user-configurable cryptographic algorithms;
- does not encrypt or decrypt user files;
- does not provide a VPN, encrypted communications service, key-management product, penetration
  capability, cryptanalytic capability, or general-purpose cryptographic interface;
- uses SHA-256 to verify file identity and integrity before trusted file operations;
- uses operating-system/Python random-token and constant-time comparison facilities to
  authenticate requests to its loopback API;
- binds the application API to the local loopback interface;
- connects to optional Ollama only through a loopback address; and
- publishes its application source under the MIT License.

The packaged Windows runtime also contains unmodified Python networking/runtime components,
including OpenSSL `libcrypto` and `libssl` libraries and Python's `_ssl` module. They are included
as third-party runtime dependencies. RedactLens does not expose them as a development kit or
general-purpose cryptographic library and its product workflow does not invoke them to provide
data-confidentiality encryption.

## Preliminary classification

BIS guidance distinguishes authentication, digital signatures, data integrity, and
non-repudiation from "cryptography for data confidentiality." Based on the reviewed functionality,
RedactLens's own cryptographic operations are limited to authentication and integrity.

The working classification for the RedactLens application source and end-user functionality is
therefore **EAR99**, because the reviewed product functionality does not appear to be described by
Category 5, Part 2 of the Commerce Control List.

This is a preliminary self-assessment, not an official BIS classification. The presence of
unmodified Python/OpenSSL object code means each final binary should be screened as a whole rather
than assuming it inherits the source-code conclusion. If a distributor concludes that the final
binary provides usable data-confidentiality encryption, the likely alternative path is mass-market
encryption treatment under ECCN 5D992.c after completing any applicable classification and
reporting requirements.

## Release controls

For every public binary release:

1. Preserve the source commit, dependency locks, release hashes, and software bill of materials.
2. Confirm that no data-confidentiality encryption or general-purpose cryptographic interface was
   added.
3. Recheck current BIS requirements before making the binary available worldwide.
4. Do not knowingly export or provide the software to prohibited destinations, restricted parties,
   or prohibited end uses.
5. Obtain export counsel or request a BIS classification when the technical facts are uncertain,
   the product will be customized for government or military use, or a transaction involves a
   restricted jurisdiction, party, or end use.

## Changes that require a new review

Repeat this analysis before releasing any version that adds:

- encryption of files, folders, reports, settings, backups, or network traffic;
- remote HTTPS transfer of scanned content;
- custom, proprietary, unpublished, or user-selectable cryptography;
- cryptographic key generation, storage, exchange, or management;
- a reusable cryptographic API, library, module, SDK, or command-line interface;
- VPN, proxy, secure-messaging, network-security, penetration-testing, digital-forensics, or
  cryptanalytic functionality; or
- government, military, intelligence, or restricted-end-use customization.

## Authoritative references

- [BIS encryption controls overview](https://www.bis.gov/learn-support/encryption-controls)
- [BIS cryptography for data confidentiality guidance](https://www.bis.gov/learn-support/encryption-controls/cryptography-for-data-confidentiality)
- [BIS encryption items not subject to the EAR](https://www.bis.gov/learn-support/encryption-controls/encryption-items-not-subject-to-ear)
- [BIS mass-market encryption guidance](https://www.bis.gov/learn-support/encryption-controls/mass-market)
- [EAR section 740.17](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-740/section-740.17)
- [EAR section 742.15](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-742/section-742.15)

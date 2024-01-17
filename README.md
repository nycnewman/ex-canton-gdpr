#  Identity Management

This sample demonstrates a way to distribute sensitive data using On/Off-Ledger encryption.

## I. Overview 

Various privacy and payment regulations recommend the use of encryption to protect sensitive data. Sensitive data might include PII, PHI, payment or credit card data. 

Daml/Canton provides protection without encryption in the following forms:

- Native enforcement of access in the Daml data model and workflows
- Native privacy through the partial, segmented distribution of data only to stakeholders and their participants
- Ability to rune the ledger to remove archived copies of data ("Right to Forget")

In many cases the above may be sufficient for your use case.

However, many companies demand additional protection in the form of data encryption. The goals of encryption include the following:

- Protecting from Database Admin (DBA) access to cleartext copies of the data
- Protecting DB backups from containing cleartext copies of the data
- Protecting a subset of shared data from parties who should see the cleartext copy but not the sensitive data

## II. Workflow

A Data Owner (Controller) can create an IdentityGroup contract to manage a list of SubProcessors. The controller can invite other Parties by exercising InviteNewMember choice. The subprocessors can then registered their public key (additional workflow to validate public key could be implemented). AES256 Encryption Keys can be created and then distributed to the members of the IdentityGroup, wrapped using their public key. DataSubject Records can be create with privateData encrypted using the shared Encryption Key. PrivateData is a text field and JSON encoded data is used in this example.

  1. Data Controller creates a IdentityGroup contract
  2. Data Controller can invites other parties through InviteParty choice
  3. Invited parties can accept invite by providing their public key in a Registered Identity record 
  4. Data Controller creates an EncryptionKey contract with a wrapped copy of a Data Encryption Key (DEK)
  5. Automation distrbutes copies of the DEK to the IdentityGroup membership, wrapped with the public key of invited parties. This is stored in SharedKey records, one per IdentityGroup and invited party
  6. Data Controller can create DataSubject records with encrypted copies of the private data. The encryption uses AES256 symmetric encryption and an IV is generated for each copy of private data
  7. Each invited party can download the DataSubject data and decrypt the data by obtaining the DEK using their private key
  8. Parties who have visibility to the DataSubject contract but are not in the IdentityGroup cannot decrypt the encrypted data set

This sample demonstrates:
- Use of Daml workflows to manage set(s) of identities and ability to register off ledger public keys
- Use of automation to use asymmetric encryption to secure data encryption keys and use Daml/Canton to distribute to participants
- Demonstrate ability to differentiate between completely shared access to record and encrypted data, through to no access or only to non-sensitive fields

## III. Alteratives / Know Issues / TODOS

Alternatives
- An additional workflow step could added where the Data Controller can validate a registration proposal (validate the public key being offered through an out of band mechanism)
- Structure of data subject is use case dependent
- The use of asymmetric DEK instead of symmetric might allow separation of read and write access to data

TODOs
- Code is example only and in not way fit for any for of production use (error handling, unhappy paths, audit of encryption implementation)
- Offboarding flows are not implemented. One could add choices and automation to remove copies of shared keys for uninvited participants
- Does not demonstrate pruning of data set
- Whilst Daml model support variations in encryption and on/off ledger storage, only on-ledger, encrypted storage is tested
- UI

## IV. Compiling & Testing

Run each of the following commands in a separate shell:

* Start the sandbox and navigator on default port 6865 via:

```
      daml start
```

* Start Automation in a separate window

```
      run-owner.sh
```

This performs the following:
- starts various long running automation for owner and five identities
- run through invitation of identities 1 through 4 (not 5)
- creates two encryption keys and two data subject records encryption with separate keys

Expected Results:

- Identity1 should see both data subject contracts and all private data
- Identity2 should only see one data subject contract and be able to see private data
- Identity5 should only see one data subject contract and not be able to decrypt the private data

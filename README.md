#  Sensitive Data Storage in Daml/Canton

This sample discusses several tradeoffs for storing sensitive data. Sensitive data might include:
- Personally Identifying Information (PII)
- Personal Health Information (PHI) as defined in HIPAA
- Credit card or payment information (PCI) 

# Overview 

Privacy, health and payment regulations recommend the secure storage of sensitive information as part of an 
application. Traditional distributed ledgers or blockchain provide an immutable record of all data and transactions,
and as a result are often not appropriate for use in these applications. 

Daml/Canton provides protection without encryption in the following forms:

- Native enforcement of access in the Daml data model and workflows. 
  - Parties can only see contracts for which they are stakeholders.
- Native privacy through the partial, segmented distribution of data only to stakeholders and their participants. 
  - Canton only replicates copies of contracts to participant nodes of stakeholder parties. Other participants are unaware of the transactions or data, nor receive a copy.
- Ability to prune the ledger to remove archived copies of data ("Right to Forget"). 
  - Canton allows for controlled pruning of the ledger contents to purge archive contracts 

In many cases, the above may be sufficient for your business use case.

The use of encryption to protect sensitive data, is a fairly comon option and we discuss potential options for using 
Daml to manage not just the contract commitments but the secure distribution of encryption keys amongst participants.

However, many companies demand additional protection in the form of data encryption. The goals of encryption include the following:

- Protecting from Database Admin (DBA) access to cleartext copies of the data in the DB
- Protecting DB backups from containing cleartext copies of the data
- Protecting a subset of shared data from parties who should see the non-sensitive data but be restricted from accessing the sensitive data

# In-Depth Topics

- [Canton's Core Capabilities](documentation/canton-capabilities)
- [Use of Encryption](documentation/encryption.md)

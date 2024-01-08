#  IdentityManagement
Identitymanegement is a identity management application built in Daml.

### I. Overview 

A Data Owner can create a IdentityConroller contract to manage a list of SubProcessors. The controller can invite other Parties by exercising InviteIdentity choice. Invite has option to AccessInvite (where they provide their public key) or RejectInvite. The subprocessors can see the public key of the owner in the IdentitiyController record. The owner can also RemoveIdentity choice to remove a party from their list.

### II. Workflow
  1. DataController creates a IdentityController contract
  2. DataController can invite other parties through InviteParty choice
  3. Invited parties can accept invite by providing their public key in a PublicKey record 

### III. Challenge(s)

### IV. Compiling & Testing
To compile and test, run the pre-written script in the `Test.daml` under /daml OR run:
```
$ daml start
```



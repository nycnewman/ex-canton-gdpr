import logging
import asyncio
import random
import string
import json
import argparse
import pprint
import os
import sys
import base64
import traceback
import pprint
import json

import dazl
from dazl.ledgerutil import ACS
from dazl.ledger import ActAs, Admin, ReadAs, User

from dataclasses import dataclass, fields
from dataclasses_json import dataclass_json
from typing import List

from google.cloud import storage

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

@dataclass_json
@dataclass
class RSAKey:
    name: str
    private_key: str
    public_key: str
    public_base64: str
    public_fingerprint: str

@dataclass_json
@dataclass
class RSAKeys:
    keys: List[RSAKey]

@dataclass_json
@dataclass
class EncryptionKey:
    id: str
    key: str

@dataclass
class WrappedEncryptionKey:
    id: str
    wrapped_base64: str

@dataclass_json
@dataclass
class PartyConfig:
    name: str # short name
    party: str # Party ID on ledger
    rsa_key: RSAKey # RSA key for user

@dataclass_json
@dataclass
class Parties:
    owner: str
    identity1: str
    identity2: str
    identity3: str
    identity4: str
    identity5: str

@dataclass
class Config:
    url: str
    party_list: [PartyConfig]

def log_cancellation(f):
    async def wrapper(*args, **kwargs):
        try:
            return await f(*args, **kwargs)
        except asyncio.CancelledError as e:
            print(f"Cancelled {f}")
            print("Error thrown: {}".format(e))
            raise
    return wrapper

def log_message(stack, exception):
    logging.debug(stack)
    logging.debug(exception)
    print("ERROR: {}. {}".format(exception, stack))
    exit(1)

def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode (value) # returns bytes

def trim_zeros(value):
    while len(value) > 0 and value[-1] == 0x0:
        value = value[:-1]
    return(value)

def create_rsa_key(owner: str):

    rsa_keys = RSAKeys( [] )
    keys_filename = 'keys.json'
    if os.path.isfile(keys_filename):
        f = open(keys_filename, 'r')
        keys_json = f.read()
        f.close()
        if keys_json != "":
            rsa_keys = RSAKeys.schema().loads(keys_json)

    found_key = None
    if rsa_keys != []:
        for key in rsa_keys.keys:
            if key.name == owner:
                found_key = key
                break

    if found_key != None:
        rsa_key = RSAKey (
            found_key.name,
            serialization.load_pem_private_key(found_key.private_key.encode('utf-8'), password=None),
            serialization.load_pem_public_key(found_key.public_key.encode('utf-8')),
            found_key.public_base64,
            found_key.public_fingerprint
        )
        return( rsa_key )
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_base64 = (base64.b64encode(public_pem)) #.decode()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_base64)
        digest_bytes = digest.finalize()

        public_fingerprint = digest_bytes.hex()

        rsa_key = RSAKey( owner, private_key, public_key, public_base64, public_fingerprint)
        disk_key = RSAKey( owner, private_pem, public_pem, public_base64, public_fingerprint)

        rsa_keys.keys.append( disk_key  )

        f = open(keys_filename, 'w')
        f.write(RSAKeys.schema().dumps(rsa_keys))
        f.close()

        return rsa_key

def create_dek_key(key_id: str):
    key = os.urandom(32)
    #key_id = ''.join(random.choices(string.digits + string.digits, k = 10))
    return( EncryptionKey(key_id, key) )

def wrap_dek_key(public_key: str, dek_key: str):
    ciphertext = public_key.encrypt(
        dek_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    wrapped_key_base64 = base64.b64encode(ciphertext)
    wrapped_key_base64 = wrapped_key_base64.decode()

    return( wrapped_key_base64 )

def unwrap_dek_key(private_key: str, wrapped_key: str):
    try: 
        ciphertext_key = base64.b64decode(wrapped_key)
        plaintext_key = None
        try:
            plaintext_key = private_key.decrypt(
                ciphertext_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            #print("UDK: Decryption failed - check keys")
            print(e)
            return( None )

        return( plaintext_key )
    except Exception as e:
        log_message(traceback.format_exc(), e)
        return( None )

def encrypt_data_payload(encryption_key: str, original_data: str):
    try: 
        iv = os.urandom(16)
        data_bytes = json.dumps(original_data)
        data_bytes = add_to_16(data_bytes)

        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data_bytes) + encryptor.finalize()

        encrypted_data = base64.b64encode(ciphertext).decode("utf-8")
        iv_base64 = base64.b64encode(iv).decode("utf-8")
        
        return( (iv_base64, encrypted_data) )
    except Exception as e:
        log_message(traceback.format_exc(), e)

def unencrypt_data_payload(plaintext_key, private_data: str, iv: str):
    try: 
        dataValue = base64.b64decode(private_data)
        iv = base64.b64decode(iv)
        cipher = Cipher(algorithms.AES(plaintext_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        original_text = decryptor.update(dataValue) + decryptor.finalize()
        original_text = trim_zeros(original_text)
        cleartext_data = json.loads(original_text)
        return( cleartext_data )
    except Exception as e:
        log_message(traceback.format_exc(), e)

@log_cancellation
async def validate_proposals(config: Config, party : PartyConfig):
    while True:
        try: 
            proposal_contracts = []
            async with dazl.connect(url=config.url, act_as=dazl.Party(party.party), read_as=dazl.Party(party.party)) as conn:
                async with conn.query("IdentityManagement:DataProcessorProposal") as stream:
                    async for event in stream.creates():
                        proposal_contracts.append(event)

                for proposal in proposal_contracts:
                    if proposal.payload['dataProcessor'] != party.party:
                        continue

                    print("Validating subprocessor proposal")
                    print("NOTE: This should have a check that provided key makes sense and is valid")
                    result = await conn.exercise(proposal.contract_id, "AcceptAndRegister", { "processorPublicKey" : { "publicKey" : party.rsa_key.public_base64, "fingerprint" : party.rsa_key.public_fingerprint } } )
                    logging.debug("Proposal Response: {}".format(result))
                    print("Proposal Response: {}".format(result))

                await conn.close()
            await asyncio.sleep(2)
        except Exception as e:
            log_message(traceback.format_exc(), e)

@log_cancellation
async def validate_processor(config: Config, party : PartyConfig):
    while True:
        try: 
            proposal_contracts = []
            async with dazl.connect(url=config.url, act_as=dazl.Party(party.party), read_as=dazl.Party(party.party)) as conn:
                async with conn.query("IdentityManagement:DataProcessorValidation") as stream:
                    async for event in stream.creates():
                        proposal_contracts.append(event)

                for proposal in proposal_contracts:
                    if proposal.payload['dataController'] != party.party:
                        continue
                
                    print("Validating subprocessor identity")
                    print("NOTE: This should have a check that provided key makes sense and is valid")
                    result = await conn.exercise(proposal.contract_id, "Validate" )
                    logging.debug("Validation Response: {}".format(result))
                    print("Validation Response: {}".format(result))

                await conn.close()
            await asyncio.sleep(2)
        except Exception as e:
            log_message(traceback.format_exc(), e)

@log_cancellation
async def dump_contracts(config, party):
    while True:
        async with dazl.connect(url=config.url, read_as=dazl.Party(party.party)) as conn:
            async with conn.stream("*") as stream:
                async for event in stream:
                    try: 
                        #print(event)
                        if isinstance(event, (dazl.ledger.CreateEvent)):
                            print("Dump: Create {} {}".format(event.contract_id, event.payload))
                        elif isinstance(event, dazl.ledger.ArchiveEvent):
                            print("Dump: Archive {}".format(event.contract_id))
                        elif isinstance(event, dazl.ledger.Boundary):
                            print("Dump: Boundary {}".format(event.offset))
                    except Exception as e:
                        log_message(traceback.format_exc(), e)
            await asyncio.sleep(10)

@log_cancellation
async def dump_contracts_offset(config, party, offset_value: str):
    while True:
        async with dazl.connect(url=config.url, read_as=dazl.Party(party.party)) as conn:
            async with conn.stream("*", offset=offset_value) as stream:
                async for event in stream:
                    try: 
                        #print(event)
                        if isinstance(event, (dazl.ledger.CreateEvent)):
                            print("Dump: Create {} {}".format(event.contract_id, event.payload))
                        elif isinstance(event, dazl.ledger.ArchiveEvent):
                            print("Dump: Archive {}".format(event.contract_id))
                        elif isinstance(event, dazl.ledger.Boundary):
                            print("Dump: Boundary {}".format(event.offset))
                    except Exception as e:
                        log_message(traceback.format_exc(), e)
            await asyncio.sleep(10)

@log_cancellation
async def distribute_keys(config: Config, party : PartyConfig):
    while True:
        async with dazl.connect(url=config.url, act_as=dazl.Party(party.party), read_as=dazl.Party(party.party)) as conn:
            try:
                agreement_contracts = {}
                async with conn.query("IdentityManagement:DataProcessorAgreement") as stream:
                    async for event in stream.creates():
                        if event.payload['dataController'] == party.party:
                            agreement_contracts[event.payload['dataProcessor']] = event

                distributed_keys = {}
                async with conn.query("DataSubject:WrappedKey") as stream:
                    async for event in stream.creates():
                        if event.payload['owner'] == party.party:
                            key_id = event.payload["keyId"]['KeyId']
                            agreement_id = event.payload['agreementContractCid']
                            recipient_id = event.payload['recipient']

                            if agreement_id == None:
                                agreement_id = "primary"
                            key_array = distributed_keys.get(key_id, {})
                            key_array[agreement_id] = event
                            distributed_keys[key_id] = key_array

                for key_id in distributed_keys:
                    # check if primary still exists:
                    if distributed_keys[key_id].get('primary', None) == None:
                        # we need to delete shared copies as 
                        for tmpkey in distributed_keys[key_id]:
                            result = await conn.archive(distributed_keys[key_id][tmpkey].contract_id)
                            print(result)
                    else:
                        # Get real DEK
                        key_contract = distributed_keys[key_id]['primary']
                        contract_id = key_contract.contract_id
                        wrapped_key = key_contract.payload['wrappedKey']

                        plaintext_key = unwrap_dek_key(party.rsa_key.private_key, wrapped_key)

                        if plaintext_key == None:
                            print("distribute_keys: Decryption failed - check keys ({})".format(party.party))
                            continue

                        for member in agreement_contracts:
                            agreement_contract = agreement_contracts[member]
                            if distributed_keys[key_id].get(agreement_contract.contract_id, None) == None:
                                identity_public_key = base64.b64decode(agreement_contract.payload['processorPublicKey']['publicKey'])

                                public_key = serialization.load_pem_public_key(
                                    identity_public_key
                                )
        
                                wrapped_key_base64 = wrap_dek_key(public_key, plaintext_key)

                                logging.debug("Distributing a key to: {}".format(member))
                                print("Distributing a Key to : {}".format(member))
                                print("{} {} {} ".format(party.party, member, key_id ))
                                contract = { 'owner' : party.party, 'recipient': member, 'keyId' : {'KeyId' : key_id}, 'wrappedKey' : wrapped_key_base64, "agreementContractCid": agreement_contract.contract_id }
                                result = await conn.create('DataSubject:WrappedKey', contract)
                                print(result)

            except Exception as e:
                log_message(traceback.format_exc(), e)

            await conn.close()
        await asyncio.sleep(2)

@log_cancellation
async def create_data_subject(config: Config, owner: PartyConfig, subject_id: str):
    try:
        async with dazl.connect(url=config.url, read_as=dazl.Party(owner.party)) as conn:
            agreement_contracts = []
            async with conn.query("IdentityManagement:DataProcessorAgreement") as stream:
                async for event in stream.creates():
                    if event.payload['dataController'] == owner.party:
                        agreement_contracts.append(event)

        processors_ids = [x.payload['dataProcessor'] for x in agreement_contracts]

        contract = { 
            'dataController' : owner.party, 
            'subjectId' : { 'SubjectId': subject_id},
            'dataProcessors' : processors_ids
        }
        async with dazl.connect(url=config.url, act_as=owner.party) as conn:
            result = await conn.create('DataSubject:DataSubject', contract)
            print("Data Subject: {}".format(result))

    except Exception as e:
        log_message(traceback.format_exc(), e)

@log_cancellation
async def create_data_subject_data(config: Config, owner: PartyConfig, subject_id: str, key_id: str, location: str, subprocessors: [PartyConfig], public_data1: str, public_data2: str, private_data: str ):
    try:
        encryption_keys = {}
        async with dazl.connect(url=config.url, act_as=dazl.Party(owner.party), read_as=dazl.Party(owner.party)) as conn:
            async with conn.query("DataSubject:WrappedKey") as stream:
                async for event in stream.creates():
                    if event.payload['owner'] == owner.party:
                        key_array = encryption_keys.get(event.payload['keyId']['KeyId'], [])
                        key_array.append(event)
                        encryption_keys[event.payload['keyId']['KeyId']] = key_array

        plaintext_key = None
        for key_contract in encryption_keys.get(key_id, []):
            #print(key_contract.payload)
            contract_id = key_contract.contract_id
            agreement_id = key_contract.payload['agreementContractCid']
            wrapped_key = key_contract.payload['wrappedKey']
            if agreement_id == None:
                plaintext_key = unwrap_dek_key(owner.rsa_key.private_key, wrapped_key)

        if plaintext_key == None:
            print("ERROR: Not able to retrieve encryption key: {}".format(key_id))
            exit(1)

        (iv, encrypted_data) = encrypt_data_payload(plaintext_key, private_data)

        encryption_setting = { 
                    'EncAES256': {
                        'keyId' : {'KeyId': key_id},
                        'iv' : iv
                    } }
        
        private_data = {}
        print(location)
        if location == 'on':
            private_data['OnLedger'] = {}
            private_data['OnLedger']['encryption'] = encryption_setting
            private_data['OnLedger']['dataValue'] = encrypted_data
        elif location == 'off':
            private_data['OffLedger'] = {}
            private_data['OffLedger']['encryption'] = encryption_setting

            file_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k = 63))
            bucket_name = "kms-test-gcs"       # TODO: Hardcoded but should be a configuration parameter
            destination_blob_name = "061a2a61b4f25e04d1c5e02d706444ed2d908fe550bbf7d76bbbbd2e896c3f59/{}".format(file_id)

            storage_client = storage.Client()
            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(destination_blob_name)
            blob.upload_from_string(encrypted_data)

            private_data['OffLedger']['dataLocation'] = ''.join( (bucket_name, ":", destination_blob_name) )

        subprocessors_ids = [x.party for x in subprocessors]

        contract = { 
            'dataController' : owner.party, 
            'subjectId' : { 'SubjectId': subject_id},
            'publicData1' : public_data1,
            'publicData2' : public_data2,
            'privateData' : private_data,
            'dataProcessors' : subprocessors_ids 
        }
        #print(contract)
        async with dazl.connect(url=config.url, act_as=owner.party) as conn:
            result = await conn.create('DataSubject:DataSubjectData', contract)
            print("DataSubjectData: {}".format(result))

    except Exception as e:
        log_message(traceback.format_exc(), e)

@log_cancellation
async def dump_data_subjects(config: Config, party: PartyConfig):
    while True:
        try: 
            async with dazl.connect(url=config.url, read_as=dazl.Party(party.party)) as conn:
                agreement_contracts = {}
                async with conn.query("IdentityManagement:DataProcessorAgreement") as stream:
                    async for event in stream.creates():
                        #if event.payload['dataProcessor'] == party.party:
                        agreement_contracts[event.contract_id] = event

                data_subjects = {}
                async with conn.query("DataSubject:DataSubject") as stream:
                    async for event in stream.creates():
                        data_subjects[event.contract_id] = event.payload

                data_subject_data = {}
                async with conn.query("DataSubject:DataSubjectData") as stream:
                    async for event in stream.creates():
                        data_array = data_subject_data.get(event.payload['subjectId']['SubjectId'], [])
                        data_array.append(event.payload)
                        data_subject_data[event.payload['subjectId']['SubjectId']] = data_array

                encryption_keys = {}
                async with conn.query("DataSubject:WrappedKey") as stream:
                    async for event in stream.creates():
                        key_array = encryption_keys.get(event.payload['keyId']['KeyId'], {})
                        agreement_id = event.payload['agreementContractCid']
                        if agreement_id == None:
                            agreement_id = 'primary'
                        key_array[agreement_id] = event
                        encryption_keys[event.payload['keyId']['KeyId']] = key_array
                
                for contract in data_subjects:
                    subject_id = data_subjects[contract]['subjectId']['SubjectId']
                    print("==========")
                    print("Data Subject: {}".format(subject_id))

                    if data_subject_data.get(subject_id, None) == None:
                        # no data contracts
                        continue
                    
                    for data_contract in data_subject_data[subject_id]:
                        privateData = None

                        enc_key_id = None
                        enc_iv = None
                        data_value = None
                        if data_contract['privateData'].get('OnLedger', None) != None:
                            enc_key_id = str(data_contract['privateData']['OnLedger']['encryption']['EncAES256']['keyId']['KeyId'])
                            enc_iv = data_contract['privateData']['OnLedger']['encryption']['EncAES256']['iv']

                            data_value = data_contract['privateData']['OnLedger']['dataValue']
                            
                        elif data_contract['privateData'].get('OffLedger', None) != None:
                            enc_key_id = str(data_contract['privateData']['OffLedger']['encryption']['EncAES256']['keyId']['KeyId'])
                            enc_iv = data_contract['privateData']['OffLedger']['encryption']['EncAES256']['iv']

                            data_location = data_contract['privateData']['OffLedger']['dataLocation']
                            (bucket_name, destination_blob_name) = data_location.split(':')
                            storage_client = storage.Client()
                            bucket = storage_client.bucket(bucket_name)
                            blob = bucket.blob(destination_blob_name)
                            data_value = blob.download_as_string()

                        else:
                            print("Data Subject Data: {} | {} | {} | {} | {}".format(party.party, data_contract['subjectId']['SubjectId'], data_contract['publicData1'], 
                                data_contract['publicData2'], '<None>'))

                        if encryption_keys.get(enc_key_id, None) == None:
                            print("DDS: No key available to decrypt contract (1) ({})".format(party.party))
                            print("Data Subject Data: {} | {} | {} | {} | {}".format(party.party, data_contract['subjectId']['SubjectId'], 
                                data_subject_data[data_contract]['publicData1'], data_contract['publicData2'], "<ERROR> Decrypting data"))
                            continue

                        for agreement in encryption_keys[enc_key_id]:
                            if data_contract['dataController'] == party.party:
                                # party is data controller so has no agreement
                                key_contract = encryption_keys[enc_key_id]['primary']
                                wrapped_key = key_contract.payload['wrappedKey']
                            else:
                                # party is a subprocessor so need to match to agreement
                                key_contract = encryption_keys[enc_key_id][agreement]
                                wrapped_key = key_contract.payload['wrappedKey']
                        
                        plaintext_key = unwrap_dek_key(party.rsa_key.private_key, wrapped_key)

                        if plaintext_key == None:
                            print("DDS: Decryption of key not possible (2) ({})".format(party.party))
                            privateData = None
                            print("Data Subject Data: {} | {} | {} | {} | {}".format(party.party, data_contract['subjectId']['SubjectId'], 
                                data_contract['publicData1'], data_contract['publicData2'], privateData))
                            continue
                        else:
                            privateData = unencrypt_data_payload(plaintext_key, data_value, enc_iv)

                            print("Data Subject Data: {} | {} | {} | {} | {}".format(party.party, data_contract['subjectId']['SubjectId'], 
                                data_contract['publicData1'], data_contract['publicData2'], privateData))

                await conn.close()
            await asyncio.sleep(5)
        except Exception as e:
            log_message(traceback.format_exc(), e)
            print("DDS: Exiting: {}".format(party.party))

async def run_automation(config : Config, identity: PartyConfig):

    task1 = asyncio.create_task(validate_proposals(config, identity))
    task2 = asyncio.create_task(validate_processor(config, identity))
    task3 = asyncio.create_task(dump_data_subjects(config, identity))
    task4 = asyncio.create_task(distribute_keys(config, identity))
    #task4 = asyncio.create_task(dump_contracts(config, identity))
    
    await asyncio.gather(task1, task2, task3, task4)

async def create_master(config : Config, identity: PartyConfig):
    try:
        async with dazl.connect(url=config.url, act_as=dazl.Party(identity.party), read_as=dazl.Party(identity.party)) as conn:
            found = False
            master_contract = None
            async with conn.query("IdentityManagement:DataControllerMaster") as stream:
                async for event in stream.creates():
                    logging.debug(event.contract_id)
                    logging.debug(event.payload)
                    if (event.payload["dataController"] == identity.party):
                        found = True
                        master_contract = event
                    
            if (found == False):
                logging.debug("Registering Data Controller Master")
                print("Creating master contract: ")
                contract = { 'dataController' : identity.party }
                result = await conn.create('IdentityManagement:DataControllerMaster', contract)
                logging.debug("Create result: {}".format(result))
                group_contract = result
            logging.debug("Master Contract: {}".format(master_contract))

            await conn.close()

    except Exception as e:
        log_message(traceback.format_exc(), e)

@log_cancellation
async def invite_processor(config : Config, identity: PartyConfig, invitees: [PartyConfig]):
    try:
        async with dazl.connect(url=config.url, act_as=dazl.Party(identity.party), read_as=dazl.Party(identity.party)) as conn:
            found = False
            master_contract = None
            async with conn.query("IdentityManagement:DataControllerMaster") as stream:
                async for event in stream.creates():
                    logging.debug(event.contract_id)
                    logging.debug(event.payload)
                    if (event.payload["dataController"] == identity.party):
                        found = True
                        master_contract = event
                    
            if (found == False):
                print("No master contract found for party")
                return

            for invitee in invitees:
                target = string_to_party(invitee, config.party_list)
                if target == None:
                    print("ERROR: Bad invitee")
                    exit(1)
                
                print("Inviting processor party: {}".format(target.name))
                params = { "dataProcessor": target.party, "controllerPublicKey" : { "publicKey" : target.rsa_key.public_base64, "fingerprint" : target.rsa_key.public_fingerprint }}
                result = await conn.exercise( master_contract.contract_id, "InviteDataProcessor", params )
                logging.debug("Invite Response: {}".format(result))
                print("Invite Response: {}".format(result))

            await conn.close()

    except Exception as e:
        log_message(traceback.format_exc(), e)

async def register_dek_key(config : Config, identity: PartyConfig, key_id: str):
    encryption_key = create_dek_key(key_id)
    wrapped_key = WrappedEncryptionKey(encryption_key.id, wrap_dek_key(identity.rsa_key.public_key, encryption_key.key))
    try:    
        async with dazl.connect(url=config.url, act_as=dazl.Party(identity.party), read_as=dazl.Party(identity.party)) as conn:
            print("Registering encryption key")
            contract = { 'owner' : identity.party, 'recipient' : identity.party, 'keyId' : {'KeyId': key_id}, 
             'wrappedKey' : wrapped_key.wrapped_base64, "agreementContractCid" : None }
            try:
                result = await conn.create('DataSubject:WrappedKey', contract)
                print(result)
            except Exception as e:
                log_message(traceback.format_exc(), e)
            await conn.close()
    except Exception as e:
        log_message(traceback.format_exc(), e)

# Dummy function to test and evaluate various DAZL features
async def run_test(config : Config, party: PartyConfig):
        try: 
            async with dazl.connect(url=config.url, read_as=dazl.Party(party.party)) as conn:
                offset = await conn.get_ledger_end()
                print( offset ) 
                async with ACS(conn, ["IdentityManagement:DataSubject", "IdentityManagement:WrappedKey"]) as acs:
                    acs = await acs.read()

                print(acs.offset)
                print(len(acs.contracts))
                for contract in acs.matching_contracts("IdentityManagement:WrappedKey"):
                    print(contract.value)
                    print(contract.value_type)
                    print(acs.contracts[contract])
                    print("")
                    
                #print(acs.earliest_contract("*"))

                await conn.close()
        except Exception as e:
            log_message(traceback.format_exc(), e)
            print("DDS: Exiting: {}".format(party.party))

def string_to_party(party_name: str, parties: [PartyConfig]):
    found = None
    for party in parties:
        if party_name == party.name:
            found = party
    return( found )

async def test_party(config: Config):
    async with dazl.connect(url=config.url, admin=True) as conn:
        users = await conn.list_users()
    
        for user in users:
            print("{} {}".format( user.id, user.primary_party ))

        parties = await conn.list_known_parties()

        for party in parties:
            print("{} {} {}".format( party.party, party.display_name, party.is_local ))

        party_info = await conn.allocate_party()
        print(party.party)
        await conn.create_user(
            User("testuser2", party_info.party),
            [ActAs(party_info.party), ReadAs(party_info.party), Admin],
        )

def main(argv):

    #config = Config("http://localhost:6865", [])
    #asyncio.run( test_party(config ) )
    #exit(1)

    # Load parties from parties.json (output of a Daml Script)
    parties = None
    party_names = []
    parties_filename = 'parties.json'
    if os.path.isfile(parties_filename):
        f = open(parties_filename, 'r')
        parties_json = f.read()
        f.close()
        parties = Parties.schema().loads(parties_json)

        party_names = [x.name for x in fields(parties)]
    else:
        print("ERROR: Please run Daml Script to extract party IDs first")
        exit(1)

    # Generate or load keys for each party
    owner = PartyConfig("owner", parties.owner, create_rsa_key("owner"))
    identity1 = PartyConfig("identity1", parties.identity1, create_rsa_key("identity1"))
    identity2 = PartyConfig("identity2", parties.identity2, create_rsa_key("identity2"))
    identity3 = PartyConfig("identity3", parties.identity3, create_rsa_key("identity3"))
    identity4 = PartyConfig("identity4", parties.identity4, create_rsa_key("identity4"))
    identity5 = PartyConfig("identity5", parties.identity5, create_rsa_key("identity5"))
    party_list = [owner, identity1, identity2, identity3, identity4, identity5]

    # default value for offset
    offset='000000000000000000'

    parser = argparse.ArgumentParser(description='ex-canton-gdpr')
    parser.add_argument('--url', default="http://localhost:6865", help='URL of ledger (defaults to http://localhost:6865')
    parser.add_argument('-p', '--party', choices=party_names, help='Select which party is being running these commands')
    subparser = parser.add_subparsers(dest='command')
    daemon = subparser.add_parser('daemon', help='run automation for identity')
    master = subparser.add_parser('master',help='Create master contract')
    invite = subparser.add_parser('invite', help='Invite a party to a group')
    invite.add_argument('--target', action="append", choices=party_names, help='Invite a party to a group', required=True)
    encryption = subparser.add_parser('create_encryption', help='Create a new DEK encryption key with id')
    encryption.add_argument('key_id', nargs=1,  type=str, help='id for key')
    subject = subparser.add_parser('create_subject', help='Create a new data subject record')
    subject.add_argument('subject_id', nargs=1,  type=int, help='id for subject')
    subjectdata = subparser.add_parser('create_subject_data', help='Create a new data subject record')
    subjectdata.add_argument('--target', action="append", choices=party_names, help='Part(ies) to share a subject record', required=True)
    subjectdata.add_argument('--location', choices=["on", "off"], help='On or off ledger storage', required=True)
    subjectdata.add_argument('subject_id', nargs=1,  type=int, help='id for subject')
    subjectdata.add_argument('key_id', nargs=1,  type=int, help='id for key')
    subjectdata.add_argument('public_data1', nargs=1,  type=str, help='public_data1')
    subjectdata.add_argument('public_data2', nargs=1,  type=str, help='public_data2')
    subjectdata.add_argument('private_data', nargs=1,  type=str, help='private data (e.g. json)')
    dump_contracts = subparser.add_parser('dump', help='Dump contracts visible to a party')
    dump_contracts.add_argument('--offset', nargs=1,  type=str, help='ledger offset', required=False)
    test = subparser.add_parser('test', help='test command')
    args = parser.parse_args()

    logging.basicConfig(filename=args.party + ".log", level=logging.DEBUG)

    run_as_party = string_to_party(args.party, party_list)
    if run_as_party == None:
        print("ERROR: No party specific")
        exit(1)

    config = Config("http://localhost:6865", party_list)

    print("ex-canton-gdpr: Encryption on Daml/Canton ledger")
    print("URL: {}".format(args.url))
    print("ActAs: {} {}".format(args.party, run_as_party.party))

    if args.command == "daemon":
        print("Daemon mode".format(args.party))
        asyncio.run( run_automation(config, run_as_party ) )
    elif args.command == "master":
        asyncio.run( create_master(config, run_as_party) )
    elif args.command == "invite":
        asyncio.run( invite_processor(config, run_as_party, args.target ) )
    elif args.command == "create_encryption":
        print("Create encryption key: {}".format(args.key_id[0]))
        asyncio.run( register_dek_key(config, run_as_party, args.key_id[0] ) )
    elif args.command == "create_subject":
        print("Create data subject record: {}".format(args.subject_id[0]))
        asyncio.run( create_data_subject(config, run_as_party, args.subject_id[0] ) )
    elif args.command == "create_subject_data":
        print("Create data subject record: {} {} {} {} {} {} {}".format(args.subject_id[0], args.key_id[0], args.location, args.target, args.public_data1[0], args.public_data2[0], args.private_data[0]))
        invitees = [string_to_party(x, party_list) for x in args.target]
        asyncio.run( create_data_subject_data(config, run_as_party,  str(args.subject_id[0]), str(args.key_id[0]), args.location, invitees, args.public_data1[0], args.public_data2[0], args.private_data[0] ) )
    elif args.command == "dump":
        if args.offset != []:
           offset = args.offset[0]
        print("Dumping all contracts in ledger from offset: {}".format(offset))
        asyncio.run( dump_contracts_offset(config, run_as_party, offset))
    elif args.command == "test":
        print("test:")
        asyncio.run( run_test(config, run_as_party))

    exit(0)

if __name__ == '__main__':
  main(sys.argv[1:])


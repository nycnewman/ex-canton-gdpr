import logging
import asyncio
import random
import string
import json
import argparse

import dazl
from dazl.ledgerutil import ACS

import pprint
import os
import sys
import base64
from dataclasses import dataclass, fields
from dataclasses_json import dataclass_json
from typing import List

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

@dataclass
class Config:
    url: str

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

@dataclass
class GroupConfig:
    id: str

@dataclass_json
@dataclass
class Parties:
    owner: str
    identity1: str
    identity2: str
    identity3: str
    identity4: str
    identity5: str

def log_cancellation(f):
    async def wrapper(*args, **kwargs):
        try:
            return await f(*args, **kwargs)
        except asyncio.CancelledError as e:
            print(f"Cancelled {f}")
            print("Error thrown: {}".format(e))
            raise
    return wrapper

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

        public_base64 = (base64.b64encode(public_pem)).decode()

        public_fingerprint = "1234567890"

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
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            logging.debug(e)
            print(e)
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
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        logging.debug(e)
        print(e)

def unencrypt_data_payload(plaintext_key, private_data):
    try: 
        dataValue = base64.b64decode(private_data['OnLedger']['dataValue'])
        iv = base64.b64decode(private_data['OnLedger']['encryption']['EncAES256']['iv'])
        cipher = Cipher(algorithms.AES(plaintext_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        original_text = decryptor.update(dataValue) + decryptor.finalize()
        original_text = trim_zeros(original_text)
        cleartext_data = json.loads(original_text)
        return( cleartext_data )
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        logging.debug(e)
        print(e)

@log_cancellation
async def setup_group(config: Config, owner: PartyConfig, group : GroupConfig):

    try:
        async with dazl.connect(url=config.url, act_as=dazl.Party(owner.party), read_as=dazl.Party(owner.party)) as conn:
            found = False
            group_contract = None
            async with conn.query("IdentityManagement:IdentityGroup") as stream:
                async for event in stream.creates():
                    logging.debug(event.contract_id)
                    logging.debug(event.payload)
                    if (event.payload["owner"] == owner.party) and (event.payload["id"] == group.id):
                        found = True
                        group_contract = event
                    
            if (found == False):
                logging.debug("Registering Identity Group")
                print("Creating Group: {}".format(group.id))
                contract = { 'owner' : owner.party, 'id' : group.id, 'members' : "" }
                result = await conn.create('IdentityManagement:IdentityGroup', contract)
                logging.debug("Create result: {}".format(result))
                group_contract = result
            logging.debug("Group Contract: {}".format(group_contract))

            await conn.close()

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        logging.debug(e)
        print(e)

@log_cancellation
async def validate_registration(config: Config, party : PartyConfig):
    while True:
        try: 
            group_contracts = {}
            registrations = []
            async with dazl.connect(url=config.url, act_as=dazl.Party(party.party), read_as=dazl.Party(party.party)) as conn:
                async with conn.query("IdentityManagement:IdentityGroup") as stream:
                    async for event in stream.creates():
                        group_contracts[event.payload['id']] = event

                async with conn.query("IdentityManagement:RegisteredIdentity") as stream:
                    async for event in stream.creates():
                        registrations.append(event.payload['groupId'])


                for groupId in group_contracts:
                    #if party.party == group_contracts[groupId].payload["owner"]:
                    #    # Ignore owner of group
                    #    continue

                    if groupId not in registrations:
                        # register a RegisteredIdentity record
                        logging.debug("Registering Public Key")
                        print("Registering Public Key: {}".format(party.party))
                        contract = { "member": party.party, "publicKey" : { "publicKey" : party.rsa_key.public_base64, "fingerprint" : party.rsa_key.public_fingerprint} } 
                        try:
                            print("Group Details: {}".format(group_contracts[groupId]))
                            result = await conn.exercise(group_contracts[groupId].contract_id, "RegisterPublicKey", contract )
                            print(result)
                        except Exception as e:
                            logging.debug(e)
                            print("ERROR: Validate exception: {} {}".format(party.party, e))
                await conn.close()
            await asyncio.sleep(2)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            logging.debug(e)
            print(e)

@log_cancellation
async def invite_party(config, owner:PartyConfig, group: GroupConfig, invitee:PartyConfig):

    try:
        async with dazl.connect(url=config.url, act_as=dazl.Party(owner.party), read_as=dazl.Party(owner.party)) as conn:
            print("Inviting party: {}".format(invitee.party))
            result = await conn.exercise_by_key("IdentityManagement:IdentityGroup", "InviteNewMember", {"_1": owner.party, "_2": group.id}, { "invitee": invitee.party } )
            logging.debug("Invite Response: {}".format(result))
            print("Invite Response: {}".format(result))

            await conn.close()

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        logging.debug(e)
        print(e)

@log_cancellation
async def dump_contracts(config, party):
    while True:
        contracts = {}
        async with dazl.connect(url=config.url, read_as=dazl.Party(party.party)) as conn:
            async with conn.query("*") as stream:

                @stream.on_create
                def _(event):
                    contracts[event.contract_id] = event.payload

                await stream.run()
            await conn.close()
        pprint.pprint(contracts)

@log_cancellation
async def register_key(config:Config, owner: PartyConfig, group: GroupConfig, key: WrappedEncryptionKey):

    try:    
        async with dazl.connect(url=config.url, act_as=dazl.Party(owner.party), read_as=dazl.Party(owner.party)) as conn:
            print("Registering encryption key")
            contract = { 'owner' : owner.party, 'groupId': group.id, 'id' : key.id, 'wrappedKey' : key.wrapped_base64 }
            try:
                result = await conn.create('IdentityManagement:EncryptionKey', contract)
                print(result)
            except Exception as e:
                logging.debug(e)
                print(e)
            await conn.close()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        logging.debug(e)
        print(e)

@log_cancellation
async def distribute_keys(config: Config, party : PartyConfig):
    while True:
        async with dazl.connect(url=config.url, act_as=dazl.Party(party.party), read_as=dazl.Party(party.party)) as conn:
            try:
                group_contracts = {}
                async with conn.query("IdentityManagement:IdentityGroup") as stream:
                    async for event in stream.creates():
                        #group_array = group_contracts.get(event.payload['id'], [])
                        #group_array.append(event)
                        group_contracts[event.payload['id']] = event

                encryption_keys = {}
                async with conn.query("IdentityManagement:EncryptionKey") as stream:
                    async for event in stream.creates():
                        key_array = encryption_keys.get(event.payload['groupId'], [])
                        key_array.append(event)
                        encryption_keys[event.payload['groupId']] = key_array

                identities = {}
                async with conn.query("IdentityManagement:RegisteredIdentity") as stream:
                    async for event in stream.creates():
                        group_identities = identities.get(event.payload['groupId'], {})
                        group_identities[event.payload["identity"]] = event
                        identities[event.payload['groupId']] = group_identities

                distributed_keys = {}
                async with conn.query("IdentityManagement:SharedKey") as stream:
                    async for event in stream.creates():
                        shared_key_id = event.payload["id"]
                        group_id = event.payload['groupId']
                        recipient = event.payload["recipient"]

                        key_array = distributed_keys.get(group_id, {})
                        key_array[shared_key_id] = key_array.get(shared_key_id, [])
                        key_array[shared_key_id].append(event)
                        distributed_keys[group_id] = key_array

                for groupId in group_contracts:
                    expected_members = group_contracts[groupId].payload["members"]

                    # Get real DEK
                    for key_contract in encryption_keys.get(groupId, []):
                        contract_id = key_contract.contract_id
                        key_id = key_contract.payload['id']
                        wrapped_key = key_contract.payload['wrappedKey']

                        plaintext_key = unwrap_dek_key(party.rsa_key.private_key, wrapped_key)

                        if plaintext_key == None:
                            print("distribute_keys: Decryption failed - check keys ({})".format(party.party))
                            continue

                        current_shared = []
                        if distributed_keys.get(groupId, []) != []:
                            # No keys distributed so far
                            if distributed_keys[groupId].get(key_id, []) != []:
                                for key in distributed_keys[groupId][key_id]:
                                    current_shared.append(key.payload["recipient"])

                        missing_members = [x for x in expected_members if x not in current_shared]

                        for member in missing_members:
                            # check that member has registered a public key
                            group_identities = identities.get(groupId)
                            registered_identity = None
                            identity_public_key = None

                            if group_identities != None:
                                registered_identity = identities[groupId].get(member, None)
                            else:
                                continue

                            if registered_identity != None:
                                tmp_public_key = registered_identity.payload["publicKey"]
                                tmp_public_key = tmp_public_key["publicKey"]
                                identity_public_key = base64.b64decode(tmp_public_key)
                            else:
                                continue

                            public_key = serialization.load_pem_public_key(
                                identity_public_key
                            )
    
                            wrapped_key_base64 = wrap_dek_key(public_key, plaintext_key)

                            logging.debug("Distributing a key to: {}".format(member))
                            print("Distributing a Key to : {}".format(member))
                            print("{} {} {} {}".format(party.party, member, groupId, key_id ))
                            contract = { 'owner' : party.party, 'recipient': member, 'groupId': groupId, 'id' : key_id, 'wrappedKey' : wrapped_key_base64 }
                            result = await conn.create('IdentityManagement:SharedKey', contract)
                            print(result)

            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                logging.debug(e)
                print(e)

            await conn.close()
        await asyncio.sleep(2)

@log_cancellation
async def create_data_subject(config: Config, owner: PartyConfig, group: GroupConfig, key_id: str, subprocessors: [PartyConfig], public_data1: str, public_data2: str, private_data: str ):
    try:
        encryption_keys = {}
        async with dazl.connect(url=config.url, act_as=dazl.Party(owner.party), read_as=dazl.Party(owner.party)) as conn:
            async with conn.query("IdentityManagement:EncryptionKey") as stream:
                async for event in stream.creates():
                    key_array = encryption_keys.get(event.payload['groupId'], [])
                    key_array.append(event)
                    encryption_keys[event.payload['groupId']] = key_array

        plaintext_key = None
        for key_contract in encryption_keys.get(group.id, []):
            print(key_contract.payload)
            contract_id = key_contract.contract_id
            found_key_id = key_contract.payload['id']
            wrapped_key = key_contract.payload['wrappedKey']
            if found_key_id == key_id:
                plaintext_key = unwrap_dek_key(owner.rsa_key.private_key, wrapped_key)

        if plaintext_key == None:
            print("ERROR: Not able to retrieve encryption key")
            exit(1)

        data_subject_id = ''.join(random.choices(string.digits + string.digits, k = 10))

        (iv, encrypted_data) = encrypt_data_payload(plaintext_key, private_data)

        private_data = {
            "OnLedger" : {
                'encryption' : {
                    'EncAES256': {
                        'keyId' : key_id,
                        'groupId' : group.id,
                        'iv' : iv
                    }
                },
                'dataValue' : encrypted_data
            }
        }

        subprocessors_ids = [x.party for x in subprocessors]

        contract = { 
            'owner' : owner.party, 
            'id' : data_subject_id, 
            'publicData1' : public_data1,
            'publicData2' : public_data2,
            'privateData' : private_data,
            'subprocessors' : subprocessors_ids 
        }

        async with dazl.connect(url=config.url, act_as=owner.party) as conn:
            result = await conn.create('IdentityManagement:DataSubject', contract)
            print("Data Subject: {}".format(result))

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        logging.debug(e)
        print(e)

@log_cancellation
async def dump_data_subjects(config: Config, party: PartyConfig):
    while True:
        try: 
            async with dazl.connect(url=config.url, read_as=dazl.Party(party.party)) as conn:
                contracts = {}
                async with conn.query("IdentityManagement:DataSubject") as stream:
                    async for event in stream.creates():
                        contracts[event.contract_id] = event.payload

                distributed_keys = {}
                async with conn.query("IdentityManagement:SharedKey") as stream:
                    async for event in stream.creates():
                        key_array = distributed_keys.get(str(event.payload['groupId']), {})
                        key_array[str(event.payload["id"])] = event
                        distributed_keys[event.payload['groupId']] = key_array
                
                for contract in contracts:
                    privateData = None
                    if contracts[contract]['privateData'].get('OnLedger', None) != None:
                        group_id = str(contracts[contract]['privateData']['OnLedger']['encryption']['EncAES256']['groupId'])
                        enc_key_id = str(contracts[contract]['privateData']['OnLedger']['encryption']['EncAES256']['keyId'])
                        

                        if distributed_keys.get(group_id, None) == None:
                            print("DDS: No key available to decrypt contract (1) ({})".format(party.party))
                            print("Data Subject: {} | {} | {} | {} | {}".format(party.party, contracts[contract]['id'], contracts[contract]['publicData1'], contracts[contract]['publicData2'], privateData))
                            continue

                        if distributed_keys[group_id].get(enc_key_id, None) != None:
                            key_contract = distributed_keys[group_id][enc_key_id]
                            wrapped_key = key_contract.payload['wrappedKey']
                            
                            plaintext_key = unwrap_dek_key(party.rsa_key.private_key, wrapped_key)

                            if plaintext_key == None:
                                print("DDS: Decryption of key not possible (2) ({})".format(party.party))
                                privateData = None
                                print("Data Subject: {} | {} | {} | {} | {}".format(party.party, contracts[contract]['id'], contracts[contract]['publicData1'], contracts[contract]['publicData2'], privateData))
                                continue
                            else:
                                privateData = unencrypt_data_payload(plaintext_key, contracts[contract]['privateData'])
                                #print(privateData)
                                print("Data Subject: {} | {} | {} | {} | {}".format(party.party, contracts[contract]['id'], contracts[contract]['publicData1'], contracts[contract]['publicData2'], privateData))
                        else:
                            print("DDS: No key available to decrypt contract (3) ({})".format(party.party))
                            print("Data Subject: {} | {} | {} | {} | {}".format(party.party, contracts[contract]['id'], contracts[contract]['publicData1'], contracts[contract]['publicData2'], privateData))

                await conn.close()
            await asyncio.sleep(5)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            logging.debug(e)
            print(e)
            print("DDS: Exiting: {}".format(party.party))

async def run_automation(config : Config, identity: PartyConfig):

    task1 = asyncio.create_task(validate_registration(config, identity))
    task2 = asyncio.create_task(dump_data_subjects(config, identity))
    task3 = asyncio.create_task(distribute_keys(config, identity))

    await asyncio.gather(task1, task2, task3)

async def run_group(config : Config, identity: PartyConfig, group: GroupConfig):
    await setup_group(config, identity, group)

async def run_invite(config : Config, identity: PartyConfig, group: GroupConfig, invitee: PartyConfig):
    await invite_party(config, identity, group, invitee)


async def run_dek_key(config : Config, identity: PartyConfig, group: GroupConfig, key_id: str):
    encryption_key = create_dek_key(key_id)
    wrapped_key = WrappedEncryptionKey(encryption_key.id, wrap_dek_key(identity.rsa_key.public_key, encryption_key.key))
    await register_key(config, identity, group, wrapped_key)

async def run_data_subject(config : Config, identity: PartyConfig, group: GroupConfig, encryption_key_id: str, invitees: [PartyConfig], public_data1: str, public_data2: str, private_data: str):
    await create_data_subject(config, identity, group, encryption_key_id, invitees, public_data1, public_data2, private_data)

def string_to_party(party_name: str, parties: [PartyConfig]):
    found = None
    for party in parties:
        if party_name == party.name:
            found = party
    return( found )

def main(argv):

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

    parser = argparse.ArgumentParser(description='ex-canton-gdpr')
    parser.add_argument('--url', default="http://localhost:6865", help='URL of ledger (defaults to http://localhost:6865')
    parser.add_argument('-p', '--party', choices=party_names, help='Select which party is being running these commands')
    subparser = parser.add_subparsers(dest='command')
    daemon = subparser.add_parser('daemon', help='run automation for identity')
    invite = subparser.add_parser('invite', help='Invite a party to a group')
    invite.add_argument('--group_id', type=int, help='Provided group id', required=True)
    invite.add_argument('--target', action="append", choices=party_names, help='Invite a party to a group', required=True)
    group = subparser.add_parser('group',help='Create group with provided id')
    group.add_argument('group_id', nargs=1,  type=int, help='Create group with provided id')
    encryption = subparser.add_parser('create_encryption', help='Create a new DEK encryption key with id')
    encryption.add_argument('group_id', nargs=1,  type=int, help='id for group')
    encryption.add_argument('id', nargs=1,  type=int, help='id for key')
    subject = subparser.add_parser('create_subject', help='Create a new data subject record')
    subject.add_argument('--target', action="append", choices=party_names, help='Part(ies) to share a subject record', required=True)
    subject.add_argument('group_id', nargs=1,  type=int, help='id for group')
    subject.add_argument('key_id', nargs=1,  type=int, help='id for key')
    subject.add_argument('public_data1', nargs=1,  type=str, help='public_data1')
    subject.add_argument('public_data2', nargs=1,  type=str, help='public_data2')
    subject.add_argument('private_data', nargs=1,  type=str, help='private data (e.g. json)')
    args = parser.parse_args()

    logging.basicConfig(filename=args.party + ".log", level=logging.DEBUG)

    run_as_party = string_to_party(args.party, party_list)
    if run_as_party == None:
        print("ERROR: No party specific")
        exit(1)

    config = Config("http://localhost:6865")

    print("ex-canton-gdpr: Encryption on Daml/Canton ledger")
    print("URL: {}".format(args.url))
    print("ActAs: {} {}".format(args.party, run_as_party.party))

    if args.command == "daemon":
        print("Daemon mode".format(args.party))
        asyncio.run( run_automation(config, run_as_party ) )
    elif args.command == "group":
        print("Creating group: {}".format(str(args.group_id[0])))
        group = GroupConfig( str( args.group_id[0] ) )
        asyncio.run( run_group(config, run_as_party, group ) )
    elif args.command == "invite":
        print("Invite parties: {} {}".format(args.group_id, args.target))
        group = GroupConfig(str(args.group_id))
        for invitee in args.target:
            target = string_to_party(invitee, party_list)
            if target == None:
                print("ERROR: Bad invitee")
                exit(1)
            asyncio.run( run_invite(config, run_as_party, group, target ) )
    elif args.command == "create_encryption":
        print("Create encryption key: {} {}".format(args.group_id[0], args.id[0]))
        group = GroupConfig(str(args.group_id[0]))
        asyncio.run( run_dek_key(config, run_as_party, group, args.id[0] ) )
    elif args.command == "create_subject":
        print("Create data subject record: {} {} {} {} {} {}".format(args.group_id[0], args.key_id[0], args.target, args.public_data1, args.public_data2, args.private_data))
        invitees = [string_to_party(x, party_list) for x in args.target]
        group = GroupConfig(str(args.group_id[0]))
        asyncio.run( run_data_subject(config, run_as_party, group, str(args.key_id[0]), invitees, args.public_data1, args.public_data2, args.private_data ) )

    exit(0)

if __name__ == '__main__':
  main(sys.argv[1:])


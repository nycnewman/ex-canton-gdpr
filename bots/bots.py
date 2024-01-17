import logging
import asyncio
import random
import string
import json

import dazl
from dazl.ledgerutil import ACS

import pprint
import os
import sys
import base64
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(filename="app.log", level=logging.DEBUG)

@dataclass
class Config:
    url: str

@dataclass
class RSAKey:
    private_key: str
    public_key: str
    public_base64: str
    public_fingerprint: str

@dataclass
class EncryptionKey:
    id: str
    key: str

@dataclass
class WrappedEncryptionKey:
    id: str
    wrapped_base64: str

@dataclass
class PartyConfig:
    party: str
    rsa_key: RSAKey

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

def create_rsa_key():
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

    rsa_key = RSAKey( private_key, public_key, public_base64, public_fingerprint)

    return rsa_key

def create_dek_key():
    key = os.urandom(32)
    key_id = ''.join(random.choices(string.digits + string.digits, k = 10))
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
            print("UDK: Decryption failed - check keys")
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
                    if party.party == group_contracts[groupId].payload["owner"]:
                        # Ignore owner of group
                        continue

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
                        #print(event.payload)
                        shared_key_id = event.payload["id"]
                        group_id = event.payload['groupId']
                        recipient = event.payload["recipient"]

                        key_array = distributed_keys.get(group_id, {})
                        #print(key_array)
                        key_array[shared_key_id] = key_array.get(shared_key_id, [])
                        key_array[shared_key_id].append(event)
                        #print(key_array)
                        distributed_keys[group_id] = key_array
                        #print("Distributed Keys: {}".format(distributed_keys))

                for groupId in group_contracts:
                    expected_members = group_contracts[groupId].payload["members"]

                    # Get real DEK
                    for key_contract in encryption_keys.get(groupId, []):
                        contract_id = key_contract.contract_id
                        key_id = key_contract.payload['id']
                        wrapped_key = key_contract.payload['wrappedKey']

                        plaintext_key = unwrap_dek_key(party.rsa_key.private_key, wrapped_key)

                        if plaintext_key == None:
                            print("distribute_keys: Decryption failed - check keys")
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
async def create_data_subject(config: Config, owner: PartyConfig, group: GroupConfig, encryption_key: EncryptionKey, subprocessors: [PartyConfig], original_data: str ):
    try:
        data_subject_id = ''.join(random.choices(string.digits + string.digits, k = 10))

        (iv, encrypted_data) = encrypt_data_payload(encryption_key.key, original_data)

        private_data = {
            "OnLedger" : {
                'encryption' : {
                    'EncAES256': {
                        'keyId' : encryption_key.id,
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
            'publicData1' : "open text 1",
            'publicData2' : "open text 2",
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
                        key_array = distributed_keys.get(event.payload['groupId'], {})
                        key_array[event.payload["id"]] = event
                        distributed_keys[event.payload['groupId']] = key_array
                
                for contract in contracts:
                    if contracts[contract]['privateData'].get('OnLedger', None) != None:
                        group_id = contracts[contract]['privateData']['OnLedger']['encryption']['EncAES256']['groupId']
                        enc_key_id = contracts[contract]['privateData']['OnLedger']['encryption']['EncAES256']['keyId']
                        privateData = None

                        if distributed_keys.get(group_id, None) == None:
                            print("DDS: No key available to decrypt contract (1)")
                            print("Data Subject: {} | {} | {} | {} | {}".format(party.party, contracts[contract]['id'], contracts[contract]['publicData1'], contracts[contract]['publicData2'], privateData))
                            continue

                        if distributed_keys[group_id].get(enc_key_id, None) != None:
                            key_contract = distributed_keys[group_id][enc_key_id]
                            wrapped_key = key_contract.payload['wrappedKey']
                            
                            plaintext_key = unwrap_dek_key(party.rsa_key.private_key, wrapped_key)

                            if plaintext_key == None:
                                print("DDS: Decryption of key not possible")
                                privateData = None
                                continue
                            else:
                                privateData = unencrypt_data_payload(plaintext_key, contracts[contract]['privateData'])
                                #print(privateData)
                                print("Data Subject: {} | {} | {} | {} | {}".format(party.party, contracts[contract]['id'], contracts[contract]['publicData1'], contracts[contract]['publicData2'], privateData))
                        else:
                            print("DDS: No key available to decrypt contract (2)")

                await conn.close()
            await asyncio.sleep(5)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            logging.debug(e)
            print(e)
            print("DDS: Exiting: {}".format(party.party))

async def runtasks(config : Config, identities: [PartyConfig]):
    
    (owner, identity1, identity2, identity3, identity4, identity5) = identities

    task1 = asyncio.create_task(validate_registration(config, owner))
    task2 = asyncio.create_task(validate_registration(config, identity1))
    task3 = asyncio.create_task(validate_registration(config, identity2))
    task4 = asyncio.create_task(validate_registration(config, identity3))
    task5 = asyncio.create_task(validate_registration(config, identity4))
    task6 = asyncio.create_task(validate_registration(config, identity5))

    task7 = asyncio.create_task(dump_data_subjects(config, identity1))
    task8 = asyncio.create_task(dump_data_subjects(config, identity2))
    task9 = asyncio.create_task(dump_data_subjects(config, identity5))

    #task13 = asyncio.create_task(dump_contracts(config, owner))
    task10 = asyncio.create_task(distribute_keys(config, owner))

    group = GroupConfig("123456789")

    await setup_group(config, owner, group)
    await asyncio.sleep(3)
    await invite_party(config, owner, group, identity1)
    await asyncio.sleep(3)
    await invite_party(config, owner, group, identity2)
    await asyncio.sleep(3)
    await invite_party(config, owner, group, identity3)
    await asyncio.sleep(3)
    await invite_party(config, owner, group, identity4)
    await asyncio.sleep(3)

    encryption_key1 = create_dek_key()
    wrapped_key1 = WrappedEncryptionKey(encryption_key1.id, wrap_dek_key(owner.rsa_key.public_key, encryption_key1.key))
    await register_key(config, owner, group, wrapped_key1)
    original_data = {
        "SSN" : "123456789",
        "DOB" : "01 Jan 2024",
        "Medical ID" : "987654321"
    }
    await create_data_subject(config, owner, group, encryption_key1, [identity1, identity5], original_data)

    encryption_key2 = create_dek_key()
    wrapped_key2 = WrappedEncryptionKey(encryption_key2.id, wrap_dek_key(owner.rsa_key.public_key, encryption_key2.key))
    await register_key(config, owner, group, wrapped_key2)
    original_data = {
        "SSN" : "999999999",
        "DOB" : "01 Jan 2022",
        "Medical ID" : "987654322"
    }
    await create_data_subject(config, owner, group, encryption_key2, [identity1, identity2], original_data)

    await asyncio.gather(task1, task2, task3, task4, task5, task6, task7, task8, task9, task10)


def main(argv):

    parties = None
    parties_filename = 'parties.json'
    if os.path.isfile(parties_filename):
        f = open(parties_filename, 'r')
        parties_json = f.read()
        f.close()
        parties = Parties.schema().loads(parties_json)

    #group_id = ''.join(random.choices(string.digits + string.digits, k = 10))
    config = Config("http://localhost:6865")

    rsa_key = create_rsa_key()
    owner = PartyConfig(parties.owner, rsa_key)
    rsa_key = create_rsa_key()
    identity1 = PartyConfig(parties.identity1, rsa_key)
    rsa_key = create_rsa_key()
    identity2 = PartyConfig(parties.identity2, rsa_key)
    rsa_key = create_rsa_key()
    identity3 = PartyConfig(parties.identity3, rsa_key)
    rsa_key = create_rsa_key()
    identity4 = PartyConfig(parties.identity4, rsa_key)
    rsa_key = create_rsa_key()
    identity5 = PartyConfig(parties.identity5, rsa_key)

    asyncio.run( runtasks(config, [owner, identity1, identity2, identity3, identity4, identity5] ) )


if __name__ == '__main__':
  main(sys.argv[1:])


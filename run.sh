#!/bin/bash

rm app.log

daml script --dar .daml/dist/ex-canton-gdpr-0.0.1.dar --ledger-host localhost --ledger-port 6865 --script-name Setup:setupParties --output-file parties.json

#daml script --dar .daml/dist/ex-canton-gdpr-0.0.1.dar --ledger-host localhost --ledger-port 6865 --script-name Test:testSharedGroup


poetry run python3 bots/bots.py -p owner daemon &
poetry run python3 bots/bots.py -p identity1 daemon &
poetry run python3 bots/bots.py -p identity2 daemon &
poetry run python3 bots/bots.py -p identity3 daemon &
poetry run python3 bots/bots.py -p identity4 daemon &
poetry run python3 bots/bots.py -p identity5 daemon &

poetry run python3 bots/bots.py -p owner group 123456789

poetry run python3 bots/bots.py -p owner invite --group 123456789 --target owner
poetry run python3 bots/bots.py -p owner invite --group 123456789 --target identity1
poetry run python3 bots/bots.py -p owner invite --group 123456789 --target identity2
poetry run python3 bots/bots.py -p owner invite --group 123456789 --target identity3
poetry run python3 bots/bots.py -p owner invite --group 123456789 --target identity4

poetry run python3 bots/bots.py -p owner create_encryption 123456789 987654321

poetry run python3 bots/bots.py -p owner create_subject --target identity1 --target identity2 123456789 987654321 "public 1" "public 2" '{"SSN" : "123456789","DOB" : "01 Jan 2024","Medical ID" : "987654321"}'

poetry run python3 bots/bots.py -p owner create_subject --target identity1 --target identity2 123456789 987654321 "public 1" "public 2" '{"SSN" : "11111111","DOB" : "01 Jan 2024","Medical ID" : "987654321"}'

poetry run python3 bots/bots.py -p owner create_subject --target identity1 --target identity5 123456789 987654321 "public 1" "public 2" '{"SSN" : "22222222","DOB" : "01 Jan 2024","Medical ID" : "987654321"}'

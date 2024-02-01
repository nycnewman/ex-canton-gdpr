#!/bin/bash

# This script assumes you are on a MacOS device and use the iTerm2 terminal program. It also requires that you enable
# accessibility rights to iTerm (Apple icon, System Settings, Privacy & Security, Accessibility, iTerm checked) and 
# have enabled Python API in iTerm (iTerm2, Settings, General, Magic tab, enable Python, Automation)

rm app.log

daml deploy
daml script --dar .daml/dist/ex-canton-gdpr-0.0.1.dar --ledger-host localhost --ledger-port 6865 --script-name Setup:setupParties --output-file parties.json

#daml script --dar .daml/dist/ex-canton-gdpr-0.0.1.dar --ledger-host localhost --ledger-port 6865 --script-name Test:testSharedGroup

ITERM2_COOKIE=$(osascript -e 'tell application "iTerm2" to request cookie') 
python3 script_daemons.py


poetry run python3 bots/bots.py -p owner master
poetry run python3 bots/bots.py -p owner invite --target identity1
poetry run python3 bots/bots.py -p owner invite --target identity2
poetry run python3 bots/bots.py -p owner invite --target identity3
poetry run python3 bots/bots.py -p owner invite --target identity4

sleep 2

for i in {0..10} 
do
    SUBJECT_ID1=$(od -An -N4 -i /dev/urandom | tr -d '-')
    poetry run python3 bots/bots.py -p owner create_subject $SUBJECT_ID1

    SUBJECT_ID2=$(od -An -N4 -i /dev/urandom | tr -d '-')
    poetry run python3 bots/bots.py -p owner create_subject $SUBJECT_ID2

    KEY_ID=$(od -An -N4 -i /dev/urandom | tr -d '-')
    poetry run python3 bots/bots.py -p owner create_encryption $KEY_ID

    poetry run python3 bots/bots.py -p owner create_subject_data --target identity1 --target identity2 $SUBJECT_ID1 $KEY_ID "public 1" "public 1" '{"SSN" : "1111111111","DOB" : "01 Jan 2024","Medical ID" : "987654321"}'

    poetry run python3 bots/bots.py -p owner create_subject_data --target identity1 --target identity2 $SUBJECT_ID1 $KEY_ID "public 2" "public 2" '{"Credit_Card" : "1111-2222-3333-4444", "Expiry": "01-2000", "CVV": "111" }'

    poetry run python3 bots/bots.py -p owner create_subject_data --target identity3 --target identity4 $SUBJECT_ID2 $KEY_ID "public 3" "public 3" '{"SSN":"33333333","DOB":"31 Dec 2024","Medical ID" : "987654321"}'

    sleep 10

done

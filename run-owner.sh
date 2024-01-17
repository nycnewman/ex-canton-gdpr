#!/bin/bash

rm app.log

daml script --dar .daml/dist/ex-canton-gdpr-0.0.1.dar --ledger-host localhost --ledger-port 6865 --script-name Setup:setupParties --output-file parties.json

#daml script --dar .daml/dist/ex-canton-gdpr-0.0.1.dar --ledger-host localhost --ledger-port 6865 --script-name Test:testSharedGroup

export DAML_LEDGER_PARTY=`cat parties.json | jq -r '.["owner"]'`
export DAML_LEDGER_URL="http://localhost:6865"

poetry run python3 bots/bots.py



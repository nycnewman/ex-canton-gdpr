# Core Canton Capabilities

## Segregated Distribution of Data

## Contract Archiving

## Pruning

This demonstrates how to configure pruning in Canton. Note however that these settings are not viable for production as it would
have a significant impact on performance of the system

- Depends on Docker to run Postgres instance
- Tested against Canton Enterprise (not Community) 2.8.0 (available from Artifactory)
- Very short pruning intervals defined for domain and participants
- Pruning required ongoing activity in ledger

```angular2html
./start-postgres.sh
./run-canton.sh

./run.sh

poetry run python3 bots/bots.py -p owner dump --offset '000000000000000000'

# repeat following to generate new records and events
poetry run python3 bots/bots.py -p owner create_subject --target identity3 --target identity4 123456789 987654321 "public 1111" "public 2222" '{"SSN" : "33334444","DOB" : "01 Jan 2024","Medical ID" : "987654321"}'

# this should fail as initial Boundary no longer exists once pruning has completed
poetry run python3 bots/bots.py -p owner dump --offset '000000000000000000'

# where the value represents an offset in the ledger (obtained from boundary event records.

```

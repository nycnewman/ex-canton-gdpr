#!/bin/bash

export POSTGRES_HOST=localhost
export DOMAIN_USER=domain
export DOMAIN_PASSWORD='DomainPassword!'
export PARTICIPANT1_USER=participant1
export PARTICIPANT1_PASSWORD='Participant1Password!'
export PARTICIPANT2_USER=participant2
export PARTICIPANT2_PASSWORD='Participant2Password!'
export PARTICIPANT3_USER=participant3
export PARTICIPANT3_PASSWORD='Participant3Password!'


./canton-enterprise-2.8.0/bin/canton -c simple-topology.conf --bootstrap bootstrap.canton

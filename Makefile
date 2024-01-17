daml_files := $(shell find . -name '*.daml' -type f)


.PHONY: run
run: .venv/bin/python3 .daml/dist/ex-canton-gdpr-0.0.1.dar
	poetry run python3 bots/bots.py --url localhost:6865

.daml/dist/ex-canton-gdpr-0.0.1.dar: $(daml_files)
	daml build

.venv/bin/python3:
	python3 -m venv .venv
	pip3 install -r requirements.txt

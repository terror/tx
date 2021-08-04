default:
	just --list

ci: fmt test

fmt:
  yapf --in-place --recursive **/*.py

test:
  pytest

run *args:
  python3 ./src {{args}}

install *pkg:
  pipenv install {{pkg}} --skip-lock

lock:
  pipenv lock --pre

install-editable:
  pipenv install -e .

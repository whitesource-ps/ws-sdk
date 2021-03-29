#!/usr/bin/env bash/bin/bash

version=$(python -V 2>&1 | grep -Po '(?<=Python 3)(.+)' | tr -d ' ')
version_3=$(python3 -V 2>&1 | grep -Po '(?<=Python 3)(.+)' | tr -d ' ')

if ! python3 -V; then
  VERSION=$(python -V 2>&1 | grep -Po '(?<=Python )(.+)')
  if [[ $VERSION = 3* ]] ; then
    echo "Please install Python3"
    exit
  else
    PYTHON=$(which python)
    VERSION=$(python -V 2>&1 | grep -Po '(?<=Python )(.+)')
    PIP=$(which pip)
  fi
else
  PYTHON=$(which python3)
  VERSION=$(python3 -V 2>&1 | grep -Po '(?<=Python )(.+)')
  PIP=$(which pip3)
fi
echo "Found Python3 version:" "$VERSION"

echo "Converting text to UNIX"
dos2unix -q ./*

echo "Installing as user requirements:"
$PIP install -r requirements.txt

echo "To execute:" "${PYTHON}" "projects_cleanup.py params.config"

#!/bin/bash

cd flutter && git cat-file -p "$1":bin/internal/engine.version

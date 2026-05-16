#!/bin/bash
#
# Install git hooks for this repo.
# Run once after cloning: ./install-hooks.sh
#

git config core.hooksPath hooks
chmod +x hooks/*
echo "Git hooks installed (core.hooksPath=hooks)."

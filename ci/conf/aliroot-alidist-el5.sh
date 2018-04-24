# Continuous builder configuration for alidist/AliRoot on SLC5 native

# What is the package to rebuild
PACKAGE=AliRoot

# How many parallel jobs (i.e. make -j$JOBS)
JOBS=8

# Pause between each PR processing (seconds)
DELAY=300

# Where to get/push cached builds from/to
REMOTE_STORE="rsync://repo-ci.marathon.mesos/store/::rw"

# GitHub slug of the repository accepting PRs
PR_REPO=alisw/alidist

# PRs are made to this branch
PR_BRANCH=master

# Start PR check if PR comes from one of them (comma-separated)
TRUSTED_USERS=

# Start PR if author has already contributed to the PR
TRUST_COLLABORATORS=1

# What is the default to use
ALIBUILD_DEFAULTS=prod-latest

# How to name the check
CHECK_NAME=build/AliRoot/alidist

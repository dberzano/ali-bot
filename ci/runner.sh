#!/bin/bash -xe
set -o pipefail

# Setup GitLab credentials (to push new data)
printf "protocol=https\nhost=gitlab.cern.ch\nusername=alibuild\npassword=$GITLAB_TOKEN\n" |
  git credential-store --file $PWD/git-creds store
git config --global credential.helper "store --file $PWD/git-creds"

# Setup GitHub API credentials (to communicate with PRs)
echo $PR_TOKEN > $HOME/.github-token

# Clone code under "code"
CI_REPO=$CI_REPO # gh_user/gh_repo[:branch]
CI_REPO_ONLY=${CI_REPO%:*}
CI_BRANCH=${CI_REPO##*:}
[[ -d code/.git ]] || git clone https://github.com/$CI_REPO_ONLY ${CI_BRANCH:+-b $CI_BRANCH} code/

# Clone configuration under "conf"
[[ -d conf/.git ]] || { git clone https://gitlab.cern.ch/ALICEDevOps/ali-marathon.git conf/;
                        pushd conf;
                          git config user.name "ALICE bot";
                          git config user.email "ali.bot@cern.ch";
                        popd; }

# Continuous ops: update
pushd conf
  git fetch --all
  git reset --hard origin/HEAD
  git clean -fxd
  pushd ci_conf
    ../../../code/ci/sync-egroups.py > groups.yml || { rm groups.yml; git checkout groups.yml; }
    git commit -a -m "CI e-groups updated" || true
    git push
  popd
popd
pushd code
  git fetch --all
  git reset --hard origin/$([[ "$CI_BRANCH" ]] && echo "$CI_BRANCH" || echo HEAD)
  git clean -fxd
  pushd ci
    for X in ../../conf/ci_conf/*; do
      ln -nfs $X .
    done
    ls -l
    ./process-pull-request --admins $CI_ADMINS --bot-user alibuild --debug
  popd
popd

# Update self, sleep, relaunch
cp code/ci/runner.sh . && chmod +x runner.sh
sleep $SLEEP
exec ./runner.sh "$@"

#!/usr/bin/env python
from __future__ import print_function
from logging import debug, info, warning, error
from argparse import ArgumentParser
from os.path import expanduser
import logging, re, json, yaml
from klein import Klein
from twisted.internet.task import LoopingCall
from twisted.internet import defer, task, reactor, threads
from time import sleep, time
from random import randint
from github import Github,GithubException

class Approvers(object):
  def __init__(self, users_override=[]):
    self.approvers = []
    self.users_override = users_override
  def __call__(self):
    return self.approvers
  @staticmethod
  def from_str(s, users_override=[]):
    match = re.findall("([0-9]+) of ([^;]+)?", s)
    a = Approvers(users_override=users_override)
    for m in match:
      a.push(int(m[0]), map(Approvers.ghstrip, str(m[1]).split(",")))
    return a
  def approve(self, user):
    if user in self.users_override:
      self.approvers = True
      return True
    if self.approvers == True:
      return True
    ok = False
    for a in self.approvers:
      try:
        a["u"].remove(user)
        a["n"] = a["n"]-1
        ok = True
      except (KeyError,ValueError):
        pass
    if ok:
      self.approvers = [ a for a in self.approvers if a["n"] >= 1 ]
      if not self.approvers:
        self.approvers = True
    return ok
  def push(self, num_approvers, approvers):
    if not self.approvers and isinstance(approvers, bool):
      self.approvers = approvers
    elif isinstance(self.approvers, bool) and not isinstance(approvers, bool):
      self.approvers = [{ "n":num_approvers, "u":approvers }]
    elif not isinstance(approvers, bool):
      found = False
      for x in self.approvers:
        if x["u"] == approvers:
          x["n"] = max(x["n"], num_approvers)  # be restrictive when updating existing group
          found = True
          break
      if not found:
        self.approvers.append({ "n":num_approvers, "u":approvers })
  def flat(self):
    f = set()
    if self.approvers == True:
      return f
    for x in self.approvers:
      f.update(x["u"])
    return f
  def ghtagmap(self, u):
    if u in self.usermap:
      return "@%s (%s)" % (u, self.usermap[u])
    return "@"+u
  @staticmethod
  def ghstrip(u):
    try:
      u = u[0:u.index("(")]
    except ValueError:
      pass
    return u.strip("@ ")
  def __str__(self):
    if self.approvers == True:
      return "approved"
    approval_str = [ "%d of %s" % (x["n"], ", ".join(map(self.ghtagmap, x["u"]))) for x in self.approvers ]
    return "; ".join(approval_str)

class State(object):

  def __init__(self, name, sha=None, approvers=Approvers(), opener=None,
               dryRun=False, haveApproved=[], haveApproved_p2=[]):
    self.name                = name
    self.sha                 = sha
    self.approvers           = approvers
    self.opener              = opener
    self.dryRun              = dryRun
    self.haveApproved        = haveApproved
    self.haveApproved_p2     = haveApproved_p2
    self.approvers_unchanged = Approvers.from_str(str(approvers), approvers.users_override)
    if name == "STATE_INITIAL":
      self.action = self.action_check_permissions
    elif name == "STATE_APPROVAL_REQUIRED":
      self.action = self.action_approval_required
    elif name == "STATE_APPROVAL_PENDING":
      self.action = self.action_approval_pending
    elif name == "STATE_TESTS_ONLY":
      self.action = self.action_tests_only
    elif name == "STATE_TESTS_AUTOMERGE":
      self.action = self.action_tests_automerge
    elif name == "STATE_MERGE_APPROVAL_PENDING":
      self.action = self.action_approval2_pending
    else:
      raise RuntimeError("unknown state %s" % self.name)

  def __str__(self):
    return "%s: sha: %s, approvers: %s, opener: %s, have approved: %s, have approved (2): %s" % \
           (self.name, self.sha, self.approvers, self.opener, self.haveApproved, self.haveApproved_p2)

  def action_check_permissions(self, pull, perms, tests):
    if  pull.changed_files > 10:
      # Too many changed files. It's not worth to check every single one of them. This would also
      # exhaust the API calls. Let's ask for the approval of the masters only.
      info("this pull request has %d (> 10) changed files: requesting approval from the admins only" % \
           pull.changed_files)
      self.approvers.push(1, self.approvers.users_override)
    else:
      for fn in pull.get_files():
        debug("determining permissions for file %s" % fn.filename)
        for rule in perms:
          num_approve,approve = rule(fn.filename, pull.user.login)  # approve can be bool or set (not list)
          if approve:
            debug("file %s matched by rule %s: %s" % (fn.filename, rule.path_regexp, approve))
            self.approvers.push(num_approve, approve)
            break
        assert approve, "this should not happen: for file %s no rule matches" % fn.filename
    debug("computed list of approvers: %s (override: %s)" % (self.approvers, self.approvers.users_override))
    self.approvers_unchanged = Approvers.from_str(str(self.approvers), users_override=self.approvers.users_override)
    self.action_approval_required(pull, perms, tests)

  def action_approval_required(self, pull, perms, tests):
    self.action_approval_pending(pull, perms, tests)
    if self.approvers() != True:
      info("%s: approval required by: %s" % (self.sha, self.approvers))
      self.request_approval(pull)

  def request_approval(self, pull):
    setStatus(pull, self.sha, "review", "pending", "pending approval")
    commentOnPr(pull, "%s: approval required: %s\n\n" \
                      "_Comment with `+1` to approve and allow automatic merging," \
                      "or with `+test` to run tests only. **Please comment on the pull request: " \
                      "[click here](https://github.com/%s/pull/%d) and comment at the bottom of " \
                      "the page.**_" % \
                      (self.sha, self.approvers, pull.base.repo.full_name, pull.number))

  def action_approval_pending(self, pull, perms, tests):
    approveTestsOnly = False
    hasChanged = False
    for u in self.haveApproved:
      if self.approvers.approve(u["u"]):
        hasChanged = True
        if u["what"] == "test":
          approveTestsOnly = True
    if self.approvers() == True:
      setStatus(pull, self.sha, "review", "success", \
                "tests approved" if approveTestsOnly else "merge approved")
      for t in tests:
        setStatus(pull, self.sha, t, "pending", "test required")
    if self.approvers() == True and approveTestsOnly:
      info("%s: only testing approved, no auto merge on test success" % self.sha)
      commentOnPr(pull, "%s: testing approved: " \
                        "will not be automatically merged; starting testing. " \
                        "If testing succeeds, merging will require further approval from %s" % \
                        (self.sha, str(self.approvers_unchanged)))
    elif self.approvers() == True:
      info("%s: changes approved, auto merge on test success" % self.sha)
      commentOnPr(pull, "%s: approved: will be automatically merged on successful tests" % self.sha)
    else:
      review_status = getStatus(pull, self.sha, "review")[0]
      if hasChanged or (review_status is not None and review_status != "pending"):
        info("%s: list of approvers has changed to %s, notifying" % (self.sha, self.approvers))
        self.request_approval(pull)
      else:
        info("%s: list of approvers unchanged, nothing to say" % self.sha)

  def action_approval2_pending(self, pull, perms, tests):
    hasChanged = False
    for u in self.haveApproved_p2:
      if self.approvers.approve(u["u"]):
        hasChanged = True
    if self.approvers() == True:
      info("%s: merge approved, merging now" % self.sha)
      prMerge(pull)
    else:
      review_status = getStatus(pull, self.sha, "review")[0]
      if review_status != "success":
        setStatus(pull, self.sha, "review", "success", "tests approved")  # conflicts gone: restore
      if hasChanged or review_status != "success":
        info("%s: list of merge approvers has changed to %s, notifying" % (self.sha, self.approvers))
        self.request_approval(pull)
      else:
        info("%s: list of merge approvers unchanged, nothing to say" % self.sha)

  def action_tests_only(self, pull, perms, tests):
    ok = False
    if getStatus(pull, self.sha, "review")[0] != "success":
      setStatus(pull, self.sha, "review", "success", "tests approved")  # conflicts gone: restore
    for x in tests:
      s = getStatus(pull, self.sha, x)[0]
      debug("%s: required test %s is %s" % (self.sha, x, s))
      ok = (s == "success")
      if not ok:
        break
    if ok:
      info("%s: all tests passed, requesting approval from %s" % (self.sha, self.approvers))
      commentOnPr(pull, "%s: tests OK, approval required for merging: %s\n\n" \
                        "_Comment with `+1` to merge. **Please comment on the pull request: " \
                        "[click here](https://github.com/%s/pull/%d) and comment at the bottom " \
                        "of the page.**_" % \
                        (self.sha, str(self.approvers), pull.base.repo.full_name, pull.number))
    info("%s: tests are currently in progress, will not auto merge on success" % self.sha)

  def action_tests_automerge(self, pull, perms, tests):
    ok = False
    if getStatus(pull, self.sha, "review")[0] != "success":
      setStatus(pull, self.sha, "review", "success", "merge approved")  # conflicts gone
    for x in tests:
      s = getStatus(pull, self.sha, x)[0]
      debug("%s: required test %s is %s" % (self.sha, x, s))
      ok = (s == "success")
      if not ok:
        break
    if ok:
      prMerge(pull)
    else:
      info("%s: tests are currently in progress, will auto merge on success" % self.sha)

class Transition(object):

  def __init__(self, regexp, final_state, from_states):
    self.regexp      = regexp
    self.final_state = final_state
    self.from_states = from_states

  def __str__(self):
    return "PR Transition: user: %s, regexp: %s, new state: %s, from: %s" % (self.user, self.regexp, self.final_state, self.from_states)

  def evolve(self, state, opener, first_line, extra_allowed_openers):
    allowed_openers = state.approvers.flat()
    allowed_openers.update(extra_allowed_openers)
    debug("evolve: source: %s, allowed: %s, regexp: %s, final: %s, from: %s" % \
          (state, allowed_openers, self.regexp, self.final_state, self.from_states))
    if state.name not in self.from_states:
      debug("evolve: from state %s unallowed" % state.name)
      return state

    match = re.search(self.regexp, first_line)
    named_matches = match.groupdict() if match else None
    if not named_matches:
      debug("evolve: comment does not match")
      return state
    if named_matches.get("sha", state.sha) != state.sha:
      debug("evolve: comment does not pertain to current sha")
      return state

    if "approval" in named_matches:
      # Whoever wrote the comment is considered. Authz is checked later on
      new_state = State(name=state.name,
                        sha=state.sha,
                        approvers=state.approvers,
                        opener=state.opener,
                        dryRun=state.dryRun,
                        haveApproved=state.haveApproved,
                        haveApproved_p2=state.haveApproved_p2)
      ha = new_state.haveApproved_p2 if state.name == "STATE_MERGE_APPROVAL_PENDING" else new_state.haveApproved
      ha.append({"u":opener,"what":"test" if named_matches["approval"] == "test" else "merge"})
      debug("evolve: list of approvers updated: %s" % new_state.haveApproved)
    elif not opener in allowed_openers:
      debug("evolve: opener %s unallowed to move to state %s" % (opener, self.final_state))
      return state
    elif "approvers" in named_matches:
      app = Approvers.from_str(named_matches["approvers"], users_override=extra_allowed_openers)
      if not app:
        debug("evolve: cannot match approvers")
        return state
      new_state = State(name=self.final_state,
                        sha=state.sha,
                        approvers=app,
                        opener=opener,
                        dryRun=state.dryRun,
                        haveApproved=state.haveApproved,
                        haveApproved_p2=state.haveApproved_p2)
    else:
      debug("evolve: approved")
      new_state = State(name=self.final_state,
                        sha=state.sha,
                        approvers=state.approvers,
                        opener=opener,
                        dryRun=state.dryRun,
                        haveApproved=state.haveApproved,
                        haveApproved_p2=state.haveApproved_p2)

    return new_state

TRANSITIONS = [
  Transition("^\+(?P<approval>1|test)",
             None,
             ["STATE_INITIAL", "STATE_APPROVAL_REQUIRED", "STATE_APPROVAL_PENDING", "STATE_MERGE_APPROVAL_PENDING"]),
  Transition("^(?P<sha>[a-fA-F0-9]+): approval required[^:]*: (?P<approvers>.*)",
             "STATE_APPROVAL_PENDING",
             ["STATE_INITIAL", "STATE_APPROVAL_PENDING"]),
  Transition("^(?P<sha>[a-fA-F0-9]+): testing approved.*further approval from (?P<approvers>.*)",
             "STATE_TESTS_ONLY",
             ["STATE_INITIAL", "STATE_APPROVAL_PENDING"]),
  Transition("^(?P<sha>[a-fA-F0-9]+): approved",
             "STATE_TESTS_AUTOMERGE",
             ["STATE_INITIAL", "STATE_APPROVAL_PENDING"]),
  Transition("^(?P<sha>[a-fA-F0-9]+): tests OK, approval required[^:]*: (?P<approvers>.*)",
             "STATE_MERGE_APPROVAL_PENDING",
             ["STATE_TESTS_ONLY"])
]

class Perms(object):

  def __init__(self, path_regexp, authorized, approve, num_approve):
    self.path_regexp = path_regexp
    self.authorized = authorized
    self.approve = approve
    self.num_approve = num_approve

  def path_match(self, path):
    try:
      return True if re.search(self.path_regexp, path) else False
    except re.error as e:
      warning("path regular expression %s is not valid: %s" % (self.path_regexp, e))
      return False

  def __call__(self, path, current_user):
    if self.path_match(path):
      if current_user in self.authorized:
        return 0,True
      else:
        return self.num_approve,set(self.approve)
    return 0,False

class PrRPC(object):
  app = Klein()
  items = set()

  def __init__(self, host, port, bot_user, admins, processQueueEvery, processAllEvery, dryRun):
    self.bot_user = bot_user
    self.admins = admins
    self.dryRun = dryRun
    self.must_exit = False
    self.gh = None
    self.gh_repos = {}
    self.pulls_hashes = {}

    def set_must_exit():
      self.must_exit = True
    reactor.addSystemEventTrigger("before", "shutdown", set_must_exit)

    def schedule_process_pull_requests():
      items_to_process = self.items.copy()
      self.items = set()  # empty queue
      d = threads.deferToThread(self.process_pull_requests, items_to_process,
                                                            self.bot_user,
                                                            self.admins,
                                                            self.dryRun)
      d.addCallback(lambda unprocessed: self.items.update(unprocessed))  # repush (requeue) unprocessed
      d.addErrback(lambda x: error("Uncaught exception during pull request test: %s" % str(x)))
      d.addBoth(lambda x: reactor.callLater(processQueueEvery, schedule_process_pull_requests))
      return d

    if processAllEvery <= 0:
      warning("Pull requests will be processed only upon callbacks")
    else:
      reactor.callLater(1, LoopingCall(self.add_all_open_prs).start, processAllEvery)

    reactor.callLater(10, schedule_process_pull_requests)
    self.app.run(host, port)

  def j(self, req, obj):
    req.setHeader("Content-Type", "application/json")
    return json.dumps(obj)

  def gh_init_repo(self, repo=None):
    if not self.gh:
      try:
        self.gh = Github(login_or_token=open(expanduser("~/.github-token")).read().strip())
      except (IOError,GithubException) as e:
        error("GitHub API problem: %s" % e)
        return False
    if repo and not repo in self.gh_repos:
      debug("Getting GitHub repository %s" % repo)
      try:
        self.gh_repos[repo] = self.gh.get_repo(repo)
      except GithubException as e:
        error("Cannot get GitHub repository: %s" % e)
        return False
    return True

  def add_all_open_prs(self):
    self.pulls_hashes = {}
    perms,_,_ = load_perms("perms.yml", "groups.yml", "mapusers.yml", admins=args.admins.split(","))
    for repo_name in perms:
      self.gh_init_repo(repo_name)
      try:
        for p in self.gh_repos[repo_name].get_pulls():
          fullpr = repo_name + "#" + str(p.number)
          self.pulls_hashes[fullpr] = p.head.sha
          debug("Process all: appending %s" % fullpr)
          self.items.add(fullpr)
      except GithubException as e:
        warning("Cannot get pulls for %s: %s" % (repo_name, e))

  # Processes a list of pull requests. Takes as input an iterable of pull requests
  # in the form Group/Repo#PrNum and returns a set of processed pull requests.
  def process_pull_requests(self, prs, bot_user, admins, dryRun):
    gh_req_left = -1
    info("Processing all scheduled pull requests: %d to go" % len(prs))
    unprocessed = set(prs)  # keep track of what could not be processed

    # Load permissions as first thing
    perms,tests,usermap = load_perms("perms.yml", "groups.yml", "mapusers.yml", admins=args.admins.split(","))
    #debug("permissions:\n"+json.dumps(perms, indent=2, default=lambda o: o.__dict__))
    #debug("tests:\n"+json.dumps(tests, indent=2))
    #debug("GitHub to full names mapping:\n"+json.dumps(usermap, indent=2))
    setattr(Approvers, "usermap", usermap)

    for pr in prs:
      if self.must_exit:
        info("Interrupting loop: must exit")
        break
      repo,prnum = pr.split("#", 1)
      prnum = int(prnum)
      debug("Queued PR: %s#%d" % (repo,prnum))
      if not repo in perms:
        debug("Skipping %s: not a configured repository" % pr)
        unprocessed.remove(pr)
        continue
      if not self.gh_init_repo():
        break
      gh_req_left,gh_req_limit = self.gh.rate_limiting
      info("GitHub API calls: %d calls left (%d calls allowed) - reset in %d seconds" % \
           (gh_req_left,gh_req_limit,
            self.gh.rate_limiting_resettime-time()))
      if not self.gh_init_repo(repo):
        warning("Skipping this pull request, GitHub could not fetch the repo")
        continue

      ok = False
      try:
        pull = self.gh_repos[repo].get_pull(prnum)
        sha = pull.head.sha
        debug("PR %s#%d has hash %s" % (repo,prnum,sha))
        self.pulls_hashes[pr] = sha
        ok = pull_state_machine(pull,
                                self.gh_repos[repo],
                                perms.get(repo, []),
                                tests.get(repo, []),
                                bot_user,
                                admins,
                                dryRun)
      except GithubException as e:
        error("Cannot process pull request %s#%d, removing from list: %s" % (repo, prnum, e))
        ok = True
      except Exception as e:
        error("Cannot process pull request %s#%d, retrying, strange error: %s" % (repo, prnum, e))

      # PR can be removed from list
      if ok:
        unprocessed.remove(pr)
    if gh_req_left > 0:
      gh_req_left_2,gh_req_limit_2 = self.gh.rate_limiting
      info("GitHub API calls: %d calls done, %d calls left (%d calls allowed) - reset in %d seconds" % \
           (gh_req_left-gh_req_left_2,
            gh_req_left_2,gh_req_limit_2,
            self.gh.rate_limiting_resettime-time()))
    return unprocessed  # empty set in case of full success

  @app.route("/", methods=["POST"])
  def github_callback(self, req):
    data = json.loads(req.content.read())
    repo = data.get("repository", {}).get("full_name", None)  # always there
    prid = None
    if "pull_request" in data and data.get("action") in [ "opened", "synchronize" ]:
      # EVENT: pull request just opened
      prid = data.get("number", None)
      etype = "pull request opened"
    elif "state" in data and "context" in data and "sha" in data:
      # EVENT: state changed, let's hope we have the hash in cache
      for k,v in self.pulls_hashes.items():
        if v == data["sha"]:
          prid = k.split("#", 1)[1]
          etype = "state changed"
          break
      if not prid:
        warning("State changed event was unhandled: could not find %s in cache" % data["sha"])
    elif "issue" in data and data.get("action") == "created" \
      and isinstance(data["issue"].get("pull_request", None), dict) \
      and data["issue"].get("closed_at", True) is None \
      and data.get("sender", {}).get("login", "alibuild") != "alibuild":
      # EVENT: comment added on an open pull request (and not by a bot)
      prid = data["issue"].get("number", None)
      etype = "pull request commented"
    if repo and prid:
      prid = int(prid)
      prfull = "%s#%d" % (repo, prid)
      info("Received relevant event (%s) for %s" % (etype, prfull))
      self.items.add(prfull)
    else:
      debug("Received unhandled event from GitHub:\n%s" % json.dumps(data, indent=2))
    return "roger"

  @app.route("/list")
  def get_list(self, req):
    return self.j(req, {"queued":list(self.items),
                        "hashes":self.pulls_hashes})

  @app.route("/process/<group>/<repo>/<prid>")
  def process(self, req, group, repo, prid):
    pr = "%s/%s#%d" % (group, repo, int(prid))
    self.items.add(pr)
    return self.j(req, {"added_to_queue": pr})

  @app.route("/health")
  def health(self, req):
    return self.j(req, {"status": "ok"})

# Parse file
def load_perms(f_perms, f_groups, f_mapusers, admins):
  perms = {}
  groups = {}
  mapusers = {}
  tests = {}
  realnames = {}

  # Load user mapping (CERN -> GitHub)
  try:
    mapusers = yaml.safe_load(open(f_mapusers))
    for k in mapusers:
      if not " " in mapusers[k]:
        mapusers[k] = mapusers[k] + " " + mapusers[k]
      un,real = mapusers[k].split(" ", 1)
      realnames[un] = real  # gh -> full
      mapusers[k] = un      # cern -> gh
  except (IOError,yaml.YAMLError) as e:
    error("cannot load user mapping from %s: %s" % (f_mapusers, e))

  # Load external groups
  try:
    groups = yaml.safe_load(open(f_groups))
    for k in groups:
      groups[k] = groups[k].split()
  except (IOError,yaml.YAMLError) as e:
    error("cannot load external groups from %s: %s" % (f_groups, e))

  # Load permissions
  try:
    c = yaml.safe_load(open(f_perms))
  except (IOError,yaml.YAMLError) as e:
    error("cannot load permissions from %s: %s" % (f_perms, e))
    c = {}
  for g in c.get("groups", {}):
    # Get internal groups (they override external groups with the same name)
    groups[g] = list(set(c["groups"][g].split()))
  for repo in c:
    if not "/" in repo: continue
    try:
      tests[repo] = c[repo].get("tests", [])
    except (KeyError,TypeError) as e:
      warning("config %s: wrong syntax for tests in repo %s" % (f_perms, repo))
      tests[repo] = []
    try:
      rules = c[repo].get("rules", [])
    except (KeyError,TypeError) as e:
      warning("config %s: wrong syntax for rules in repo %s" % (f_perms, repo))
      rules = []
    perms[repo] = []
    for path_rule in rules:
      if not isinstance(path_rule, dict):
        warning("config %s: skipping unknown token %s" % (f_perms,path_rule))
        continue
      for path_regexp in path_rule:
        auth = path_rule[path_regexp].split()
        approve = []
        num_approve = 1
        for a in auth:
          if a.startswith("approve="): approve = a[8:].split(",")
          elif a.startswith("num_approve="):
            try:
              num_approve = int(a[12:])
              if num_approve < 1: raise ValueError
            except ValueError as e:
              warning("config %s: invalid %s for repo %s path %s: fallback to 1" % \
                      (cf, a, repo, path_regexp))
              num_approve = 1

        auth = [ x for x in auth if not "=" in x ]
        # Append rule to perms
        perms[repo].append(Perms(path_regexp=path_regexp,
                                 authorized=auth,
                                 approve=approve,
                                 num_approve=num_approve))

  # Expand groups (unknown discarded)
  for repo in perms:
    for path_rule in perms[repo]:
      for k in ["authorized", "approve"]:
        users = set()
        for u in getattr(path_rule, k):
          if u[0] == "@": users.update(groups.get(u[1:], []))
          else: users.add(u)
        # Map users (unknown discarded)
        setattr(path_rule, k, list(set([ mapusers[u] for u in users if u in mapusers ])))
      if not path_rule.approve:
        #warning("empty list of approvers for %s on %s: defaulting to admins" % \
        #        (path_rule.path_regexp, repo))
        path_rule.approve = admins
      path_rule.num_approve = min(path_rule.num_approve, len(path_rule.approve))

  # Append catch-all default rule to all repos: we *always* match something
  for repo in perms:
    perms[repo].append(Perms(path_regexp="^.*$",
                             authorized=[],  # TODO use authorized=admins in production
                             approve=admins,
                             num_approve=1))

  return perms,tests,realnames

def pull_state_machine(pull, repo, perms, tests, bot_user, admins, dryRun):

  info("~~~ processing pull %s#%d: %s (changed files: %d) ~~~" % (repo.full_name, pull.number, pull.title, pull.changed_files))

  if not pull.changed_files:
    if getStatus(pull, pull.head.sha, "review") != ("error", "empty pull request"):
      commentOnPr(pull, ("@%s: your pull request changes no files (%s)." + \
                         "You may want to fix it or close it.") % (pull.user.login, pull.head.sha))
      setStatus(pull, pull.head.sha, "review", "error", "empty pull request")
    info("skipping pull %s#%d (%s): it is empty!" % (repo.full_name, pull.number, pull.title))
    return True  # ok

  if pull.closed_at:
    info("skipping pull %s#%d (%s): closed" % (repo.full_name, pull.number, pull.title))
    return True  # ok

  if not pull.mergeable:
    if pull.mergeable_state == "dirty":
      # It really cannot be merged. Notify user
      if getStatus(pull, pull.head.sha, "review") != ("error", "conflicts"):
        commentOnPr(pull, ("@%s: there are conflicts in your changes (%s) you need to fix.\n\n" + \
                           "_You can have a look at the "                                       + \
                           "[documentation](http://alisw.github.io/git-advanced/) or you can "  + \
                           "press the **Resolve conflicts** button and try to fix them from "   + \
                           "the web interface._") % (pull.user.login, pull.head.sha))
        setStatus(pull, pull.head.sha, "review", "error", "conflicts")
      info("skipping pull %s#%d (%s): it cannot be merged, status is \"%s\"" % \
           (repo.full_name, pull.number, pull.title, pull.mergeable_state))
      return True  # ok to skip
    else:  # "unknown"
      info("skipping pull %s#%d (%s): still computing mergeability status (which is \"%s\")" % \
           (repo.full_name, pull.number, pull.title, pull.mergeable_state))
      return False  # we should come back to it

  state = State(name="STATE_INITIAL",
                sha=pull.head.sha,
                dryRun=args.dryRun,
                approvers=Approvers(users_override=admins),
                haveApproved=[])

  commit_date = None  # lazy (save API calls)

  for comment in pull.get_issue_comments():
    if not commit_date:
      commit_date = pull.head.repo.get_commit(pull.head.sha).commit.committer.date
    comment_date = comment.created_at
    commenter = comment.user.login
    first_line = comment.body.split("\n", 1)[0].strip()
    if (comment_date-commit_date).total_seconds() < 0:
      info("* %s @ %s UTC: %s ==> skipping" % (commenter, comment_date, first_line))
      continue
    info("* %s @ %s UTC: %s" % (commenter, comment_date, first_line))
    for transition in TRANSITIONS:
      new_state = transition.evolve(state, commenter, first_line, [bot_user]+admins)
      if not new_state is state:
        # A transition occurred
        info("  ==> %s" % new_state)
        state = new_state
        break

  info("Final state is %s: executing action" % state)
  state.action(pull, perms, tests)
  return True

def getStatus(pull, sha, context):
  commit = pull.base.repo.get_commit(sha)
  for s in commit.get_statuses():
    if s.context == context:
      return s.state,s.description
      break  # first (most recent) only
  debug("Could not get \"%s\" state for %s" % (context, sha))
  return None,None

if __name__ == "__main__":
  parser = ArgumentParser()
  parser.add_argument("--dry-run", dest="dryRun",
                      action="store_true", default=False,
                      help="Do not modify Github")
  parser.add_argument("--debug", dest="debug",
                      action="store_true", default=False,
                      help="Be verbose in debug output")
  parser.add_argument("--more-debug", dest="more_debug",
                      action="store_true", default=False,
                      help="Include GitHub API debug output")
  parser.add_argument("--bot-user", dest="bot_user",
                      help="GitHub bot username (mandatory)")
  parser.add_argument("--admins", dest="admins",
                      help="Comma-separated list of GitHub usernames of admins (mandatory)")
  parser.add_argument("--process-queue-every", dest="processQueueEvery", default=30, type=int,
                      help="Accumulate pull requests and process them every that many seconds")
  parser.add_argument("--process-all-every", dest="processAllEvery", default=600, type=int,
                      help="Process all pull requests every that many seconds (0: callbacks only)")
  args = parser.parse_args()
  if args.more_debug: args.debug = True
  if not args.bot_user:
    parser.error("Please specify the bot's user name on GitHub (--bot-user)")
  if not args.admins:
    parser.error("Please specify the GitHub usernames of admins (--admins)")
  if args.processQueueEvery < 5:
    parser.error("--process-queue-every must be at least 5 seconds")
  if args.processAllEvery > 0 and args.processAllEvery < 10:
    parser.error("--process-all-every must be either 0 (disable) or at least 10 seconds")

  logger = logging.getLogger()
  loggerHandler = logging.StreamHandler()
  loggerHandler.setFormatter(logging.Formatter('%(levelname)s:%(name)s: %(message)s'))
  if args.debug: logger.setLevel(logging.DEBUG)
  else: logger.setLevel(logging.INFO)
  if not args.more_debug:
    logging.getLogger("github").setLevel(logging.WARNING)
  logger.addHandler(loggerHandler)

  if args.dryRun:
    commentOnPr = lambda pr, comment: info("dry run; would comment the following: %s" % (comment))
    setStatus = lambda pull, sha, context, state, message: \
                  info("dry run; would set for context %s state %s, message %s for %s" % (context, state, message, sha))
    prMerge = lambda pull: info("dry run; would have merged this pull request")
  else:
    def commentOnPr(pr, comment):
      info("commenting: %s" % comment)
      pr.create_issue_comment(comment)
    def setStatus(pull, sha, context, state, message):
      add_state = True
      commit = pull.base.repo.get_commit(sha)
      for s in commit.get_statuses():
        if s.context == context and s.state == state and s.description == message:
          debug("most recent %s state for %s is already %s (%s)" % (context, sha, state, message))
          add_state = False
        break  # first (most recent) only
      if add_state:
        info("setting state %s (%s) for %s" % (state, message, sha))
        commit.create_status(state, "", message, context)
    def prMerge(pull):
      info("merging pull request")
      pull.merge()

  prrpc = PrRPC(host="0.0.0.0",
                port=8000,
                bot_user=args.bot_user,
                admins=args.admins.split(","),
                processQueueEvery=args.processQueueEvery,
                processAllEvery=args.processAllEvery,
                dryRun=args.dryRun)

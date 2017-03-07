from github import Github, GithubException
from collections import namedtuple
from logging import debug, info, warning, error

class MetaGit(object):

  def __init__(self, backend, token, rw=True):
    # Set rw to False to only read from GitHub ("dry run")
    assert backend=="GitHub", "You can only use GitHub for now"
    self.gh = Github(login_or_token=token)  # lazy
    self.gh_commits = {}
    self.gh_pulls = {}
    self.gh_repos = {}
    self.rate_left = 0
    self.rate_limit = 0
    self.rate_reset = 0
    self.rw = rw

  def get_rate_limit(self):
    # Returns a tuple with three elements: API calls left, limit, reset time (s)
    try:
      a,b = self.gh.rate_limiting
      return a,b,self.gh.rate_limiting_resettime
    except GithubException as e:
      raise MetaGitException("Cannot get GitHub rate limiting")

  def get_pull(self, pr, cached=False):
    # Given pr in group/repo#num format, returns a MetaPull with attributes. No cache by default
    repo,num = self.split_repo_pr(pr)
    if not repo in self.gh_repos:
      try:
        self.gh_repos[repo] = self.gh.get_repo(repo)
      except GithubException as e:
        raise MetaGitException("Cannot get repository %s: %s" % (repo, e))
    if not cached or not pr in self.gh_pulls:
      try:
        self.gh_pulls[pr] = self.gh_repos[repo].get_pull(num)
      except GithubException as e:
        raise MetaGitException("Cannot get pull request %s: %s" % (pr, e))
    pull = namedtuple("MetaPull", ["title", "hash", "changed_files"])
    pull.name            = pr
    pull.repo            = repo
    pull.num             = num
    pull.title           = self.gh_pulls[pr].title
    pull.changed_files   = self.gh_pulls[pr].changed_files
    pull.sha             = self.gh_pulls[pr].head.sha
    pull.closed_at       = self.gh_pulls[pr].closed_at
    pull.mergeable       = self.gh_pulls[pr].mergeable
    pull.mergeable_state = self.gh_pulls[pr].mergeable_state
    pull.who             = self.gh_pulls[pr].user.login
    pull.when            = self.gh_pulls[pr].head.repo.get_commit(pull.sha).commit.committer.date
    pull.get_files       = self.gh_pulls[pr].get_files  # TODO
    return pull

  def get_pulls(self, repo):
    # Returns a set of pull requests for this repository, and caches the objects
    if not repo in self.gh_repos:
      try:
        self.gh_repos[repo] = self.gh.get_repo(repo)
      except GithubException as e:
        raise MetaGitException("Cannot get repository %s: %s" % (repo, e))
    all_pulls = set()
    try:
      for p in self.gh_repos[repo].get_pulls():
        pr = repo + "#" + str(p.number)
        self.gh_pulls[pr] = p
        all_pulls.add(pr)
    except GithubException as e:
      raise MetaGitException("Cannot get list of pull requests for %s" % repo)
    return all_pulls

  def get_pull_from_sha(self, sha):
    # Returns a pull request object from the sha, if cached. None if not found
    for pr in self.gh_pulls:
      if self.gh_pulls[pr].head.sha == sha:
        return self.get_pull(pr, cached=True)
    return None

  def get_statuses(self, pr, contexts):
    # Given a pr and an array of contexts returns a dict of MetaStatus. If status is not found, it
    # will not appear in the returned dict
    pull = self.get_pull(pr, cached=True)
    if not pull.sha in self.gh_commits:
      try:
        self.gh_commits[pull.sha] = self.gh_pulls[pr].base.repo.get_commit(pull.sha)
      except GithubException as e:
        raise MetaGitException("Cannot get commit %s from %s: %s" % (pull.sha, pr, e))
    statuses = {}
    try:
      for s in self.gh_commits[pull.sha].get_statuses():
        if s.context in contexts and not s.context in statuses:
          sn = namedtuple("MetaStatus", ["context", "state", "description"])
          sn.context     = s.context
          sn.state       = s.state
          sn.description = s.description
          statuses.update({ pull.sha: sn })
          if len(statuses) == len(contexts):
            break
    except GithubException as e:
      raise MetaGitException("Cannot get statuses for %s on %s: %s" % (pull.sha, pr, e))
    return statuses

  def get_status(self, pr, context):
    # Return state and description for a single status, or None,None if not found
    for _,d in self.get_statuses(pr, [context]).items():
      return d.state,d.description
    return None,None

  def set_status(self, pr, context, state, description="", force=False):
    # Set status for a given pr. If force==True set it even if it already exists
    if not self.rw:
      info("%s: not setting %s=%s (dry run)" % (pr, context, state))
      return
    info("%s: setting %s=%s (dry run)" % (pr, context, state))
    pull = self.get_pull(pr, cached=True)
    if not pull.sha in self.gh_commits:
      try:
        self.gh_commits[pull.sha] = self.gh_pulls[pr].base.repo.get_commit(pull.sha)
      except GithubException as e:
        raise MetaGitException("Cannot get commit %s from %s: %s" % (pull.sha, pr, e))
    gh_commit = self.gh_commits[pull.sha]
    if not force:
      try:
        for s in gh_commit.get_statuses():
          if s.context == context:
            if s.state == state and s.description == description:
              debug("%s: %s=%s already set" % (pr, context, state))
              return
            break
      except GithubException as e:
        raise MetaGitException("Cannot verify statuses for %s on %s: %s" % (pull.sha, pr, e))
    try:
      gh_commit.create_status(state, description=description, context=context)
    except GithubException as e:
      raise MetaGitException("Cannot add state %s=%s (%s) to %s on %s: %s" % \
                             (context, state, description, pull.sha, pr, e))

  def add_comment(self, pr, comment):
    # Add a comment to a pull request
    if not self.rw:
      info("%s: not adding comment \"%s\" (dry run)" % (pr, comment))
      return
    info("%s: adding comment \"%s\"" % (pr, comment))
    self.get_pull(pr, cached=True)
    try:
      self.gh_pulls[pr].create_issue_comment(comment)
    except GithubException as e:
      raise MetaGitException("Cannot create comment %s on %s: %s" % (comment, pr, e))

  def get_comments(self, pr):
    # Gets all comments in a pull request. Based on generators
    self.get_pull(pr, cached=True)
    try:
      for c in self.gh_pulls[pr].get_issue_comments():
        cn = namedtuple("MetaComment", ["body", "firstline", "who", "when"])
        cn.body  = c.body
        cn.short = cn.body.split("\n", 1)[0].strip()
        cn.who   = c.user.login
        cn.when  = c.created_at
        yield cn
    except GithubException as e:
      raise MetaGitException("Cannot get comments for %s: %s" % (pr, e))

  def merge(self, pr):
    # Merge a pull request
    if not self.rw:
      info("%s: not merging (dry run)" % pr)
      return
    info("%s: merging" % pr)
    self.get_pull(pr, cached=True)
    try:
      self.gh_pulls[pr].merge()
    except GithubException as e:
      raise MetaGitException("Cannot merge %s: %s" % (pr, e))

  @staticmethod
  def split_repo_pr(full):
    try:
      repo,num = full.split("#", 1)
      num = int(num)
    except Exception:
      raise MetaGitException("%s: invalid format" % full)
    return repo,num

class MetaGitException(Exception):
  def __init__(self, message):
    self.message = str(message)
  def __str__(self):
    return self.message

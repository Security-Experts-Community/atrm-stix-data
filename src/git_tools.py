from datetime import datetime

import git

def get_last_commit_hash(repo_path: str):
    repo = git.Repo(repo_path)
    return repo.commit("main").hexsha[:7]

def get_file_creation_date(repo_path: str, file_path: str) -> datetime:
    repo = git.Repo(repo_path)
    commits = list(repo.iter_commits(paths=file_path))
    if commits and len(commits):
        return commits[-1].committed_datetime
    return None


def get_file_modification_date(repo_path: str, file_path: str) -> datetime:
    repo = git.Repo(repo_path)
    commits = list(repo.iter_commits(paths=file_path))
    if commits and len(commits):
        return commits[0].committed_datetime
    return None

from dataclasses import dataclass
import logging
import os
import subprocess
import threading

from saq.constants import CONFIG_GIT, CONFIG_GIT_REPOS
from saq.service import ACEServiceInterface


@dataclass
class GitRepo:
    name: str # the name of the repo
    description: str # the description of the repo
    local_path: str # the local path to the repo
    git_url: str # the git url of the repo
    update_frequency: int # the frequency to update the repo in seconds
    branch: str # the branch to use for the repo

def get_configured_repos() -> list[GitRepo]:
    from saq.configuration.config import get_config
    result: list[GitRepo] = []
    for git_repo_dict in get_config().get(CONFIG_GIT, CONFIG_GIT_REPOS):
        result.append(GitRepo(
            name=git_repo_dict.get("name"),
            description=git_repo_dict.get("description"),
            local_path=git_repo_dict.get("local_path"),
            git_url=git_repo_dict.get("git_url"),
            update_frequency=git_repo_dict.get("update_frequency"),
            branch=git_repo_dict.get("branch"),
        ))

    return result

def repo_exists(target_path: str) -> bool:
    """Returns True if the repo exists at the given path, False otherwise."""
    return os.path.isdir(os.path.join(target_path, ".git"))

def get_repo_branch(local_path: str) -> str:
    """Returns the branch of the repo at the given path."""
    if not repo_exists(local_path):
        raise RuntimeError(f"repo {local_path} does not exist")

    process = subprocess.Popen(["git", "-C", local_path, "rev-parse", "--abbrev-ref", "HEAD"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"failed to get branch of repo {local_path}: {stderr}")

    return stdout.strip()

def clone_repo(git_url: str, local_path: str, branch: str) -> bool:
    """Clones the repo at the given URL to the given local path and branch."""
    process = subprocess.Popen(["git", "clone", git_url, local_path, "--branch", branch], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"failed to clone repo {git_url} to {local_path}: {stderr}")

    return True

def change_repo_branch(local_path: str, branch: str) -> bool:
    """Changes the branch of the repo at the given path."""
    if not repo_exists(local_path):
        raise RuntimeError(f"repo {local_path} does not exist")
    
    process = subprocess.Popen(["git", "-C", local_path, "checkout", branch], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"failed to change branch of repo {local_path} to {branch}: {stderr}")

    return True

def repo_is_up_to_date(git_url: str, local_path: str, branch: str) -> bool:
    """Returns True if the repo is up to date, False otherwise."""
    process = subprocess.Popen(["git", "-C", local_path, "status", "--porcelain"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"failed to check if repo {local_path} is up to date: {stderr}")

    return stdout.strip() == ""

def pull_repo(git_url: str, local_path: str, branch: str) -> bool:
    """Pulls the latest changes from the given URL to the given local path and branch."""
    process = subprocess.Popen(["git", "-C", local_path, "pull", git_url, branch], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"failed to pull latest changes from {git_url} to {local_path}: {stderr}")

    return True

def update_repo(repo: GitRepo) -> bool:
    """Updates the given repo. Returns True if the repo was updated, False otherwise."""
    # ensure the local path exists, create it if not
    if not os.path.isdir(repo.local_path):
        logging.info(f"creating directory {repo.local_path}")
        os.makedirs(repo.local_path)

    # clone the repo if it doesn't exist
    if not repo_exists(repo.local_path):
        logging.info(f"cloning repo {repo.git_url} to {repo.local_path} branch {repo.branch}")
        return clone_repo(repo.git_url, repo.local_path, repo.branch)
    else:
        if get_repo_branch(repo.local_path) != repo.branch:
            logging.info(f"changing branch of repo {repo.local_path} to {repo.branch}")
            change_repo_branch(repo.local_path, repo.branch)

        logging.info(f"checking if repo {repo.local_path} is up to date")
        if not repo_is_up_to_date(repo.git_url, repo.local_path, repo.branch):
            logging.info(f"pulling latest changes from {repo.git_url} to {repo.local_path} branch {repo.branch}")
            return pull_repo(repo.git_url, repo.local_path, repo.branch)
        else:
            return False

class GitManagerService(ACEServiceInterface):
    def __init__(self):
        super().__init__()
        self.started_event = threading.Event()
        self.shutdown_event = threading.Event()
        self.threads: dict[str, threading.Thread] = {}

    def start(self):
        self.started_event.clear()
        self.shutdown_event.clear()
        for repo in get_configured_repos():
            self.start_thread(repo)

        self.started_event.set()
        return True

    def start_thread(self, repo: GitRepo):
        self.threads[repo.name] = threading.Thread(target=self.run, args=(repo,))
        self.threads[repo.name].daemon = True
        self.threads[repo.name].start()

    def run(self, repo: GitRepo):
        while not self.shutdown_event.is_set():
            update_repo(repo)
            self.shutdown_event.wait(repo.update_frequency)

    def start_single_threaded(self):
        for repo in get_configured_repos():
            self.run(repo)

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.git_manager.wait_for_start(timeout)

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        for repo_name, thread in self.threads.items():
            logging.info(f"waiting for git repo manager thread {repo_name} to finish")
            thread.join()
            logging.info(f"git repo manager thread {repo_name} finished")

    
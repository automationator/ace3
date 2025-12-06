from dataclasses import dataclass
import logging
import os
import subprocess
import threading
from typing import Optional, Type

from saq.configuration.schema import ServiceConfig
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
    ssh_key_path: Optional[str] = None # optional path to an ssh key to use for the repo

    @property
    def env(self) -> dict:
        result = {}

        if self.ssh_key_path:
            # see https://stackoverflow.com/questions/4565700/how-to-specify-the-private-ssh-key-to-use-when-executing-shell-command-on-git#comment105376577_29754018
            result["GIT_SSH_COMMAND"] = f"ssh -i {self.ssh_key_path} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"

        return result

    def clone_exists(self) -> bool:
        """Returns True if the local repo clone exists at local_path, False otherwise."""
        return os.path.isdir(os.path.join(self.local_path, ".git"))

    def clone_repo(self) -> bool:
        """Clones the repo at the given URL to the given local path and branch."""
        process = subprocess.Popen(["git", "clone", self.git_url, self.local_path, "--branch", self.branch], 
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"failed to clone repo {self.git_url} to {self.local_path}: {stderr}")

        return True

    def get_repo_branch(self) -> str:
        """Returns the branch of the repo at the given path."""
        if not self.clone_exists():
            raise RuntimeError(f"repo {self.local_path} does not exist")

        process = subprocess.Popen(["git", "-C", self.local_path, "rev-parse", "--abbrev-ref", "HEAD"], 
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"failed to get branch of repo {self.local_path}: {stderr}")

        return stdout.strip()

    def change_repo_branch(self, branch: str) -> bool:
        """Changes the branch of the repo at the given path."""
        if not self.clone_exists():
            raise RuntimeError(f"repo {self.local_path} does not exist")
        
        process = subprocess.Popen(["git", "-C", self.local_path, "checkout", branch], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"failed to change branch of repo {self.local_path} to {branch}: {stderr}")

        return True

    def repo_is_up_to_date(self) -> bool:
        """Returns True if the repo is up to date, False otherwise."""
        if not self.clone_exists():
            return False

        # fetch remote first
        process = subprocess.Popen(["git", "-C", self.local_path, "fetch", "--all"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"failed to fetch remote of repo {self.local_path}: {stderr}")

        # check if there are local changes (dirty working tree, staged changes, untracked files)
        process = subprocess.Popen(["git", "-C", self.local_path, "status", "--porcelain"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"failed to check if repo {self.local_path} is up to date: {stderr}")

        # if there are local changes, repo is not up to date
        if stdout.strip() != "":
            return False

        # check if local branch is behind remote branch
        remote_branch = f"origin/{self.branch}"
        process = subprocess.Popen(["git", "-C", self.local_path, "rev-list", "--count", f"HEAD..{remote_branch}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            # if remote branch doesn't exist or other error, assume up to date
            return True

        # if there are commits on remote that we don't have locally, we're behind
        commits_behind = int(stdout.strip())
        return commits_behind == 0

    def pull_repo(self) -> bool:
        """Pulls the latest changes from the given URL to the given local path and branch."""
        process = subprocess.Popen(["git", "-C", self.local_path, "pull", self.git_url, self.branch], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"failed to pull latest changes from {self.git_url} to {self.local_path}: {stderr}")

        return True

    def update(self) -> bool:
        """Updates the repo. Returns True if the repo was updated, False otherwise."""
        # ensure the local path exists, create it if not
        if not os.path.isdir(self.local_path):
            logging.info(f"creating directory {self.local_path}")
            os.makedirs(self.local_path)

        # clone the repo if it doesn't exist
        if not self.clone_exists():
            logging.info(f"cloning repo {self.git_url} to {self.local_path} branch {self.branch}")
            return self.clone_repo()
        else:
            if self.get_repo_branch() != self.branch:
                logging.info(f"changing branch of repo {self.local_path} to {self.branch}")
                self.change_repo_branch(self.branch)

            logging.info(f"checking if repo {self.local_path} is up to date")
            if not self.repo_is_up_to_date():
                logging.info(f"pulling latest changes from {self.git_url} to {self.local_path} branch {self.branch}")
                return self.pull_repo()
            else:
                return False

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
            ssh_key_path=git_repo_dict.get("ssh_key_path"),
        ))

    return result

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
            repo.update()
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

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ServiceConfig

    
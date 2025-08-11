import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from saq.git import (
    GitRepo,
    get_configured_repos,
    repo_exists,
    get_repo_branch,
    clone_repo,
    change_repo_branch,
    repo_is_up_to_date,
    pull_repo,
    update_repo,
)


@pytest.mark.unit
class TestGitRepo:
    def test_gitrepo_creation(self):
        repo = GitRepo(
            local_path="/path/to/repo",
            git_url="https://github.com/user/repo.git",
            update_frequency=3600,
            enabled=True,
            branch="main"
        )
        
        assert repo.local_path == "/path/to/repo"
        assert repo.git_url == "https://github.com/user/repo.git"
        assert repo.update_frequency == 3600
        assert repo.enabled is True
        assert repo.branch == "main"

    def test_gitrepo_dataclass_equality(self):
        repo1 = GitRepo(
            local_path="/path/to/repo",
            git_url="https://github.com/user/repo.git",
            update_frequency=3600,
            enabled=True,
            branch="main"
        )
        
        repo2 = GitRepo(
            local_path="/path/to/repo",
            git_url="https://github.com/user/repo.git",
            update_frequency=3600,
            enabled=True,
            branch="main"
        )
        
        assert repo1 == repo2

    def test_gitrepo_dataclass_inequality(self):
        repo1 = GitRepo(
            local_path="/path/to/repo1",
            git_url="https://github.com/user/repo1.git",
            update_frequency=3600,
            enabled=True,
            branch="main"
        )
        
        repo2 = GitRepo(
            local_path="/path/to/repo2",
            git_url="https://github.com/user/repo2.git",
            update_frequency=7200,
            enabled=False,
            branch="develop"
        )
        
        assert repo1 != repo2


@pytest.mark.unit
class TestRepoExists:
    def test_repo_exists_true(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        git_dir = repo_path.mkdir(".git")
        
        assert repo_exists(str(repo_path)) is True

    def test_repo_exists_false_no_git_dir(self, tmpdir):
        repo_path = tmpdir.mkdir("not_a_repo")
        
        assert repo_exists(str(repo_path)) is False

    def test_repo_exists_false_nonexistent_path(self, tmpdir):
        nonexistent_path = str(tmpdir.join("nonexistent"))
        
        assert repo_exists(nonexistent_path) is False


@pytest.mark.integration
class TestGetRepoBranch:
    def setup_test_repo(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)
        
        test_file = repo_path.join("test.txt")
        test_file.write("initial content")
        
        subprocess.run(["git", "add", "test.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True)
        
        return str(repo_path)

    def test_get_repo_branch_main(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        subprocess.run(["git", "checkout", "-b", "main"], cwd=repo_path, check=True)
        
        branch = get_repo_branch(repo_path)
        
        assert branch == "main"

    def test_get_repo_branch_develop(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        subprocess.run(["git", "checkout", "-b", "develop"], cwd=repo_path, check=True)
        
        branch = get_repo_branch(repo_path)
        
        assert branch == "develop"

    def test_get_repo_branch_master_default(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        
        branch = get_repo_branch(repo_path)
        
        assert branch in ["master", "main"]

    def test_get_repo_branch_nonexistent_repo(self, tmpdir):
        nonexistent_path = str(tmpdir.join("nonexistent"))
        
        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            get_repo_branch(nonexistent_path)

    def test_get_repo_branch_invalid_repo(self, tmpdir):
        not_a_repo = tmpdir.mkdir("not_a_repo")
        
        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            get_repo_branch(str(not_a_repo))


@pytest.mark.integration
class TestCloneRepo:
    def setup_remote_repo(self, tmpdir):
        remote_path = tmpdir.mkdir("remote_repo")
        
        subprocess.run(["git", "init", "--bare"], cwd=str(remote_path), check=True)
        
        temp_clone = tmpdir.mkdir("temp_clone")
        subprocess.run(["git", "clone", str(remote_path), str(temp_clone)], check=True)
        
        test_file = temp_clone.join("test.txt")
        test_file.write("test content")
        
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_clone), check=True)
        
        subprocess.run(["git", "checkout", "-b", "test-branch"], cwd=str(temp_clone), check=True)
        branch_file = temp_clone.join("branch.txt")
        branch_file.write("branch content")
        subprocess.run(["git", "add", "branch.txt"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Branch commit"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "push", "origin", "test-branch"], cwd=str(temp_clone), check=True)
        
        return str(remote_path)

    def test_clone_repo_success_default_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("cloned_repo"))
        
        result = clone_repo(remote_path, local_path, "master")
        
        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))
        assert os.path.exists(os.path.join(local_path, "test.txt"))

    def test_clone_repo_success_specific_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("cloned_repo"))
        
        result = clone_repo(remote_path, local_path, "test-branch")
        
        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))
        assert os.path.exists(os.path.join(local_path, "branch.txt"))

    def test_clone_repo_failure_invalid_url(self, tmpdir):
        local_path = str(tmpdir.join("cloned_repo"))
        invalid_url = "https://invalid-url-that-does-not-exist.com/repo.git"
        
        with pytest.raises(RuntimeError, match="failed to clone repo"):
            clone_repo(invalid_url, local_path, "main")

    def test_clone_repo_failure_invalid_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("cloned_repo"))
        
        with pytest.raises(RuntimeError, match="failed to clone repo"):
            clone_repo(remote_path, local_path, "nonexistent-branch")


@pytest.mark.integration
class TestChangeRepoBranch:
    def setup_multi_branch_repo(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)
        
        test_file = repo_path.join("test.txt")
        test_file.write("initial content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True)
        
        subprocess.run(["git", "checkout", "-b", "develop"], cwd=str(repo_path), check=True)
        dev_file = repo_path.join("dev.txt")
        dev_file.write("dev content")
        subprocess.run(["git", "add", "dev.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Dev commit"], cwd=str(repo_path), check=True)
        
        subprocess.run(["git", "checkout", "master"], cwd=str(repo_path), check=True)
        
        return str(repo_path)

    def test_change_repo_branch_success(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)
        
        assert get_repo_branch(repo_path) == "master"
        
        result = change_repo_branch(repo_path, "develop")
        
        assert result is True
        assert get_repo_branch(repo_path) == "develop"
        assert os.path.exists(os.path.join(repo_path, "dev.txt"))

    def test_change_repo_branch_same_branch(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)
        
        assert get_repo_branch(repo_path) == "master"
        
        result = change_repo_branch(repo_path, "master")
        
        assert result is True
        assert get_repo_branch(repo_path) == "master"

    def test_change_repo_branch_nonexistent_branch(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)
        
        with pytest.raises(RuntimeError, match="failed to change branch"):
            change_repo_branch(repo_path, "nonexistent-branch")

    def test_change_repo_branch_nonexistent_repo(self, tmpdir):
        nonexistent_path = str(tmpdir.join("nonexistent"))
        
        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            change_repo_branch(nonexistent_path, "main")

    def test_change_repo_branch_invalid_repo(self, tmpdir):
        not_a_repo = tmpdir.mkdir("not_a_repo")
        
        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            change_repo_branch(str(not_a_repo), "main")

    def test_change_repo_branch_remote_tracking(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)
        
        subprocess.run(["git", "checkout", "-b", "feature"], cwd=repo_path, check=True)
        feature_file = Path(repo_path) / "feature.txt"
        feature_file.write_text("feature content")
        subprocess.run(["git", "add", "feature.txt"], cwd=repo_path, check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Feature commit"], cwd=repo_path, check=True)
        
        subprocess.run(["git", "checkout", "master"], cwd=repo_path, check=True)
        
        result = change_repo_branch(repo_path, "feature")
        
        assert result is True
        assert get_repo_branch(repo_path) == "feature"
        assert os.path.exists(os.path.join(repo_path, "feature.txt"))


@pytest.mark.integration
class TestRepoIsUpToDate:
    def setup_test_repo(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)
        
        test_file = repo_path.join("test.txt")
        test_file.write("initial content")
        
        subprocess.run(["git", "add", "test.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True)
        
        return str(repo_path)

    def test_repo_is_up_to_date_clean_working_tree(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        
        result = repo_is_up_to_date("dummy_url", repo_path, "master")
        
        assert result is True

    def test_repo_is_up_to_date_dirty_working_tree(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        
        test_file = Path(repo_path) / "test.txt"
        test_file.write_text("modified content")
        
        result = repo_is_up_to_date("dummy_url", repo_path, "master")
        
        assert result is False

    def test_repo_is_up_to_date_untracked_files(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        
        new_file = Path(repo_path) / "new.txt"
        new_file.write_text("new content")
        
        result = repo_is_up_to_date("dummy_url", repo_path, "master")
        
        assert result is False

    def test_repo_is_up_to_date_staged_changes(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        
        new_file = Path(repo_path) / "staged.txt"
        new_file.write_text("staged content")
        subprocess.run(["git", "add", "staged.txt"], cwd=repo_path, check=True)
        
        result = repo_is_up_to_date("dummy_url", repo_path, "master")
        
        assert result is False

    def test_repo_is_up_to_date_invalid_repo_path(self, tmpdir):
        invalid_path = str(tmpdir.join("nonexistent"))
        
        with pytest.raises(RuntimeError, match="failed to check if repo"):
            repo_is_up_to_date("dummy_url", invalid_path, "master")


@pytest.mark.integration
class TestPullRepo:
    def setup_remote_and_local_repos(self, tmpdir):
        remote_path = tmpdir.mkdir("remote_repo")
        subprocess.run(["git", "init", "--bare"], cwd=str(remote_path), check=True)
        
        temp_setup = tmpdir.mkdir("temp_setup")
        subprocess.run(["git", "clone", str(remote_path), str(temp_setup)], check=True)
        
        test_file = temp_setup.join("test.txt")
        test_file.write("initial content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        local_path = tmpdir.mkdir("local_repo")
        subprocess.run(["git", "clone", str(remote_path), str(local_path)], check=True)
        
        test_file.write("updated content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Update commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        return str(remote_path), str(local_path)

    def test_pull_repo_success(self, tmpdir):
        remote_path, local_path = self.setup_remote_and_local_repos(tmpdir)
        
        result = pull_repo(remote_path, local_path, "master")
        
        assert result is True
        
        test_file_content = Path(local_path) / "test.txt"
        assert test_file_content.read_text() == "updated content"

    def test_pull_repo_failure_invalid_repo_path(self, tmpdir):
        invalid_path = str(tmpdir.join("nonexistent"))
        
        with pytest.raises(RuntimeError, match="failed to pull latest changes"):
            pull_repo("dummy_url", invalid_path, "master")

    def test_pull_repo_failure_invalid_remote(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)
        
        with pytest.raises(RuntimeError, match="failed to pull latest changes"):
            pull_repo("https://invalid-remote.com/repo.git", str(repo_path), "master")


@pytest.mark.integration
class TestUpdateRepo:
    def setup_remote_repo(self, tmpdir):
        remote_path = tmpdir.mkdir("remote_repo")
        subprocess.run(["git", "init", "--bare"], cwd=str(remote_path), check=True)
        
        temp_setup = tmpdir.mkdir("temp_setup")
        subprocess.run(["git", "clone", str(remote_path), str(temp_setup)], check=True)
        
        test_file = temp_setup.join("test.txt")
        test_file.write("initial content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        return str(remote_path)

    def test_update_repo_clone_new_repo(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("new_repo"))
        
        repo = GitRepo(
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            enabled=True,
            branch="master"
        )
        
        result = update_repo(repo)
        
        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))
        assert os.path.exists(os.path.join(local_path, "test.txt"))

    def test_update_repo_creates_directory(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("nested", "path", "repo"))
        
        repo = GitRepo(
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            enabled=True,
            branch="master"
        )
        
        result = update_repo(repo)
        
        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))

    def test_update_repo_up_to_date_repo(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("existing_repo"))
        
        subprocess.run(["git", "clone", remote_path, local_path], check=True)
        
        repo = GitRepo(
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            enabled=True,
            branch="master"
        )
        
        result = update_repo(repo)
        
        assert result is False

    def test_update_repo_pull_updates(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("existing_repo"))
        
        subprocess.run(["git", "clone", remote_path, local_path], check=True)
        
        temp_update = tmpdir.mkdir("temp_update")
        subprocess.run(["git", "clone", remote_path, str(temp_update)], check=True)
        
        update_file = temp_update.join("update.txt")
        update_file.write("updated content")
        subprocess.run(["git", "add", "update.txt"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Update commit"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_update), check=True)
        
        local_file = Path(local_path) / "local_change.txt"
        local_file.write_text("local change")
        
        repo = GitRepo(
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            enabled=True,
            branch="master"
        )
        
        result = update_repo(repo)
        
        assert result is True
        assert os.path.exists(os.path.join(local_path, "update.txt"))

    def test_update_repo_switches_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("existing_repo"))
        
        subprocess.run(["git", "clone", remote_path, local_path], check=True)
        
        temp_update = tmpdir.mkdir("temp_update")
        subprocess.run(["git", "clone", remote_path, str(temp_update)], check=True)
        
        subprocess.run(["git", "checkout", "-b", "develop"], cwd=str(temp_update), check=True)
        dev_file = temp_update.join("develop.txt")
        dev_file.write("develop content")
        subprocess.run(["git", "add", "develop.txt"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Develop commit"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "push", "origin", "develop"], cwd=str(temp_update), check=True)
        
        subprocess.run(["git", "fetch", "origin", "develop"], cwd=local_path, check=True)
        
        assert get_repo_branch(local_path) == "master"
        
        repo = GitRepo(
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            enabled=True,
            branch="develop"
        )
        
        result = update_repo(repo)
        
        assert get_repo_branch(local_path) == "develop"
        assert os.path.exists(os.path.join(local_path, "develop.txt"))


@pytest.mark.unit
class TestGetConfiguredRepos:
    def test_get_configured_repos_mock_config(self, monkeypatch):
        mock_repos = [
            {
                "local_path": "/path/to/repo1",
                "git_url": "https://github.com/user/repo1.git",
                "update_frequency": 3600,
                "enabled": True,
                "branch": "main"
            },
            {
                "local_path": "/path/to/repo2",
                "git_url": "https://github.com/user/repo2.git",
                "update_frequency": 7200,
                "enabled": False,
                "branch": "develop"
            }
        ]
        
        class MockConfig:
            def get(self, section, key):
                if section == "git" and key == "repos":
                    return mock_repos
                return None
        
        def mock_get_config():
            return MockConfig()
        
        monkeypatch.setattr("saq.configuration.config.get_config", mock_get_config)
        
        repos = get_configured_repos()
        
        assert len(repos) == 2
        
        assert repos[0].local_path == "/path/to/repo1"
        assert repos[0].git_url == "https://github.com/user/repo1.git"
        assert repos[0].update_frequency == 3600
        assert repos[0].enabled is True
        assert repos[0].branch == "main"
        
        assert repos[1].local_path == "/path/to/repo2"
        assert repos[1].git_url == "https://github.com/user/repo2.git"
        assert repos[1].update_frequency == 7200
        assert repos[1].enabled is False
        assert repos[1].branch == "develop"

    def test_get_configured_repos_empty_config(self, monkeypatch):
        class MockConfig:
            def get(self, section, key):
                if section == "git" and key == "repos":
                    return []
                return None
        
        def mock_get_config():
            return MockConfig()
        
        monkeypatch.setattr("saq.configuration.config.get_config", mock_get_config)
        
        repos = get_configured_repos()
        
        assert len(repos) == 0
        assert repos == []
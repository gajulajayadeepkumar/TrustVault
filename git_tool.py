"""
Git Helper Utility using Dulwich for TrustVault
Provides Git CLI-like functionality: init, add, commit, log, status.
"""
import sys
import os
import time
from dulwich import porcelain

REPO_PATH = os.path.dirname(os.path.abspath(__file__))

def init_repo():
    if not os.path.exists(os.path.join(REPO_PATH, ".git")):
        porcelain.init(REPO_PATH)
        print(f"Initialized empty Git repository in {REPO_PATH}")
    else:
        print(f"Git repository already initialized in {REPO_PATH}")

def add_all():
    porcelain.add(REPO_PATH)
    print("Staged all files.")

def commit(message: str, author: str = "TrustVault Developer <developer@trustvault.local>"):
    add_all()
    commit_sha = porcelain.commit(
        REPO_PATH,
        message=message.encode("utf-8"),
        author=author.encode("utf-8"),
        committer=author.encode("utf-8")
    )
    sha_hex = commit_sha.decode("utf-8") if isinstance(commit_sha, bytes) else str(commit_sha)
    print(f"Committed: [{sha_hex[:7]}] {message}")
    return sha_hex

def log():
    from dulwich.repo import Repo
    repo = Repo(REPO_PATH)
    walker = repo.get_walker(max_entries=10)
    for entry in walker:
        c = entry.commit
        msg = c.message.decode("utf-8").strip() if isinstance(c.message, bytes) else str(c.message).strip()
        sha = c.id.decode("utf-8") if isinstance(c.id, bytes) else str(c.id)
        print(f"{sha[:7]} - {msg}")

def status():
    status = porcelain.status(REPO_PATH)
    print(f"Staged: {status.staged}")
    print(f"Unstaged: {status.unstaged}")
    print(f"Untracked: {status.untracked}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python git_tool.py [init|add|commit <msg>|log|status]")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    if cmd == "init":
        init_repo()
    elif cmd == "add":
        add_all()
    elif cmd == "commit":
        msg = sys.argv[2] if len(sys.argv) > 2 else f"Update {time.strftime('%Y-%m-%d %H:%M:%S')}"
        commit(msg)
    elif cmd == "log":
        log()
    elif cmd == "status":
        status()
    else:
        print(f"Unknown command: {cmd}")

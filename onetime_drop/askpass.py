#!/usr/bin/python3
"""SSH_ASKPASS helper for action links.

ssh runs this with the prompt as argv[1]. The secret comes from an environment variable that
exists only in the environment of that one ssh child process (and therefore this helper). It is
answered only for password prompts; host-key or other questions are refused. ssh is started with
NumberOfPasswordPrompts=1, so a wrong password is never retried.
"""
import os
import sys

ENV = "ONETIME_DROP_ASKPASS_SECRET"


def main() -> int:
    prompt = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
    secret = os.environ.get(ENV, "")
    if not secret or "password" not in prompt:
        return 1
    sys.stdout.write(secret + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())

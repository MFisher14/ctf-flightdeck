"""The release the fake reports: FAKE_SAGE_VERSION, set by the stub that starts the worker."""
import os

version = os.environ.get("FAKE_SAGE_VERSION", "10.7")

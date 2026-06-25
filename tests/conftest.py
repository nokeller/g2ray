import os
import tempfile

os.environ.setdefault("G2RECON_DATA_DIR", tempfile.mkdtemp(prefix="g2recon-tests-"))
os.environ.setdefault("G2RECON_ADMIN_PASSWORD", "test-password")

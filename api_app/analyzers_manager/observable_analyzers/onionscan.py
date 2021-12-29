# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import subprocess
from shutil import which

# celery exceptions
from celery.exceptions import SoftTimeLimitExceeded

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException

# test mocks
from tests.mock_utils import MockPopen, patch

logger = logging.getLogger(__name__)


class OnionScan(classes.ObservableAnalyzer):
    """
    check a .onion domain for privacy misconfigurations and info leaks.
    """

    onionscan_binary: str = "/opt/deploy/bundled/onionscan"
    _verbose: bool = True
    _tor_proxy_address: str = None

    def set_params(self, params):
        self._verbose = params.get("verbose", True)
        self._tor_proxy_address = params.get("torProxyAddress", None)

    def run(self):
        """
        Run Onionscan against target onion domain
        """
        # Check for onionscan binary in path/pwd.
        if which("onionscan"):
            self.onionscan_binary = "onionscan"
        if not which(self.onionscan_binary):
            raise AnalyzerRunException("onionscan is not installed!")
        # Generate the subprocess command args
        command = [self.onionscan_binary, "--jsonReport", self.observable_name]
        if self._verbose:
            command.append("--verbose")
        if self._tor_proxy_address:
            command.append(f"--torProxyAddress={self._tor_proxy_address}")
        # Open a pipe to onionscan process
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # read all std communication
            outs, errs = [std.decode("utf-8") for std in process.communicate()]
            if errs != "":
                raise AnalyzerRunException(f"onionscan error: {str(errs)}.")
            # load stdout json and return to user
            logger.info("onionscan output: \n%s" % outs)
            onionscan_json_report = json.loads(outs)
            # return report to user
            return onionscan_json_report
        except subprocess.SubprocessError as exc:
            raise AnalyzerRunException(
                f"error spwaning onionscan process. error: {str(exc)}"
            )
        except json.decoder.JSONDecodeError as exc:
            raise AnalyzerRunException(
                f"error reading onionscan output json. error: {str(exc)}"
            )
        except SoftTimeLimitExceeded as exc:
            # handle celery timeout
            self._handle_exception(exc)
            if process:
                process.kill()

    @classmethod
    def _monkeypatch(cls):
        patches = [patch("subprocess.Popen", return_value=MockPopen())]
        return super()._monkeypatch(patches=patches)

#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import re
import sys
import time

from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import getSQLSnippet
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.shell import autoCompletion
from lib.request import inject
from lib.takeover.udf import UDF
from lib.takeover.web import Web
from lib.takeover.xp_cmdshell import XP_cmdshell
from lib.utils.safe2bin import safechardecode
from thirdparty.six.moves import input as _input

class Abstraction(Web, UDF, XP_cmdshell):
    """
    This class defines an abstraction layer for OS takeover functionalities
    to UDF / XP_cmdshell objects
    """

    def __init__(self):
        self.envInitialized = False
        self.alwaysRetrieveCmdOutput = False

        UDF.__init__(self)
        Web.__init__(self)
        XP_cmdshell.__init__(self)

    def execCmd(self, cmd, silent=False):
        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            self.udfExecCmd(cmd, silent=silent)

        elif Backend.isDbms(DBMS.MSSQL):
            self.xpCmdshellExecCmd(cmd, silent=silent)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

    def evalCmd(self, cmd, first=None, last=None):
        retVal = None

        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            retVal = self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            retVal = self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            retVal = self.udfEvalCmd(cmd, first, last)

        elif Backend.isDbms(DBMS.MSSQL):
            retVal = self.xpCmdshellEvalCmd(cmd, first, last)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

        return safechardecode(retVal)

    def runCmd(self, cmd):
        choice = None

        if not self.alwaysRetrieveCmdOutput:
            message = "do you want to retrieve the command standard "
            message += "output? [Y/n/a] "
            choice = readInput(message, default='Y').upper()

            if choice == 'A':
                self.alwaysRetrieveCmdOutput = True

        if choice == 'Y' or self.alwaysRetrieveCmdOutput:
            output = self.evalCmd(cmd)

            if output:
                conf.dumper.string("command standard output", output)
            else:
                dataToStdout("No output\n")
        else:
            self.execCmd(cmd)

    def shell(self):
        if self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            infoMsg = "calling OS shell. To quit type "
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        else:
            if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                infoMsg = "going to use 'COPY ... FROM PROGRAM ...' "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                infoMsg = "going to use injected user-defined functions "
                infoMsg += "'sys_eval' and 'sys_exec' for operating system "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.isDbms(DBMS.MSSQL):
                infoMsg = "going to use extended procedure 'xp_cmdshell' for "
                infoMsg += "operating system command execution"
                logger.info(infoMsg)

            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise SqlmapUnsupportedFeatureException(errMsg)

            infoMsg = "calling %s OS shell. To quit type " % (Backend.getOs() or "Windows")
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        autoCompletion(AUTOCOMPLETE_TYPE.OS, OS.WINDOWS if Backend.isOs(OS.WINDOWS) else OS.LINUX)

        # ===================================================================
        # GhostMap 2026 OS Shell
        # ===================================================================
        # Improvements over the upstream sqlmap shell:
        #   - Pre-flight passive environment fingerprint (saves typing the
        #     first 4-5 commands of every engagement and produces report-
        #     ready context).
        #   - Pre-execution preview of every command (operator sees what
        #     will run and can abort before committing).
        #   - Confirmation prompt for dangerous commands (rm -rf, format,
        #     dd, mkfs, etc.) -- protects YOU from typo'd commands on a
        #     real client system.
        #   - !save / !transcript / !hist / !replay / !probe / !info / ?
        #     special commands.
        #   - Branded prompt with DBMS, OS, user, and RCE method in use.
        #   - Better Ctrl-C handling (aborts current line, not the shell).
        #   - Caught command exceptions don't kill the session.
        # ===================================================================

        _gm_dbms = Backend.getDbms() or "?"
        _gm_os_label = Backend.getOs() or "Windows"
        _gm_is_win = _gm_os_label.lower().startswith("win")

        # Identify which RCE method is in use, for prompt + report
        try:
            if self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
                _gm_method = "web-backdoor"
            elif Backend.isDbms(DBMS.MYSQL) or Backend.isDbms(DBMS.PGSQL):
                _gm_method = "udf-sys_exec"
            elif Backend.isDbms(DBMS.MSSQL):
                _gm_method = "xp_cmdshell"
            else:
                _gm_method = "auto"
        except Exception:
            _gm_method = "auto"

        # Color helpers
        _RESET = "\033[0m"
        _DIM = "\033[01;30m"
        _BOLD = "\033[01;37m"
        _RED = "\033[01;31m"
        _GREEN = "\033[01;32m"
        _YELLOW = "\033[01;33m"
        _BLUE = "\033[01;34m"
        _CYAN = "\033[01;36m"
        _prompt_main = _RED if _gm_is_win else _GREEN

        # ----------- Pre-flight environment fingerprint -----------
        # GhostMap v5: detect blind technique and skip the heavy fingerprint.
        # In time-based or boolean-blind, each multi-line probe takes
        # minutes to retrieve. We default to NO heavy fingerprint and
        # offer !quick (IP correlation only, ~5s) or !probe (full).
        try:
            from lib.core.preshell import (
                run_probes, format_summary,
                correlate_ip_only, is_blind_technique,
                detect_web_server_location, format_web_location_panel,
            )

            _gm_blind = is_blind_technique()
            if _gm_blind:
                dataToStdout("\n%s[!]%s blind technique detected -- heavy "
                             "environment fingerprint would be very slow.\n" %
                             (_YELLOW, _RESET))
                dataToStdout("%s    Type %s!quick%s for IP correlation only "
                             "(~5s), or %s!probe%s for full fingerprint.\n%s" %
                             (_DIM, _CYAN, _DIM, _CYAN, _DIM, _RESET))
                # Run only the quick IP correlation -- 1 probe, 1 line.
                try:
                    _gm_probe_results = correlate_ip_only(self.evalCmd, _gm_os_label)
                except Exception:
                    _gm_probe_results = []
            else:
                dataToStdout("\n%s[*]%s running passive environment "
                             "fingerprint (read-only)...\n" %
                             (_CYAN, _RESET))
                _gm_probe_results = run_probes(self.evalCmd, _gm_os_label)
                dataToStdout(format_summary(_gm_probe_results, _gm_os_label))
        except Exception as _gm_ex:
            logger.debug("GhostMap pre-shell probes skipped: %s" % _gm_ex)
            _gm_probe_results = []
            _gm_blind = False

        # ----------- Shell help banner -----------
        dataToStdout("%s+--[ GhostMap OS Shell ]%s\n" % (_DIM, _RESET))
        dataToStdout("%s|%s  DBMS: %s%s%s   OS: %s%s%s   RCE method: %s%s%s\n" %
                     (_DIM, _RESET, _BOLD, _gm_dbms, _RESET,
                      _BOLD, _gm_os_label, _RESET,
                      _YELLOW, _gm_method, _RESET))
        dataToStdout("%s|%s\n" % (_DIM, _RESET))
        dataToStdout("%s|%s  Special commands:\n" % (_DIM, _RESET))
        dataToStdout("%s|%s    %s?%s | %shelp%s          show full help\n" %
                     (_DIM, _RESET, _CYAN, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!info%s              show target context\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!quick%s             quick IP correlation only (~5s)\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!probe%s             full environment fingerprint\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!web-loc%s           detect if RCE host == web server\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!ip%s                IP correlation summary\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!last%s              re-show last command output (no re-exec)\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!note <text>%s       append timestamped note to transcript\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!transcript on/off%s toggle session recording (ON by default)\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!save <cmd>%s        run cmd & save output to file\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!hist [text]%s       show / search history\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!noconfirm%s         skip command preview (DANGER)\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %s!clear%s             clear screen\n" %
                     (_DIM, _RESET, _CYAN, _RESET))
        dataToStdout("%s|%s    %sx%s | %sq%s | %sexit%s    exit shell\n" %
                     (_DIM, _RESET, _CYAN, _RESET, _CYAN, _RESET, _CYAN, _RESET))
        dataToStdout("%s+--%s\n\n" % (_DIM, _RESET))

        # ----------- Shell session state -----------
        _gm_cmd_count = 0
        _gm_history = []          # list of executed commands
        _gm_transcript = None     # file handle if transcript on
        _gm_skip_preview = False  # toggled by !noconfirm
        _gm_last_output = ""      # captured for !last
        _gm_last_cmd = ""

        # ----------- Auto-open transcript (v5: ON by default) -----------
        try:
            import os as _os, datetime as _dt
            from lib.core.data import paths
            _ts = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            _tdir = paths.SQLMAP_OUTPUT_PATH
            try:
                if not _os.path.isdir(_tdir):
                    _os.makedirs(_tdir)
            except OSError:
                _tdir = _os.path.expanduser("~")
            _tpath = _os.path.join(_tdir, "ghostmap-shell-%s.log" % _ts)
            _gm_transcript = open(_tpath, "w")
            _gm_transcript.write("# GhostMap shell transcript (auto-opened)\n")
            _gm_transcript.write("# Started: %s UTC\n" % _ts)
            _gm_transcript.write("# DBMS: %s | OS: %s | method: %s\n\n" %
                                 (_gm_dbms, _gm_os_label, _gm_method))
            _gm_transcript.flush()
            dataToStdout("%s[*]%s session transcript: %s%s%s\n" %
                         (_GREEN, _RESET, _DIM, _tpath, _RESET))
            dataToStdout("%s    Use %s!transcript off%s if you want to stop "
                         "recording.\n%s\n" %
                         (_DIM, _CYAN, _DIM, _RESET))
        except Exception as _gm_ex:
            logger.debug("GhostMap transcript auto-open skipped: %s" % _gm_ex)
            _gm_transcript = None

        # Patterns for "this command looks dangerous" check.
        # Linux: rm -rf, dd, mkfs, shred, :() fork bomb, > /dev/sda
        # Windows: format, del /f /s /q, rmdir /s
        _DANGEROUS_LINUX = [
            re.compile(r"\brm\s+(-[rRfF]+\s+)+/?"),
            re.compile(r"\bmkfs\b"),
            re.compile(r"\bdd\s+.*\bof=/dev/"),
            re.compile(r"\bshred\b"),
            re.compile(r":\(\)\s*\{\s*:\s*\|\s*:"),  # fork bomb
            re.compile(r">\s*/dev/(sd[a-z]|nvme|hd[a-z])"),
            re.compile(r"\bchmod\s+(-R\s+)?[0-7]?777\s+/"),
        ]
        _DANGEROUS_WIN = [
            re.compile(r"\bformat\s+[a-z]:", re.I),
            re.compile(r"\bdel\s+/[fsq]+\s", re.I),
            re.compile(r"\brmdir\s+/s", re.I),
            re.compile(r"\bcipher\s+/w", re.I),
        ]

        def _is_dangerous(cmd):
            patterns = _DANGEROUS_WIN if _gm_is_win else _DANGEROUS_LINUX
            for p in patterns:
                if p.search(cmd):
                    return True
            return False

        # Use a dict for mutable state captured by closures (for !last).
        _gm_state = {"last_cmd": "", "last_output": ""}

        def _record(cmd, output=None):
            _gm_history.append(cmd)
            _gm_state["last_cmd"] = cmd
            if output is not None:
                _gm_state["last_output"] = str(output)
            if _gm_transcript and not _gm_transcript.closed:
                try:
                    _gm_transcript.write("\n$ %s\n" % cmd)
                    if output:
                        _gm_transcript.write(str(output))
                        _gm_transcript.write("\n")
                    _gm_transcript.flush()
                except Exception:
                    pass

        try:
            while True:
                command = None

                try:
                    # Branded prompt: ghostmap[mysql@linux:xp_cmdshell]#
                    _prompt = "%sghostmap%s[%s%s%s@%s%s%s:%s%s%s]%s# " % (
                        _prompt_main, _RESET,
                        _YELLOW, _gm_dbms.lower(), _RESET,
                        _BLUE, _gm_os_label.lower(), _RESET,
                        _DIM, _gm_method, _RESET,
                        "",
                    )
                    command = _input(_prompt)
                    command = getUnicode(command, encoding=sys.stdin.encoding)
                except UnicodeDecodeError:
                    pass
                except KeyboardInterrupt:
                    print()
                    logger.warning("interrupted; type 'x' or 'q' to exit the shell")
                    continue
                except EOFError:
                    print()
                    logger.info("end of input, exiting shell")
                    break

                if not command:
                    continue

                command = command.strip()

                # ============ Built-in ghostmap commands ============
                if command in ("?", "help", "!help"):
                    dataToStdout("%sGhostMap shell help:%s\n" % (_BOLD, _RESET))
                    dataToStdout("  ?, help               show this help\n")
                    dataToStdout("  !info                 target context\n")
                    dataToStdout("  !probe                re-run environment fingerprint\n")
                    dataToStdout("  !transcript on        start session recording to file\n")
                    dataToStdout("  !transcript off       stop session recording\n")
                    dataToStdout("  !save <cmd>           run cmd & save output to ./gm-out-*.txt\n")
                    dataToStdout("  !hist                 show command history\n")
                    dataToStdout("  !hist <text>          search history for <text>\n")
                    dataToStdout("  !replay <N>           re-run history entry #N\n")
                    dataToStdout("  !noconfirm            skip per-command preview (use with care)\n")
                    dataToStdout("  !confirm              re-enable per-command preview\n")
                    dataToStdout("  !clear, clear, cls    clear screen\n")
                    dataToStdout("  x, q, exit, quit      exit shell\n")
                    dataToStdout("\n  Anything else is executed as an OS command on the target.\n")
                    dataToStdout("  Dangerous commands (rm -rf, format, dd to disk, ...) require\n")
                    dataToStdout("  explicit confirmation regardless of !noconfirm setting.\n")
                    continue

                if command == "!info":
                    _user = ""
                    try:
                        _user = Backend.getCurrentUser() or ""
                    except Exception:
                        pass
                    dataToStdout("%sTarget context:%s\n" % (_BOLD, _RESET))
                    dataToStdout("  DBMS:           %s\n" % _gm_dbms)
                    dataToStdout("  OS:             %s\n" % _gm_os_label)
                    dataToStdout("  RCE method:     %s\n" % _gm_method)
                    if _user:
                        dataToStdout("  DBMS user:      %s\n" % _user)
                    dataToStdout("  Commands run:   %d\n" % _gm_cmd_count)
                    dataToStdout("  Transcript:     %s\n" %
                                 ("on -> %s" % _gm_transcript.name if _gm_transcript else "off"))
                    dataToStdout("  Preview:        %s\n" %
                                 ("OFF" if _gm_skip_preview else "on"))
                    continue

                if command == "!probe":
                    try:
                        from lib.core.preshell import run_probes, format_summary
                        results = run_probes(self.evalCmd, _gm_os_label)
                        dataToStdout(format_summary(results, _gm_os_label))
                    except Exception as ex:
                        logger.error("probe failed: %s" % ex)
                    continue

                # GhostMap v5: !quick -- IP correlation only (~5s)
                if command == "!quick":
                    try:
                        from lib.core.preshell import correlate_ip_only
                        results = correlate_ip_only(self.evalCmd, _gm_os_label)
                        for label, value in results:
                            if isinstance(value, dict):
                                for k, v in value.items():
                                    dataToStdout("  %s%s%s  %s\n" %
                                                 (_BOLD, ("%-12s" % k), _RESET, v))
                            else:
                                dataToStdout("  %s%-12s%s  %s\n" %
                                             (_BOLD, label, _RESET,
                                              (value or "n/a").strip()))
                    except Exception as ex:
                        logger.error("!quick failed: %s" % ex)
                    continue

                # GhostMap v5: !web-loc -- detect if RCE host == web server
                if command in ("!web-loc", "!webloc"):
                    try:
                        from lib.core.preshell import (detect_web_server_location,
                                                        format_web_location_panel)
                        info = detect_web_server_location(self.evalCmd, _gm_os_label)
                        dataToStdout(format_web_location_panel(info))
                        dataToStdout("\n")
                    except Exception as ex:
                        logger.error("!web-loc failed: %s" % ex)
                    continue

                # GhostMap v5: !ip -- show IP correlation summary
                if command == "!ip":
                    try:
                        from lib.core.preshell import correlate_ip_only
                        out = correlate_ip_only(self.evalCmd, _gm_os_label)
                        for label, value in out:
                            if isinstance(value, dict):
                                dataToStdout("\n  %sIP correlation%s\n" %
                                             (_BOLD, _RESET))
                                for k, v in value.items():
                                    dataToStdout("    %s%-14s%s  %s\n" %
                                                 (_DIM, k, _RESET, v))
                            else:
                                dataToStdout("  %s%-14s%s  %s\n" %
                                             (_BOLD, label, _RESET,
                                              (value or "n/a").strip()))
                        dataToStdout("\n")
                    except Exception as ex:
                        logger.error("!ip failed: %s" % ex)
                    continue

                # GhostMap v5: !last -- re-show last command output (no re-exec)
                if command == "!last":
                    if _gm_state["last_cmd"]:
                        dataToStdout("%s$ %s%s\n" % (_DIM, _gm_state["last_cmd"], _RESET))
                        dataToStdout(_gm_state["last_output"] or "")
                        dataToStdout("\n")
                    else:
                        dataToStdout("%sno previous command in this session.%s\n" %
                                     (_DIM, _RESET))
                    continue

                # GhostMap v5: !note <text> -- add timestamped note to transcript
                if command.startswith("!note"):
                    parts = command.split(None, 1)
                    note_text = parts[1] if len(parts) > 1 else ""
                    if not note_text:
                        dataToStdout("%susage: !note <text to append>%s\n" %
                                     (_DIM, _RESET))
                    elif _gm_transcript and not _gm_transcript.closed:
                        try:
                            ts_now = time.strftime("%Y-%m-%d %H:%M:%S")
                            _gm_transcript.write("\n# [NOTE %s] %s\n" %
                                                 (ts_now, note_text))
                            _gm_transcript.flush()
                            dataToStdout("%s[+] note saved to transcript%s\n" %
                                         (_GREEN, _RESET))
                        except Exception as ex:
                            logger.error("!note write failed: %s" % ex)
                    else:
                        dataToStdout("%s!note requires transcript active. Run "
                                     "%s!transcript on%s first.%s\n" %
                                     (_YELLOW, _CYAN, _YELLOW, _RESET))
                    continue

                if command.startswith("!transcript"):
                    parts = command.split(None, 1)
                    arg = parts[1].lower() if len(parts) > 1 else ""
                    if arg == "on":
                        if _gm_transcript and not _gm_transcript.closed:
                            dataToStdout("transcript already active: %s\n" % _gm_transcript.name)
                        else:
                            ts = time.strftime("%Y%m%d-%H%M%S")
                            tpath = "gm-transcript-%s.txt" % ts
                            try:
                                _gm_transcript = open(tpath, "w")
                                _gm_transcript.write("# GhostMap shell transcript\n")
                                _gm_transcript.write("# Started: %s\n" %
                                                     time.strftime("%Y-%m-%d %H:%M:%S"))
                                _gm_transcript.write("# DBMS: %s | OS: %s | method: %s\n" %
                                                     (_gm_dbms, _gm_os_label, _gm_method))
                                _gm_transcript.flush()
                                dataToStdout("%s[+]%s transcript ON -> %s\n" %
                                             (_GREEN, _RESET, tpath))
                            except Exception as ex:
                                logger.error("could not open transcript: %s" % ex)
                                _gm_transcript = None
                    elif arg == "off":
                        if _gm_transcript:
                            try:
                                _gm_transcript.close()
                            except Exception:
                                pass
                            dataToStdout("%s[+]%s transcript OFF\n" % (_GREEN, _RESET))
                            _gm_transcript = None
                        else:
                            dataToStdout("transcript was not active\n")
                    else:
                        dataToStdout("usage: !transcript on | off\n")
                    continue

                if command.startswith("!save"):
                    parts = command.split(None, 1)
                    if len(parts) < 2:
                        dataToStdout("usage: !save <command>\n")
                        continue
                    inner = parts[1]
                    ts = time.strftime("%Y%m%d-%H%M%S")
                    fname = "gm-out-%s.txt" % ts
                    try:
                        out = self.evalCmd(inner)
                        with open(fname, "w") as f:
                            f.write("# GhostMap output capture\n")
                            f.write("# Command: %s\n" % inner)
                            f.write("# Time: %s\n\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
                            f.write(str(out) if out else "(no output)\n")
                        dataToStdout("%s[+]%s output saved to %s (%d bytes)\n" %
                                     (_GREEN, _RESET, fname,
                                      len(str(out)) if out else 0))
                        _record(inner, out)
                        _gm_cmd_count += 1
                    except Exception as ex:
                        logger.error("!save failed: %s" % ex)
                    continue

                if command.startswith("!hist"):
                    parts = command.split(None, 1)
                    needle = parts[1] if len(parts) > 1 else None
                    if not _gm_history:
                        dataToStdout("history is empty\n")
                        continue
                    for i, h in enumerate(_gm_history, 1):
                        if needle and needle.lower() not in h.lower():
                            continue
                        dataToStdout("  %s%4d%s  %s\n" % (_DIM, i, _RESET, h))
                    continue

                if command.startswith("!replay"):
                    parts = command.split()
                    if len(parts) < 2 or not parts[1].isdigit():
                        dataToStdout("usage: !replay <N>\n")
                        continue
                    n = int(parts[1])
                    if 1 <= n <= len(_gm_history):
                        command = _gm_history[n - 1]
                        dataToStdout("%s[*]%s replaying: %s\n" % (_CYAN, _RESET, command))
                        # Fall through to normal execution
                    else:
                        dataToStdout("history index out of range (1-%d)\n" % len(_gm_history))
                        continue

                if command == "!noconfirm":
                    _gm_skip_preview = True
                    dataToStdout("%s[!]%s per-command preview DISABLED. "
                                 "Dangerous commands still require confirmation.\n" %
                                 (_YELLOW, _RESET))
                    continue

                if command == "!confirm":
                    _gm_skip_preview = False
                    dataToStdout("%s[+]%s per-command preview re-enabled\n" %
                                 (_GREEN, _RESET))
                    continue

                if command in ("!clear", "clear", "cls"):
                    dataToStdout("\033[2J\033[H")
                    continue

                if command.lower() in ("x", "q", "exit", "quit"):
                    if _gm_transcript:
                        try:
                            _gm_transcript.close()
                        except Exception:
                            pass
                    break

                # ============ Real OS command path ============

                # Dangerous-command check FIRST (cannot be skipped)
                if _is_dangerous(command):
                    dataToStdout("%s[!] DANGEROUS COMMAND DETECTED:%s %s\n" %
                                 (_RED, _RESET, command))
                    dataToStdout("    This command may destroy data or render the target "
                                 "unbootable.\n")
                    dataToStdout("    On a real client engagement this is almost never "
                                 "what you want.\n")
                    yn = readInput("    Are you absolutely sure? type 'YES' to confirm: ",
                                   default="N")
                    if yn != "YES":
                        dataToStdout("%s[+]%s aborted, command NOT executed\n" %
                                     (_GREEN, _RESET))
                        continue

                # Per-command preview (skippable with !noconfirm)
                if not _gm_skip_preview:
                    dataToStdout("%s[?]%s about to run on target: %s%s%s\n" %
                                 (_CYAN, _RESET, _BOLD, command, _RESET))
                    yn = readInput("    execute? [Y/n/s=skip-preview-this-session] ",
                                   default="Y").upper()
                    if yn == "N":
                        dataToStdout("%s[+]%s skipped\n" % (_GREEN, _RESET))
                        continue
                    if yn == "S":
                        _gm_skip_preview = True
                        dataToStdout("%s[!]%s preview disabled for the rest of the session\n" %
                                     (_YELLOW, _RESET))

                # Execute with timing + better error handling
                # GhostMap v5: capture output via evalCmd (returns string)
                # so we can: (a) silence the [INFO] retrieved spam, (b) show
                # a clean exit-code+time+chars line at the end, (c) save the
                # output for !last and !note.
                _gm_cmd_count += 1
                _t0 = time.time()
                _gm_cmd_timeout = 60  # seconds; configurable in future
                try:
                    # Use evalCmd to capture output silently. This bypasses
                    # the runCmd path that floods the operator with INFO
                    # retrieval lines.
                    _gm_output = None
                    try:
                        # Some DBMS/method combos: evalCmd works well
                        _gm_output = self.evalCmd(command)
                    except Exception:
                        _gm_output = None

                    # GhostMap v5: best-effort decode of Spanish/Latin Windows
                    # output. When the target is Windows in es-ES locale, the
                    # output comes back in cp850/cp1252 with bytes that don't
                    # round-trip through UTF-8 cleanly. We try to fix the
                    # most common case: tildes/eñe replaced by '?'.
                    if _gm_output and _gm_is_win:
                        try:
                            # If we got bytes, decode as cp850
                            if isinstance(_gm_output, bytes):
                                _gm_output = _gm_output.decode('cp850', errors='replace')
                            # If we got a str with mojibake from cp850-as-latin1,
                            # try to undo it.
                            elif isinstance(_gm_output, str) and "?" in _gm_output:
                                # Heuristic: try latin1 -> cp850 round trip
                                try:
                                    _candidate = _gm_output.encode('latin-1', 'ignore').decode('cp850', 'ignore')
                                    # Only use if it looks more like Spanish
                                    if any(c in _candidate for c in "áéíóúñüÁÉÍÓÚÑÜ¿¡"):
                                        _gm_output = _candidate
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    # Fallback: if evalCmd failed/returned nothing, fall back
                    # to the upstream runCmd path (which prints output as it
                    # retrieves chars).
                    if _gm_output is None or not str(_gm_output).strip():
                        self.runCmd(command)
                        _gm_output_str = ""
                    else:
                        _gm_output_str = str(_gm_output)
                        # Print the captured output cleanly, no spam.
                        dataToStdout(_gm_output_str)
                        if not _gm_output_str.endswith("\n"):
                            dataToStdout("\n")

                    _record(command, output=_gm_output_str)
                    _elapsed = time.time() - _t0

                    # Always show a discreet status footer for this command:
                    # exit code (we infer from output content), elapsed time,
                    # chars retrieved.
                    _gm_chars = len(_gm_output_str.strip()) if _gm_output_str else 0
                    _gm_exit = "ok" if _gm_chars > 0 else "empty"
                    dataToStdout("%s    [%s · %.2fs · %d chars retrieved]%s\n" %
                                 (_DIM, _gm_exit, _elapsed, _gm_chars, _RESET))

                    if _elapsed > _gm_cmd_timeout:
                        dataToStdout("%s    [!] command exceeded %ds (took %.2fs).%s\n" %
                                     (_YELLOW, _gm_cmd_timeout, _elapsed, _RESET))
                        dataToStdout("%s        Possible: hung process, interactive prompt,%s\n" %
                                     (_DIM, _RESET))
                        dataToStdout("%s        or very large output on slow oracle.%s\n" %
                                     (_DIM, _RESET))
                except KeyboardInterrupt:
                    print()
                    logger.warning("command interrupted by user")
                except Exception as _gm_ex:
                    logger.error("command execution failed: %s" % _gm_ex)
                    logger.warning("the shell session is still active; "
                                   "you can retry or run a different command")
        finally:
            if _gm_transcript:
                try:
                    _gm_transcript.close()
                except Exception:
                    pass

    def _initRunAs(self):
        if not conf.dbmsCred:
            return

        if not conf.direct and not isStackingAvailable():
            errMsg = "stacked queries are not supported hence sqlmap cannot "
            errMsg += "execute statements as another user. The execution "
            errMsg += "will continue and the DBMS credentials provided "
            errMsg += "will simply be ignored"
            logger.error(errMsg)

            return

        if Backend.isDbms(DBMS.MSSQL):
            msg = "on Microsoft SQL Server 2005 and 2008, OPENROWSET function "
            msg += "is disabled by default. This function is needed to execute "
            msg += "statements as another DBMS user since you provided the "
            msg += "option '--dbms-creds'. If you are DBA, you can enable it. "
            msg += "Do you want to enable it? [Y/n] "

            if readInput(msg, default='Y', boolean=True):
                expression = getSQLSnippet(DBMS.MSSQL, "configure_openrowset", ENABLE="1")
                inject.goStacked(expression)

        # TODO: add support for PostgreSQL
        # elif Backend.isDbms(DBMS.PGSQL):
        #     expression = getSQLSnippet(DBMS.PGSQL, "configure_dblink", ENABLE="1")
        #     inject.goStacked(expression)

    def initEnv(self, mandatory=True, detailed=False, web=False, forceInit=False):
        self._initRunAs()

        if self.envInitialized and not forceInit:
            return

        if web:
            self.webInit()
        else:
            self.checkDbmsOs(detailed)

            if mandatory and not self.isDba():
                warnMsg = "functionality requested probably does not work because "
                warnMsg += "the current session user is not a database administrator"

                if not conf.dbmsCred and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.PGSQL):
                    warnMsg += ". You can try to use option '--dbms-cred' "
                    warnMsg += "to execute statements as a DBA user if you "
                    warnMsg += "were able to extract and crack a DBA "
                    warnMsg += "password by any mean"

                logger.warning(warnMsg)

            if any((conf.osCmd, conf.osShell)) and Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                success = True
            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                success = self.udfInjectSys()

                if success is not True:
                    msg = "unable to mount the operating system takeover"
                    raise SqlmapFilePathException(msg)
            elif Backend.isDbms(DBMS.MSSQL):
                if mandatory:
                    self.xpCmdshellInit()
            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise SqlmapUnsupportedFeatureException(errMsg)

        self.envInitialized = True

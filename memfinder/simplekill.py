#!/usr/bin/env python

import psutil

from . import utils


class SimpleKill(object):

    @staticmethod
    def _find_and_kill_by_pid(pid):
        for process in psutil.process_iter():
            if isinstance(pid, list):
                if process.pid in pid:
                    process.kill()
            else:
                if process.pid == pid:
                    process.kill()
                    break

    def kill_by_pid(self, pid):
        """
        Kill a process using its PID
        :param pid: pid of the process to kill
        :type pid: int or list of int
        """
        if utils.is_valid_pid(pid):
            self._find_and_kill_by_pid(pid)


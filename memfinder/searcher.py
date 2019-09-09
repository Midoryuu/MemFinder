#!/usr/bin/env python

import os
import yara
import ntpath
import time
import psutil

from . import utils


class Searcher(object):

    @staticmethod
    def _get_rule_files(rules_folder, rule):
        if not isinstance(rules_folder, str) and not isinstance(rule, str):
            raise TypeError("Error: You must set a path containing rule files"
                            " in rules_folder or the path to a rule file in rule.")
        rule_files = {}
        if rule is not None:
            try:
                yara.compile(filepath=rule)
            except yara.Error as er:
                utils.display_warning("skipping rule {}.\n{}".format(rule, er))
                return None
            rule_files[ntpath.basename(rule)] = rule
        else:
            if ntpath.isdir(rules_folder):
                for file in os.listdir(rules_folder):
                    rule = ntpath.join(rules_folder, file)
                    if ntpath.isfile(rule) and file not in rule_files:
                        try:
                            yara.compile(filepath=rule)
                            rule_files[file] = rule
                        except yara.Error as er:
                            utils.display_warning("skipping rule {}.\n{}".format(rule, er))
        return rule_files

    def _get_all_pid(self):
        # Todo return all the working pid
        raise NotImplemented

    @staticmethod
    def _search(pid_list, rule_files, timeout):
        rules = yara.compile(filepaths=rule_files)
        pid_found = []
        matches = None
        for pid in pid_list:
            utils.display_message("PID {}:".format(pid))
            if isinstance(timeout, int):
                start = time.time()
                matches = rules.match(pid=pid, timeout=timeout)
                exec_time = time.time() - start
                utils.display_message("Execution on PID {} took {} seconds"
                                      .format(pid, exec_time))
            else:
                start = time.time()
                matches = rules.match(pid=pid)
                exec_time = time.time() - start
                utils.display_message("Execution on PID {} took {} seconds"
                                      .format(pid, exec_time))
            if len(matches) > 0:
                obj_found = {'pid': pid, 'matches': []}
                for rule in matches:
                    rule_found = {'rule file': rule.namespace,
                                  'rule name': rule.rule,
                                  'strings': []}
                    utils.display_message("Rule file: {} - Rule Name: {}"
                                          .format(rule.namespace, rule.rule))
                    i = 1
                    if len(rule.strings) > 0:
                        utils.display_message("Strings:")
                    for value in rule.strings:
                        utils.display_message("{} - Offset {}".format(i, value[0]))
                        utils.display_message("{} - String identifier {}".format(i, value[1]))
                        utils.display_message("{} - String data {}".format(i, value[2]))
                        i += 1
                        rule_found['strings'].append((value[0], value[1], value[2]))
                    obj_found['matches'].append(rule_found)
                pid_found.append(obj_found)
            else:
                utils.display_message("Nothing found.")
        return pid_found

    def search_signature_by_pid(self, pid=None, rules_folder="./", rule=None, timeout=None):
        """
        Search the signatures from rules_folder or from rule in the application with
        the pid defined by pid or in all the applications if None
        :param pid: Contain one or more pid of the applications to analyse
        :type pid: int or list of int
        :param rules_folder: Path of the folder containing the yara rules
        :type rules_folder: str
        :param rule: Path of one specific yara rule
        :type rule: str
        :param timeout: timeout for each application analysis
        :type timeout: int
        :return: A list of pid and the matches associated
        :rtype: list
        """
        rule_files = self._get_rule_files(rules_folder, rule)
        if rule_files is None or len(rule_files) < 1:
            utils.display_error("No rule file available.")
            return None
        if not utils.is_valid_pid(pid):
            return None
        pid_list = []
        if pid is None:
            pid_list = self._get_all_pid()
        else:
            if isinstance(pid, int):
                pid_list.append(pid)
            else:
                pid_list = pid
        return self._search(pid_list, rule_files, timeout)

    @staticmethod
    def _get_pid_from_name(name):
        pid = []
        for process in psutil.process_iter():
            process_name = process.name()
            process_pid = process.pid
            if isinstance(name, list):
                if process_name in name and process_pid is not None:
                    pid.append({'name': process_name, 'pid': process_pid})
            else:
                if process_name == name and process_pid is not None:
                    pid.append({'name': process_name, 'pid': process_pid})
        return pid

    def search_signature_by_name(self, name, rules_folder="./", rule=None, timeout=None):
        """
        Search the signatures from rules_folder or from rule in the application with
        the name defined in name
        :param name: Contain one or more name of the applications to analyse
        :type name: str or list of str
        :param rules_folder: Path of the folder containing the yara rules
        :type rules_folder: str
        :param rule: Path of one specific yara rule
        :type rule: str
        :param timeout: timeout for each application analysis
        :type timeout: int
        :return: A list of name and the matches associated
        :rtype: list
        """
        rule_files = self._get_rule_files(rules_folder, rule)
        if rule_files is None or len(rule_files) < 1:
            utils.display_error("No rule file available.")
            return None
        if not utils.is_valid_process_name(name):
            return None
        pid_objs = self._get_pid_from_name(name)
        if pid_objs is None or len(pid_objs) < 1:
            utils.display_error("No valid process found.")
            return None
        pid_list = [val['pid'] for val in pid_objs]
        if pid_list is None or len(pid_list) < 1:
            utils.display_error("No valid process found.")
            return None
        return self._search(pid_list, rule_files, timeout)

# File: atomicredteam_connector.py
# Copyright(c) 2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
# from atomicredteam_consts import *
import requests
import json
import git
from git import Repo
import os
import yaml
import ast
import shutil


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AtomicRedTeamConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AtomicRedTeamConnector, self).__init__()

        self._state = None
        # self._atomic_dir = '/opt/phantom/tmp/atomic_repo'

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Cloning or updating Atomic Red Team repository...")

        if os.path.exists(self._atomic_dir):
            try:
                atomic_repo = Repo(self._atomic_dir)
                if not atomic_repo.bare:
                    self.save_progress("Found existing repo. Updating from source...")
                    atomic_repo.remotes.origin.pull()
                    self.save_progress("Repo updated successfully")
                    return action_result.set_status(phantom.APP_SUCCESS)
                else:
                    self.save_progress("Found existing repo, but it was bare. Cloning again...")
                    atomic_repo.clone_from(self._base_url, self._atomic_dir)
                    self.save_progress("Repo updated successfully")
                    return action_result.set_status(phantom.APP_SUCCESS)
            except git.exc.InvalidGitRepositoryError:
                self.save_progress("Found existing directory, but invalid repo. Cloning again...")
                atomic_repo = Repo.clone_from(self._base_url, self._atomic_dir)
                self.save_progress("Repo updated successfully")
                return action_result.set_status(phantom.APP_SUCCESS)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error updating the existing atomic repo. Details: {0}".format(str(e)))
        else:
            try:
                self.save_progress("No repo found.  Creating...")
                os.mkdir(self._atomic_dir)
                atomic_repo = Repo.clone_from(self._base_url, self._atomic_dir)
                self.save_progress("Repo created successfully")
                return action_result.set_status(phantom.APP_SUCCESS)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error creating new atomic repo. Details: {0}".format(str(e)))

    def _handle_format_command(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        attack_id = param['attack_id']
        supported_os = param['supported_os']
        input_args = param.get('input_arguments', '')

        for sub_dir, dirs, files in os.walk(os.path.join(self._atomic_dir, 'atomics')):
            if attack_id in sub_dir:
                for each in files:
                    if '.yaml' in each:
                        f = open(sub_dir + '/' + each, 'r')
                        try:
                            yaml_data = yaml.load(f)
                            for each_test in yaml_data['atomic_tests']:
                                formatted_test = {'attack_technique': yaml_data['attack_technique']}
                                if supported_os in each_test['supported_platforms']:
                                    if 'input_arguments' not in each_test:
                                        if each_test['executor'].get('cleanup_command') is not None:
                                            formatted_test['executor'] = {'command': each_test['executor']['command'], 'cleanup_command': each_test['executor']['cleanup_command'], 'name': each_test['executor']['name'], 'arg_types': 'None'}  # noqa
                                        else:
                                            formatted_test['executor'] = {'command': each_test['executor']['command'], 'name': each_test['executor']['name'], 'arg_types': 'None'}
                                        action_result.add_data(formatted_test)
                                        continue
                                    if input_args == '':
                                        try:
                                            input_arguments = each_test['input_arguments']
                                        except Exception as e:
                                            return action_result.set_status(phantom.APP_ERROR, "Error using default arguments: ".format(str(e)))
                                    else:
                                        try:
                                            input_arguments = ast.literal_eval(input_args)
                                        except Exception as e:
                                            return action_result.set_status(phantom.APP_ERROR, "Error evaluating argument list as JSON: ".format(str(e)))

                                    executor = each_test['executor']['command']
                                    arg_types = []
                                    for k, v in input_arguments.iteritems():
                                        var_sub = '#{' + k + '}'
                                        if input_args == '':
                                            executor = executor.replace(var_sub, v['default'])
                                            arg_types.append(v['type'])
                                        else:
                                            executor = executor.replace(var_sub, v)

                                    if each_test['executor'].get('cleanup_command') is not None:
                                        cleanup = each_test['executor']['cleanup_command']
                                        arg_types = []
                                        for k, v in input_arguments.iteritems():
                                            var_sub = '#{' + k + '}'
                                            if input_args == '':
                                                cleanup = cleanup.replace(var_sub, v['default'])
                                                arg_types.append(v['type'])
                                            else:
                                                cleanup = cleanup.replace(var_sub, v)

                                    if each_test['executor'].get('cleanup_command') is not None:
                                        formatted_test['executor'] = {'command': executor, 'cleanup_command': cleanup, 'name': each_test['executor']['name'], 'arg_types': arg_types}  # noqa
                                    else:
                                        formatted_test['executor'] = {'command': executor, 'name': each_test['executor']['name'], 'arg_types': arg_types}
                                    action_result.add_data(formatted_test)
                        except yaml.YAMLError as e:
                            pass
                        except Exception as e:
                            return action_result.set_status(phantom.APP_ERROR, "Error adding YAML data to results: ".format(str(e)))
                            # return action_result.set_status(phantom.APP_ERROR, "Error parsing YAML file:".format(str(e)))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total tests'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_module(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        attack_id = param['attack_id']

        for sub_dir, dirs, files in os.walk(self._atomic_dir + '/atomics'):
            if attack_id in sub_dir:
                for each in files:
                    if '.yaml' in each:
                        f = open(sub_dir + '/' + each, 'r')
                        try:
                            yaml_data = yaml.load(f)
                            for each_test in yaml_data['atomic_tests']:
                                each_test['attack_technique'] = yaml_data['attack_technique']
                                action_result.add_data(each_test)
                        except yaml.YAMLError as e:
                            pass
                        except Exception as e:
                            return action_result.set_status(phantom.APP_ERROR, "Error adding YAML data to results: ".format(str(e)))
                            # return action_result.set_status(phantom.APP_ERROR, "Error parsing YAML file:".format(str(e)))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total tests'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_modules(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        for sub_dir, dirs, files in os.walk(self._atomic_dir + '/atomics'):
            for each in files:
                if '.yaml' in each:
                    f = open(sub_dir + '/' + each, 'r')
                    try:
                        yaml_data = yaml.load(f)
                        action_result.add_data(yaml_data)
                    except yaml.YAMLError as e:
                        pass
                    except Exception as e:
                        return action_result.set_status(phantom.APP_ERROR, "Error adding YAML data to results: ".format(str(e)))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total techniques'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_payload(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_name_to_get = param.get('file_name', None)
        get_all = param['get_all']
        attack_id = param['attack_id']

        for sub_dir, dirs, files in os.walk(self._atomic_dir + '/atomics'):
            if attack_id in sub_dir:
                for each in files:
                    old_path = sub_dir + '/src/'
                    new_path = '/opt/phantom/vault/tmp/'
                    if 'yaml' in each and file_name_to_get is not None:
                        try:
                            for local_dir, src_dirs, payload_names in os.walk(old_path):
                                for each_payload in payload_names:
                                    if each_payload == file_name_to_get:
                                        shutil.copy2(local_dir + '/' + file_name_to_get, new_path)
                                        vault_results = Vault.add_attachment(new_path + file_name_to_get, self.get_container_id(), file_name=file_name_to_get)
                                        vault_results['file_name'] = file_name_to_get
                                        vault_results['file_path'] = local_dir + '/' + file_name_to_get
                                        action_result.add_data(vault_results)
                                        self.save_progress("Vault_results: " + str(vault_results))
                        except Exception as e:
                            return action_result.set_status(phantom.APP_ERROR, "Error finding file and attaching to vault: ".format(str(e)))
                    if 'yaml' in each and get_all:
                        try:
                            for local_dir, src_dirs, payload_names in os.walk(old_path):
                                for each_payload in payload_names:
                                    shutil.copy2(local_dir + '/' + each_payload, new_path)
                                    vault_results = Vault.add_attachment(new_path + each_payload, self.get_container_id(), file_name=each_payload)
                                    vault_results['file_path'] = local_dir + '/' + each_payload
                                    vault_results['file_name'] = each_payload
                                    action_result.add_data(vault_results)
                                    self.save_progress("Vault_results: " + str(vault_results))
                        except Exception as e:
                            return action_result.set_status(phantom.APP_ERROR, "Error copying all files in src directory".format(str(e)))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total payloads'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_module':
            ret_val = self._handle_get_module(param)

        elif action_id == 'format_command':
            ret_val = self._handle_format_command(param)

        elif action_id == 'list_modules':
            ret_val = self._handle_list_modules(param)

        elif action_id == 'update_repo':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_payload':
            ret_val = self._handle_get_payload(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        self._base_url = config.get('base_url', 'https://github.com/redcanaryco/atomic-red-team.git')
        self._atomic_dir = os.path.join(self.get_state_dir(), 'atomic_repo')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AtomicRedTeamConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)

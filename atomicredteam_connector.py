# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from atomicredteam_consts import *
import requests
import json
import git
from git import Repo
import os
import yaml
import ast


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AtomicRedTeamConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AtomicRedTeamConnector, self).__init__()

        self._state = None
        self._atomic_dir = '/opt/phantom/tmp/atomic_repo'

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
        attack_id_file = param['attack_id'] + '.yaml'
        supported_os = param['supported_os']
        input_args = param.get('input_arguments', {})
        use_arg_defaults = param.get('use_arg_defaults', True)

        for sub_dir, dirs, files in os.walk(self._atomic_dir + '/atomics'):
            for each in files:
                if each == attack_id_file:
                    f = open(sub_dir + '/' + each, 'r')
                    try:
                        yaml_data = yaml.load(f)
                        for each_test in yaml_data['atomic_tests']:
                            formatted_test = {'attack_technique': yaml_data['attack_technique']}
                            if supported_os in each_test['supported_platforms']:
                                if use_arg_defaults:
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
                                for k, v in input_arguments.iteritems():
                                    var_sub = '#{' + k + '}'
                                    if use_arg_defaults:
                                        executor = executor.replace(var_sub, v['default'])
                                    else:
                                        executor = executor.replace(var_sub, v)

                                formatted_test['executor'] = {'command': executor, 'name': each_test['executor']['name']}
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
        attack_id_file = param['attack_id'] + '.yaml'

        for sub_dir, dirs, files in os.walk(self._atomic_dir + '/atomics'):
            for each in files:
                if each == attack_id_file:
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
                        # return action_result.set_status(phantom.APP_ERROR, "Error parsing YAML file:".format(str(e)))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total techniques'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_repo(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

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

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url', 'https://github.com/redcanaryco/atomic-red-team.git')

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

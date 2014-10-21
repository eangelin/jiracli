import urllib2
import debug
import json
import contextlib

# https://docs.atlassian.com/rpc-jira-plugin/latest/com/atlassian/jira/rpc/soap/JiraSoapService.html

def _create_action_params(field_dict):
    return [{ 'id': k, 'values': map(str, v) } for k, v in field_dict.iteritems()]

class JiraBaseError(Exception):
    pass

class RequestError(JiraBaseError):
    def __init__(self, code, message):
        self.code = code
        self.message = message
    def __str__(self):
        return self.code + " " + self.message

class ConfigError(JiraBaseError):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return self.message

def _result(response):
    try:
        return response["result"]
    except KeyError:
        code = response["error"]["code"]
        message = response["error"]["message"]
        raise RequestError(code, message)

class JsonRpcClient(object):
    def __init__(self):
        self._rpc_url = None
        self._auth_token = None

    def set_rpc_url(self, rpc_url):
        self._rpc_url = rpc_url

    def rpc_url(self):
        return self._rpc_url

    def call(self, method, *params):
        if self.rpc_url() is None:
            raise ConfigError('rpc_url')

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        body = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1337
        }

        req = urllib2.Request(self.rpc_url(), debug.peek("call body", json.dumps(body)), headers)
        with contextlib.closing(urllib2.urlopen(req)) as f:
            return json.loads(f.read())

    def login(self, username, password):
        self.set_auth_token(_result(self.call("login", username, password)))

    def set_auth_token(self, token):
        self._auth_token = token

    def auth_token(self):
        return self._auth_token

    def auth_call(self, method, *params):
        return self.call(method, self._auth_token, *params)

    def get_issue(self, key):
        return _result(self.auth_call("getIssue", key))

    def get_comments(self, key):
        return _result(self.auth_call("getComments", key))

    def get_issues_from_jql_search(self, jql, max_count=10000):
        return _result(self.auth_call("getIssuesFromJqlSearch", jql, max_count))

    def create_issue(self, project, summary, description, typeid, customs = {}):
        issue = {
            "project": project,
            "summary": summary,
            "description": description,
            "type": typeid
        }
        if len(customs) > 0:
            issue["customFieldValues"] = [{"customfieldId": k, "values": v} for k,v in customs.iteritems()]
        return _result(self.auth_call("createIssue", issue))

    def delete_issue(self, key):
        return _result(self.auth_call("deleteIssue", key))

    def update_issue(self, issue_key, **fields):
        return _result(self.auth_call("updateIssue", issue_key, _create_action_params(fields)))

    def add_comment(self, issue_key, body):
        return _result(self.auth_call("addComment", issue_key, body))

    def progress_workflow_action(self, issue_key, action_id, **new_values):
        return _result(self.auth_call('progressWorkflowAction', issue_key, str(action_id), _create_action_params(new_values)))

    def add_version(self, project, name):
        return _result(self.auth_call('addVersion', project, { 'name': name }))

    def release_version(self, project, version):
        return _result(self.auth_call('releaseVersion', project, version))

    def get_issue_types(self):
        return _result(self.auth_call("getIssueTypes"))

    def get_available_actions(self, issue_key):
        return _result(self.auth_call("getAvailableActions", issue_key))

    def get_fields_for_edit(self, issue_key):
        return _result(self.auth_call("getFieldsForEdit", issue_key))

    def get_resolutions(self):
        return _result(self.auth_call("getResolutions"))

    def get_statuses(self):
        return _result(self.auth_call("getStatuses"))

    def get_priorities(self):
        return _result(self.auth_call("getPriorities"))

    def get_all_permissions(self):
        return _result(self.auth_call("getAllPermissions"))

    def get_projects_no_schemes(self):
        return _result(self.auth_call("getProjectsNoSchemes"))

    def get_versions(self, project_key):
        return _result(self.auth_call("getVersions", project_key))

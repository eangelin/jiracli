import ConfigParser
import sys
import os
import getpass
import imp

_dotfile = u'.jiracli'

def _getenv(name):
    try:
        return os.environ[name]
    except:
        return None

def _guess_user():
    try:
        return getpass.getuser()
    except:
        return None

def _find_custom_dotfile(basedir=None):
    nextdir = basedir or os.getcwd()
    while True:
        checkpath = os.path.join(nextdir, _dotfile)
        if os.path.isfile(checkpath):
            return checkpath
        parentdir = os.path.normpath(os.path.join(nextdir, os.pardir))
        if parentdir == nextdir:
            return None
        else:
            nextdir = parentdir

class Config(object):
    def __init__(self):
        self.parser = None
        self.project_modules = {}
        self.loaded_configs = []

    def load(self, paths=None):
        paths = paths or [os.path.expanduser(u'~/' + _dotfile)]
        custom = _find_custom_dotfile()
        if custom:
            paths.append(custom)
        self.parser = ConfigParser.SafeConfigParser()
        self.loaded_configs = self.parser.read(paths)

    def loaded(self):
        return self.loaded_configs

    def _tryget(self, section, name, vardict=None):
        try:
            return self.parser.get(section, name, vardict is None, vardict) if self.parser is not None else None
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            return None

    def _trygetitems(self, section):
        try:
            return self.parser.items(section) if self.parser is not None else None
        except (ConfigParser.NoSectionError):
            return None

    def _do_get(self, section, name, envvar):
        return self._tryget(section, name) or _getenv(envvar)

    def issue_types(self):
        issue_type_map = {
            u'bug': 1,
            u'feature': 2,
            u'task': 3,
            u'improvement': 4
        }
        issue_type_map.update(self._trygetitems(u'issue_types') or {})
        return issue_type_map

    def resolution_types(self):
        resolution_type_map = {
            u'fixed': 1,
            u'wont': 2,
            u'dup': 3,
            u'incomplete': 4,
            u'norepro': 5,
            u'nobug': 6
        }
        resolution_type_map.update(self._trygetitems(u'resolutions') or {})
        return resolution_type_map

    def action_types(self):
        action_type_map = {
            u'reopen': 3,
            u'resolve': 5,
            u'close': 701
        }
        action_type_map.update(self._trygetitems(u'actions') or {})
        return action_type_map

    def statuses(self):
        status_type_map = {
            u'open': 1,
            u'inprogress': 3,
            u'reopened': 4,
            u'resolved': 5,
            u'closed': 6
        }
        status_type_map.update(self._trygetitems(u'statuses') or {})
        return status_type_map

    def id_status_map(self):
        return dict((v, k) for k,v in self.statuses().iteritems())

    def auth_token_store(self):
        store = self._do_get(u'jira', u'token_store', u'JIRACLI_TOKEN')
        return os.path.expanduser(store) if store is not None else store

    def username(self):
        return self._do_get(u'defaults', u'username', u'JIRACLI_USERNAME') or _guess_user()

    def project(self):
        return self._do_get(u'defaults', u'project', u'JIRACLI_PROJECT')
    
    def editor(self):
        return self._do_get(u'jira', u'editor', u'JIRACLI_EDITOR')

    def tempdir(self):
        return self._do_get(u'jira', u'tempdir', u'JIRACLI_TEMPDIR')

    def browse_command(self, key):
        return self._tryget(u'jira', u'browse_command', {'key': key})

    def project_module(self, project_key):
        module_path = self._do_get(u'jira', project_key + u'_extensions', u'JIRACLI_' + project_key + u'EXT')
        if module_path is not None:
            module_path = os.path.expanduser(module_path)
            if module_path in self.project_modules:
                return self.project_modules[module_path]
            else:
                module_name, module_ext = os.path.splitext(os.path.split(module_path)[-1])
                module = None
                if module_ext.lower() == u'.py':
                    module = imp.load_source(module_name, module_path)
                elif module_ext.lower() == u'.pyc':
                    module = imp.load_compiled(module_name, module_path)
                self.project_modules[module_path] = module
                return module
        else:
            return None

    def rpc_url(self):
        url = self._do_get(u'jira', u'url', u'JIRACLI_URL')
        return url + u'rpc/json-rpc/jirasoapservice-v2' if url is not None else url

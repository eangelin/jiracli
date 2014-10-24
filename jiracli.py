#!/usr/bin/python

import jirarpc
import jiracliconfig
import jirapprint
import util

import getpass
import argparse
import os
import sys
import codecs
import time
import calendar

def stdin_stdout_encoding_hack():
    if sys.stdin.encoding is None:
        sys.stdin = codecs.getreader('utf8')(sys.stdin)
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

################################################################################

def ask_username():
    return raw_input('username: ').decode(sys.stdin.encoding)

def ask_password():
    return getpass.getpass('password: ') # can't do unicode

################################################################################

def qualified_issue_key(key):
    return u'-' in key

def expand_issue_key(project, key):
    return key if qualified_issue_key(key) else project + u'-' + key

def get_project_from_issue_key(key):
    return key.split(u'-')[0] if u'-' in key else None

def get_project_arg(args):
    if args.project is not None:
        return args.project
    raise ValueError(u'missing project key')

def get_issue_arg(args):
    if args.issue is not None:
        if qualified_issue_key(args.issue):
            return args.issue
        else:
            return expand_issue_key(get_project_arg(args), args.issue)
    raise ValueError(u'missing issue key')

def get_issues_arg(args):
    if args.issues is not None:
        return [issue if qualified_issue_key(issue) else expand_issue_key(get_project_arg(args), issue)
                for issue in args.issues]
    raise ValueError(u'missing issue keys')

def add_implicit_project_arg(args):
    if args.project is None:
        if u'issue' in args and args.issue is not None:
            args.project = get_project_from_issue_key(args.issue)
        elif u'issues' in args and args.issues is not None:
            qualified_issue_keys = [issue for issue in args.issues if qualified_issue_key(issue)]
            if qualified_issue_keys:
                args.project = get_project_from_issue_key(qualified_issue_keys[0])

################################################################################

def input_multiline():
    lines = []
    while True:
        line = raw_input().decode(sys.stdin.encoding)
        if line == u'' and lines and lines[-1] == u'':
            return u'\n'.join(lines[0:-1])
        lines.append(line)

def edit_multiline(what, args):
    with util.TemporaryDirectory(basedir=args.tempdir) as tempdir:
        filepath = tempdir + '/' + what
        util.create_file(filepath)
        edit_command = args.editor + ' ' + filepath
        if os.system(edit_command) == 0:
            res = util.slurp(filepath)
            return res
    return ''

def expand_text_arg(initial, what, args):
    if initial == u'-':
        return sys.stdin.read()
    elif initial == u'+':
        return edit_multiline(what, args) if args.editor else input_multiline()
    else:
        return initial

def new_issue(client, config, itype, args):
    args.description = expand_text_arg(args.description, u'description', args)
    project_module = config.project_module(get_project_arg(args))
    customs = {}
    if hasattr(project_module, u'new_issue_customs'):
        customs = project_module.new_issue_customs(client, config, itype, args)
    result = client.create_issue(get_project_arg(args), args.summary, args.description, config.issue_types()[itype], customs)
    print jirapprint.format_issue(result, config.id_status_map())
    return result

def mk_new_issue_func(client, config, itype):
    return lambda args: new_issue(client, config, itype, args)

def del_issue(client, config, args):
    client.delete_issue(get_issue_arg(args))

def show_resolutions(client, config, args):
    for r in client.get_resolutions():
        print jirapprint.format_resolution(r)

def show_statuses(client, config, args):
    for s in client.get_statuses():
        print jirapprint.format_status(s)

def show_issue_types(client, config, args):
    for it in client.get_issue_types():
        print jirapprint.format_issue_type(it)

def show_actions(client, config, args):
    for a in client.get_available_actions(get_issue_arg(args)):
        print jirapprint.format_action(a)

def show_edit_fields(client, config, args):
    for f in client.get_fields_for_edit(get_issue_arg(args)):
        print jirapprint.format_field(f)

def show_permissions(client, config, args):
    for p in client.get_all_permissions():
        print jirapprint.format_permission(p)

def show_priorities(client, config, args):
    for p in client.get_priorities():
        print jirapprint.format_priority(p)

show_info_map = {
    u'resolutions': show_resolutions,
    u'statuses': show_statuses,
    u'issuetypes': show_issue_types,
    u'actions': show_actions,
    u'editfields': show_edit_fields,
    u'permissions': show_permissions,
    u'priorities': show_priorities
}

def show_info(client, config, args):
    show_info_map[args.whatinfo](client, config, args)

def resolve_issue(client, config, fix, args):
    # always use Resolve Issue action, set status as resolved
    client.progress_workflow_action(get_issue_arg(args), config.action_types()[u'resolve'],
                                    resolution=[config.resolution_types()[fix]],
                                    status=[config.statuses()[u'resolved']])
    args.comment = expand_text_arg(args.comment, u'comment', args)
    if args.comment is not None:
        add_comment(client, config, args)

def mk_resolve_issue_func(client, config, fix):
    return lambda args: resolve_issue(client, config, fix, args)

def close_issue(client, config, args):
    client.progress_workflow_action(get_issue_arg(args), config.action_types()[u'close'])

def reopen_issue(client, config, args):
    client.progress_workflow_action(get_issue_arg(args), config.action_types()[u'reopen'])

def view_issue(client, config, args):
    key = get_issue_arg(args)
    issue = client.get_issue(key)
    comments = client.get_comments(key)
    if not args.summary:
        print jirapprint.format_issue(issue, config.id_status_map(), comments)
    else:
        print jirapprint.format_issue_summary(issue)

def browse_issue(client, config, args):
    key = get_issue_arg(args)
    browse_command = config.browse_command(key)
    if browse_command:
        os.system(browse_command)

default_order = u'updated desc, resolution desc'
project_clause = u'project=%(project)s'

find_what_map = {
    u'open': u'status in (open, reopened) order by ' + default_order,
    u'mine': u'status in (open, reopened) and assignee = "%(username)s" order by ' + default_order,
    u'unassigned': u'status in (open, reopened) and assignee is empty order by ' + default_order
}

def prefixed_version(version):
    return version and version[0] == u'@'

def strip_version_prefix(version):
    return version[1:] if prefixed_version(version) else version

def user_possessive_s(username):
    return username and username[-1] == u's'

def strip_possessive_s(username):
    if not user_possessive_s(username):
        return username
    if len(username) > 2 and username[-2:] == u"'s":
        return username[:-2]
    elif username[-1:] == "s":
        return username[:-1]

def user_exists(username, client):
    return client.get_user(username)

def find_issues(client, config, args):
    params = vars(args)
    jql_template = None
    if args.what in find_what_map:
        jql_template = find_what_map[args.what]
    elif prefixed_version(args.what): # treat as fixVersion
        jql_template = u'fixVersion = "%(version)s" order by ' + default_order
        params[u'version'] = strip_version_prefix(args.what)
    elif user_possessive_s(args.what) and user_exists(strip_possessive_s(args.what), client):
        jql_template = find_what_map['mine']
        params['username'] = strip_possessive_s(args.what)
    else:
        jql_template = u'(summary ~ "%(search)s" OR description ~ "%(search)s" OR comment ~ "%(search)s") order by ' + default_order
        params[u'search'] = args.what

    if args.project:
        jql_template = project_clause + u' and ' + jql_template

    issues = client.get_issues_from_jql_search(jql_template % params) if jql_template is not None else []

    for issue in issues:
        print jirapprint.short_format_issue(issue, config.id_status_map())

def list_projects(client, config, args):
    for p in client.get_projects_no_schemes():
        print jirapprint.short_format_project(p)

def list_versions(client, config, args):
    for v in sorted(client.get_versions(get_project_arg(args)), key=lambda v: v['sequence'], reverse=True):
        print jirapprint.short_format_version(v)

def add_comment(client, config, args):
    args.comment = expand_text_arg(args.comment, u'comment', args)
    client.add_comment(get_issue_arg(args), args.comment)

def assign_issues_to_me(client, config, args):
    for issue in get_issues_arg(args):
        client.update_issue(issue, assignee=[args.username])

def unassign_issues(client, config, args):
    for issue in get_issues_arg(args):
        client.update_issue(issue, assignee=[])

def get_version_id(versions, version):
    if prefixed_version(version):
        version_name = strip_version_prefix(version)
        matches = [v for v in versions if v['name'].lower() == version_name.lower()]
        if len(matches) == 1:
            return matches[0]['id']
        else:
            raise ValueError(u'invalid version name')
    else:
        return version

def find_version_index_by_id(versions, version_id):
    matches = [ev for ev in enumerate(versions) if ev[1]['id'] == version_id]
    if len(matches) == 1:
        return matches[0][0]
    else:
        raise ValueError(u'invalid version id')

def find_version_by_id(versions, version_id):
    return versions[find_version_index_by_id(versions, version_id)]

def unix_ts_millis_now():
    return calendar.timegm(time.gmtime()) * 1000

def status_openish(status, status_map):
    return status_map[int(status)] in (u'open', 'reopened')

def prune_version(client, config, args):
    project = get_project_arg(args)
    versions = client.get_versions(project)
    version_id = get_version_id(versions, args.version)
    jql = u'project=%(project)s and fixVersion= "%(version)s"' % { u'project': project, u'version': version_id}
    version_issues = client.get_issues_from_jql_search(jql)
    status_map = config.id_status_map()
    for issue in version_issues:
        if status_openish(issue['status'], status_map):
            new_fix_versions = filter(lambda v: v['id'] != version_id, issue['fixVersions'])
            client.update_issue(issue['key'], fixVersions=new_fix_versions)

def add_version(client, config, args):
    client.add_version(get_project_arg(args), args.name)

def release_version(client, config, args):
    versions = client.get_versions(get_project_arg(args))
    version_id = get_version_id(versions, args.version)
    version = find_version_by_id(versions, version_id)
    version['released'] = True
    version['releaseDate'] = unix_ts_millis_now()
    client.release_version(get_project_arg(args), version)

def fixin_version(client, config, args):
    version_id = get_version_id(client.get_versions(get_project_arg(args)), args.version)
    issues = get_issues_arg(args)
    for issue in issues:
        client.update_issue(issue, fixVersions=[version_id])

################################################################################

def add_new_issue_parsers(subs, client, config):
    for itype in config.issue_types():
        new_issue_parser = subs.add_parser(itype)
        new_issue_parser.add_argument(u'summary')
        new_issue_parser.add_argument(u'description', nargs=u'?', default=u'')
        new_issue_parser.set_defaults(func=mk_new_issue_func(client, config, itype))

def add_del_issue_parser(subs, client, config):
    del_issue_parser = subs.add_parser(u'del')
    del_issue_parser.add_argument(u'issue')
    del_issue_parser.set_defaults(func=lambda args: del_issue(client, config, args))

def add_resolve_issue_parsers(subs, client, config):
    for fix in config.resolution_types():
        resolve_issue_parser = subs.add_parser(fix)
        resolve_issue_parser.add_argument(u'issue')
        resolve_issue_parser.add_argument(u'comment', nargs=u'?')
        resolve_issue_parser.set_defaults(func=mk_resolve_issue_func(client, config, fix))

def add_close_issue_parser(subs, client, config):
    close_parser = subs.add_parser(u'close')
    close_parser.add_argument(u'issue')
    close_parser.set_defaults(func=lambda args: close_issue(client, config, args))

def add_reopen_issue_parser(subs, client, config):
    reopen_parser = subs.add_parser(u'reopen')
    reopen_parser.add_argument(u'issue')
    reopen_parser.set_defaults(func=lambda args: reopen_issue(client, config, args))

def add_view_issue_parser(subs, client, config):
    view_parser = subs.add_parser(u'view')
    view_parser.add_argument(u'issue')
    view_parser.add_argument(u'--summary', dest=u'summary', action='store_true')
    view_parser.set_defaults(func=lambda args: view_issue(client, config, args))

def add_browse_issue_parser(subs, client, config):
    browse_parser = subs.add_parser(u'browse')
    browse_parser.add_argument(u'issue')
    browse_parser.set_defaults(func=lambda args: browse_issue(client, config, args))

def add_comment_issue_parser(subs, client, config):
    comment_parser = subs.add_parser(u'comment')
    comment_parser.add_argument(u'issue')
    comment_parser.add_argument(u'comment')
    comment_parser.set_defaults(func=lambda args: add_comment(client, config, args))

def add_assign_issue_parsers(subs, client, config):
    dibs_parser = subs.add_parser(u'dibs')
    dibs_parser.add_argument(u'issues', nargs='+')
    dibs_parser.set_defaults(func=lambda args: assign_issues_to_me(client, config, args))
    undib_parser = subs.add_parser(u'undib')
    undib_parser.add_argument(u'issues', nargs='+')
    undib_parser.set_defaults(func=lambda args: unassign_issues(client, config, args))

def add_issue_subparsers(subs, client, config):
    # subs = parser.add_subparsers(title=u'Issue commands')
    add_new_issue_parsers(subs, client, config)
    add_del_issue_parser(subs, client, config)
    add_close_issue_parser(subs, client, config)
    add_resolve_issue_parsers(subs, client, config)
    add_reopen_issue_parser(subs, client, config)
    add_view_issue_parser(subs, client, config)
    add_browse_issue_parser(subs, client, config)
    add_comment_issue_parser(subs, client, config)
    add_assign_issue_parsers(subs, client, config)

def add_find_parser(subs, client, config):
    find_parser = subs.add_parser(u'find')
    find_parser.add_argument(u'what')
    find_parser.set_defaults(func=lambda args: find_issues(client, config, args))

def add_find_subparsers(subs, client, config):
    # subs = parser.add_subparsers(title=u'Search commands')
    add_find_parser(subs, client, config)

def add_projects_parser(subs, client, config):
    projects_parser = subs.add_parser(u'projects')
    projects_parser.set_defaults(func=lambda args: list_projects(client, config, args))

def add_versions_parser(subs, client, config):
    versions_parser = subs.add_parser(u'versions')
    versions_parser.set_defaults(func=lambda args: list_versions(client, config, args))

def add_serverinfo_parser(subs, client, config):
    info_parser = subs.add_parser(u'serverinfo')
    info_parser.add_argument(u'whatinfo', choices=show_info_map.keys())
    info_parser.add_argument(u'issue', nargs=u'?')
    info_parser.set_defaults(func=lambda args: show_info(client, config, args))

def add_info_subparsers(subs, client, config):
    # subs = parser.add_subparsers(title=u'Info commands')
    add_projects_parser(subs, client, config)
    add_versions_parser(subs, client, config)
    add_serverinfo_parser(subs, client, config)

def add_prune_parser(subs, client, config):
    prune_parser = subs.add_parser(u'prune')
    prune_parser.add_argument(u'version')
    prune_parser.set_defaults(func=lambda args: prune_version(client, config, args))

def add_version_parser(subs, client, config):
    version_parser = subs.add_parser(u'version')
    version_parser.add_argument(u'name')
    version_parser.set_defaults(func=lambda args: add_version(client, config, args))

def add_release_parser(subs, client, config):
    release_parser = subs.add_parser(u'release')
    release_parser.add_argument(u'version')
    release_parser.set_defaults(func=lambda args: release_version(client, config, args))

def add_fixin_parser(subs, client, config):
    fixin_parser = subs.add_parser(u'fixin')
    fixin_parser.add_argument(u'version')
    fixin_parser.add_argument(u'issues', nargs='+')
    fixin_parser.set_defaults(func=lambda args: fixin_version(client, config, args))

def add_version_subparsers(subs, client, config):
    # subs = parser.add_subparsers(title=u'Version commands')
    add_prune_parser(subs, client, config)
    add_version_parser(subs, client, config)
    add_release_parser(subs, client, config)
    add_fixin_parser(subs, client, config)

def print_loaded_configs(config):
    for cfg in config.loaded():
        print cfg

def add_configs_parser(subs, client, config):
    configs_parser = subs.add_parser('configs')
    configs_parser.set_defaults(func=lambda args: print_loaded_configs(config))

def get_config_setting(client, config, args):
    dotfile = jiracliconfig.global_dotfile() if args.global_ else jiracliconfig.custom_dotfile()
    config = jiracliconfig.Config()
    config.load([dotfile])
    value = config.get_setting(args.setting)
    if value:
        print(value)

def set_config_setting(client, config, args):
    dotfile = jiracliconfig.force_global_dotfile() if args.global_ else jiracliconfig.force_custom_dotfile()
    jiracliconfig.write_setting(dotfile, args.setting, args.value)

def get_set_config_setting(client, config, args):
    if args.value is None:
        get_config_setting(client, config, args)
    else:
        set_config_setting(client, config, args)

def add_config_parser(subs, client, config):
    config_parser = subs.add_parser(u'config')
    config_parser.add_argument(u'--global', dest=u'global_', action='store_true', help=u'change ~/.jiracli')
    config_parser.add_argument(u'setting')
    config_parser.add_argument(u'value', nargs='?')
    config_parser.set_defaults(func=lambda args: get_set_config_setting(client, config, args))

def print_known_settings():
    for setting, info in jiracliconfig.known_settings:
        print setting.ljust(30), '\t', info['help']

def add_settings_parser(subs, client, config):
    settings_parser = subs.add_parser(u'settings')
    settings_parser.set_defaults(func=lambda args: print_known_settings())

def add_config_subparsers(subs, client, config):
    # subs = parser.add_subparsers(title=u'Config commands')
    add_configs_parser(subs, client, config)
    add_config_parser(subs, client, config)
    add_settings_parser(subs, client, config)

################################################################################

def slurp_config_auth_token_store(config):
    try:
        with open(config.auth_token_store(), "rb") as f:
            return f.read()
    except IOError:
        return None

def reuse_auth_token(client, config):
    if config.auth_token_store() is not None:
        token = slurp_config_auth_token_store(config)
        if token is not None:
            client.set_auth_token(token)
            return True
    return False


def save_auth_token(client, config):
    if config.auth_token_store() is not None and client.auth_token() is not None:
        with open(config.auth_token_store(), "wb") as f:
            f.write(client.auth_token())

def wipe_auth_token(client, config):
    try:
        client.set_auth_token(None)
        if config.auth_token_store() is not None:
            os.remove(config.auth_token_store())
    except:
        return

################################################################################

def auth_fail_exception(exc):
    return exc.code == 500 and exc.message.find(u'RemoteAuthenticationException') != -1

def local_command(args):
    return args.command in ['config', 'configs', 'settings']

def run_args(args, client, config):
    try:
        if not local_command(args):
            if not reuse_auth_token(client, config):
                if args.username is None:
                    args.username = ask_username()
                client.login(args.username, ask_password())
        args.func(args)
        return True
    except jirarpc.RequestError as e:
        print e.message
        if auth_fail_exception(e):
            wipe_auth_token(client, config)
            return False
        return True

def main():
    stdin_stdout_encoding_hack()
    sys.argv = [a.decode('utf8') for a in sys.argv]

    config = jiracliconfig.Config()
    config.load(jiracliconfig.all_dotfiles())

    client = jirarpc.JsonRpcClient()

    parser = argparse.ArgumentParser()
    parser.add_argument(u'--username', help=u'user', default=config.username())
    parser.add_argument(u'--project', help=u'project key', default=config.project())
    parser.add_argument(u'--editor', help=u'editor for comments, descriptions', default=config.editor())
    parser.add_argument(u'--tempdir', help=u'directory for temporary files', default=config.tempdir())

    subs = parser.add_subparsers(dest='command') # would like each add_*_subparser to create their own subparser group, alas...
    add_issue_subparsers(subs, client, config)
    add_find_subparsers(subs, client, config)
    add_info_subparsers(subs, client, config)
    add_version_subparsers(subs, client, config)
    add_config_subparsers(subs, client, config)

    args = parser.parse_args()
    add_implicit_project_arg(args)
    client.set_rpc_url(config.rpc_url())

    try:
        while True:
            if run_args(args, client, config):
                break
    except ValueError as e:
        print e

    save_auth_token(client, config)

if __name__ == '__main__':
    main()


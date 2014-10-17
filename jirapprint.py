def format_resolution(r):
    return '%(name)s: %(id)s' % r

def format_status(s):
    return '%(name)s: %(id)s' % s

def format_issue_type(it):
    return '%(name)s: %(id)s' % it

def format_action(a):
    return '%(name)s: %(id)s' % a

def format_field(f):
    return '%(name)s: %(id)s' % f

def format_comment(comment):
    return '''
[%(author)s] %(body)s
''' % comment

def format_permission(p):
    return '%(name)s: %(permission)s' % p

def format_priority(p):
    return '%(name)s: %(id)s' % p

fancy_priority_map = {
    1: u'#####', #blocker
    2: u'#### ', #critical
    3: u'###  ', #major
    4: u'##   ', #minor
    5: u'#    ' #trivial
}

def format_status_assignee(issue, id_status_map):
    status_name = id_status_map[int(issue['status'])]
    assignee = issue['assignee'] or u''
    return u"".join([u"[", status_name, u": " + assignee if assignee else u"", u"]"])

def format_fancy_priority(issue):
    return fancy_priority_map[int(issue['priority'])]

def format_issue_summary(issue):
    return ''.join([issue['key'], u' ', issue['summary']])

def short_format_issue(issue, id_status_map):
    key = issue['key']
    summary = issue['summary']
    prio = format_fancy_priority(issue)
    return ''.join([key.ljust(8), u' ', prio, u' ', format_status_assignee(issue, id_status_map), u' ', summary])

def format_issue(issue, id_status_map, comments = []):
    issue_fix = dict([(k, v or u'') for (k,v) in issue.iteritems()])
    head = u"".join([issue['key'], u" ", issue['summary'], u" ", format_status_assignee(issue, id_status_map), u" ", format_fancy_priority(issue)])
    description = issue_fix['description']
    comment_trail = reduce(lambda trail, comment: trail + format_comment(comment) + '\n', comments, '')
    parts = [head, description, comment_trail]
    return u"\n\n".join([p.strip() for p in parts if p.strip() != ''])

def short_format_project(p):
    return '%(key)s: %(name)s' % p

def short_format_version(v):
    return '%(name)s' % v

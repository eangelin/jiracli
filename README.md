jiracli
=======

Quick-and-dirty command line access to useful parts of jira. Not at all stable and only ever used under cygwin.

Setup
-----
Clone the repository and create a symbolic link to jiracli.py somewhere in your path.

Tell jiracli about your jira-installation:

	$ jiracli config --global jira.url http://bugs.yourcompany.com/jira/
	
Optionally present yourself, otherwise jiracli will use logged in user name:

	$ jiracil config --global jira.username
	
Optionally tell jiracli where to put an auth token from jira, so you don't have to type your password all the time:

	$ jiracli config --global jira.token_store ~/jira_token
	
Now, cd to your project directory:

	$ cd /source/abc_project/
	
Tell jiracli your default project when in this directory or any subdirectory is abc (jira project key):

	$ jiracli config jira.project abc
	
Now, you should be good to go!

	$ jiracli find open

Notes on Jira
------------
If you use Jira 4.4.3/tomcat6 and keep getting:

	java.lang.ClassCastException: com.sun.jndi.ldap.LdapCtx cannot be cast to org.springframework.ldap.core.DirContextAdapter

... A workaround is to create a setenv.sh in your tomcat6/bin with the following contents:

	#!/bin/sh
	export JAVA_OPTS="-Datlassian.org.osgi.framework.bootdelegation=sun.*,com.sun.*,org.springframework.ldap.core.* -Dorg.apache.jasper.runtime.BodyContentImpl.LIMIT_BUFFER=true"

You might also need to increase the permsize, "-XX:MaxPermSize=512m" for instance.

Sample session
--------------
	$ jiracli bug "Something is broken"
	ABC-123 Something is broken
	$ jiracli version Sprint1
	$ jiracli versions
	...
	Sprint1
	$ jiracli fixin @Sprint1 123
	$ jiracli find @Sprint1
	ABC-123 [open: erik] Something is broken
	$ jiracli dibs 123
	$ jiracli find mine
	ABC-123 [open: erik] Something is broken
	...
	$ jiracli fixed 123 "Something is no longer broken"

jiracli
=======

Quick and dirty command line access to useful parts of jira. Not at all stable and only ever used under cygwin.

Sample session
--------------

	$ jiracli bug "Something is broken"
	ABC-123 Something is broken
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

Setup notes
------------
If you use Jira 4.4.3/tomcat6 and keep getting:

	java.lang.ClassCastException: com.sun.jndi.ldap.LdapCtx cannot be cast to org.springframework.ldap.core.DirContextAdapter

... A workaround is to create a setenv.sh in your tomcat6/bin with the following contents:

	#!/bin/sh
	export JAVA_OPTS="-Datlassian.org.osgi.framework.bootdelegation=sun.*,com.sun.*,org.springframework.ldap.core.* -Dorg.apache.jasper.runtime.BodyContentImpl.LIMIT_BUFFER=true"

You might also need to increase the permsize, "-XX:MaxPermSize=512m" for instance.

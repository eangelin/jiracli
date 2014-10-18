jiracli
=======

Quick and dirty command line access to useful parts of jira.

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

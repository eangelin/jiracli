jiracli
=======

Quick and dirty command line access to useful parts of jira.

Sample session
==============

>jiracli bug "yadayada"
ABC-123 yadayada

>jiracli versions
...
Sprint1

>jiracli fixin @Sprint1 123

>jiracli find @Sprint1
ABC-123 [open: erik] yadayada

>jiracli dibs 123
>jiracli find mine
ABC-123 [open: erik] yadayada
...
>jiracli fixed 123 "needs more cowbell"

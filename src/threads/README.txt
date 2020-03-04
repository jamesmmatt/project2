I went into the test/threads and ran grep - r alarm-multiple *
From here I grabbed the files that were returned from running that command
I edited and added alarm-mega to tests.c, tests.h, Rubric.alarm, and added alarm-mega into Make.testt file
I then ran grep - r test_alarm_multiple and grabbed alarm-wait.c then added a function for alarm mega
Then I ran the make command in the threads (not the test/threads folder) directory

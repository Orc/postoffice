#include "config.h"

#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "letter.h"


/* goodfile() -- check the goodness of a file.
 * a (.forward or usermap) is good if it's
 * 1) a regular file
 * 2) that is owned by the user
 * 3) and is not writable by anyone but the user
 */
int
goodfile(char *file, struct passwd *pwd)
{
    struct stat fs;

    return ( (stat(file, &fs) == 0) && S_ISREG(fs.st_mode) &&
			       (fs.st_uid == pwd->pw_uid ) &&
			    !(fs.st_mode & (S_IWGRP|S_IWOTH)) );
}

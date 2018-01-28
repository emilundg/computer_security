/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define LINE_BUFFER_LENGTH 1000
#define MAX_PASSWORD_AGE 3 
#define MAX_PASSWORDLENGTH 100

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		
		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		/* remove the \n sign and replace it with \0*/
		strtok(user, "\n");
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);
		if (passwddata != NULL) {
	          /* You have to encrypt user_pass for this to work */
		  /* Don't forget to include the salt */
		  if (!strncmp(user_pass, passwddata->passwd, MAX_PASSWORDLENGTH)) {
		    printf(" You're in ! (after %d failed attempts...\n",
                    passwddata->pwfailed);
                    /* Reset failed attemps to 0 */
                    passwddata->pwfailed = 0;
                    /* Check and increase password age */
                    passwddata->pwage += 1;
                    /* Update passdb */
                    mysetpwent(user, passwddata);
                    /* If password is too old, prompt user to change it */
                    if (passwddata->pwage > MAX_PASSWORD_AGE) {
                      char *new_pass1 = "1";
                      char *new_pass2 = "2";
                      while (!strncmp(new_pass1, new_pass2, MAX_PASSWORDLENGTH)) {
                        new_pass1 = getpass("You password is too old.\n Please set at new password: ");
                        new_pass2 = getpass("Please reenter new password: ");
                      }
                      printf("Successfully changed password\n");
                      passwddata->pwage = 0;
		      passwddata->passwd = new_pass1;
                      mysetpwent(user, passwddata);
                    }
                 }
                 else {
                  /* Increment number of failed attemps */
                  passwddata->pwfailed += 1;
                  mysetpwent(user, passwddata);
                 }
		/*  check UID, see setuid(2) */
		/*  start a shell, use execve(2) */
		}
		else {
	          printf("Login Incorrect \n");
		}
	}
	return 0;
}


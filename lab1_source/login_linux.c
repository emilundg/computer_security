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
#include <unistd.h>

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define LINE_BUFFER_LENGTH 1000
#define MAX_PASSWORD_AGE 3 
#define MAX_PASSWORDLENGTH 34

void signalIgnoreHandler() {
	fprintf(stderr, "\n");
}

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	signal(SIGINT, signalIgnoreHandler);
	signal(SIGQUIT, signalIgnoreHandler);
	signal(SIGTSTP, signalIgnoreHandler);
	signal(SIGTERM, signalIgnoreHandler);
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
        /* Enter username */
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

        // Receive user data from entered username
		passwddata = mygetpwnam(user);
        // Make the user enter password before username check
        char *entered_pass = getpass(prompt);
        // Make sure there is a user.
		if (passwddata == NULL) {
            printf("Login Incorrect \n");
            continue;
        }
        /* Password check */
        /* Hash the entered password with the users salt */
        user_pass = strndup(crypt(entered_pass, passwddata->passwd_salt),
            MAX_PASSWORDLENGTH);
        /* Check if the password is correct & do some checks */
        if (!strncmp(user_pass, passwddata->passwd, MAX_PASSWORDLENGTH)) {
            printf(" You're in ! (with %d failed attempts\n",
            passwddata->pwfailed);
            /* Reset failed attemps to 0 */
            passwddata->pwfailed = 0;
            /* Increase and check the  password age */
            passwddata->pwage += 1;
            mysetpwent(user, passwddata);
            /* If password is too old, prompt user to change it */
            if (passwddata->pwage > MAX_PASSWORD_AGE) {
                char *new_pass1;
                char *new_pass2;
                /* The user should enter the same password twice */
                while(1) {
                    new_pass1 = strndup(getpass(
                        "You password is too old.\n Please set at new password:"),
                        MAX_PASSWORDLENGTH);
                    new_pass2 = strndup(getpass(
                        "Please reenter new password:"),
                        MAX_PASSWORDLENGTH);
                    if (!strncmp(new_pass1, new_pass2, MAX_PASSWORDLENGTH)) {
                        break;
                    }
                }
                /* Password successfully changed */
                printf("Successfully changed password\n");
                /* Reset password age */
                passwddata->pwage = 0;
                /* Encrypt the new password with salt */
                /* TODO: Generate new salt */
                passwddata->passwd = strdup(crypt(new_pass1, passwddata->passwd_salt));
                mysetpwent(user, passwddata);
            }
            /* If login is successful, execute /bash/sh */
            /* TODO: Change access rights of current user (with setuid?) */
            char *shell = "sh";
            char *argv[3];
            argv[0] = "sh";
            execvp(shell, argv);
            exit(0);
        }
        else {
            /* Increment number of failed attemps */
            passwddata->pwfailed += 1;
            printf("Number of attempts: %d \n", passwddata->pwfailed);
            /* Preventing brute force attacks with a delay
             * if number of failed attempts exceeds 5, create a longer delay */
            if (passwddata->pwfailed > 5)
                sleep(10);
            // Small delay for preventing brute force
            sleep(0.5);
            mysetpwent(user, passwddata);
        }
	}
	return 0;
}


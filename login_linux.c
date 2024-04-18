/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <pwd.h>
#include <termios.h>
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>

#include <crypt.h>
/* Uncomment next line in step 2 */
 #include "pwent.h" 

#define TRUE 1
#define FALSE 0
#define LENGTH 16

struct termios org_opts;

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	signal(SIG_IGN, 0);
}

bool block = false;



void *timer_thread(void *vargs){
	int inp = (int *)vargs;
	printf("Args: %d \n", inp);

	block = true;
	sleep(60 * inp); // Sleep for one hour
	block = false;
	return NULL;
}



int main(int argc, char *argv[]) {

	signal(SIGINT, sighandler);
	signal(SIGTSTP, sighandler);
	signal(SIGQUIT, sighandler);
	
	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];
	bzero(user, LENGTH);
	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		// printf("Value of variable 'important1' before input of login name: %s\n",
		// 		important1);
		// printf("Value of variable 'important2' before input of login name: %s\n",
		// 		important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */
		user[strcspn(user, "\n")] = 0;
		//printf("name entered: %s\n", user);
		/* check to see if important variable is intact after input of login name - do not remove */
		// printf("Value of variable 'important 1' after input of login name: %*.*s\n",
		// 		LENGTH - 1, LENGTH - 1, important1);
		// printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		//  		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if(block){
			printf("You have failed too many times, try again later \n");
			continue;
		}		
		
		

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			
			char *enc_pass = crypt(user_pass, passwddata->passwd_salt);
			if(enc_pass == NULL){
				printf("Could not encrypt password");
				exit(-1);
			}
			
			//printf("Checking password %s : %s \n", enc_pass, passwddata->passwd);
			if (!strcmp(enc_pass, passwddata->passwd)) {
				printf("Failed attempts: %d \n", passwddata->pwfailed);
				
				passwddata->pwfailed = 0;
				passwddata->pwage += 1;
				mysetpwent(user, passwddata);
				/*  check UID, see setuid(2) */
				if(setuid(passwddata->uid) == -1){
					printf("Filed to set UID");
					exit(-1);
				};
				/*  start a shell, use execve(2) */
				static char *newenviron[] = { NULL };


				if( execve("/bin/sh", argv, newenviron) == -1){
					printf("Failed to start bash");
					exit(-1);
				}
				

				if(passwddata->pwage > 10){
					printf("You should change your password!!\n");					
				}


				continue;
			}
			passwddata->pwfailed += 1;
			mysetpwent(user, passwddata);

			if(passwddata->pwfailed > 5){
				pthread_t thread_id;
				pthread_create(&thread_id, NULL, timer_thread, (int *) passwddata->pwfailed);
			}

		}

		printf("Login Incorrect \n");
		
	
	}
	return 0;
}

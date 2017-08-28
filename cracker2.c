/**
 * Machine Problem: Password Cracker
 * CS 241 - Spring 2017
 */

#include "cracker2.h"
#include "format.h"
#include "utils.h"
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <queue.h>
#include "thread_status.h"

//mutex for global variable success
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
//barrier 
pthread_barrier_t mybarrier;

//flag for if password has been successfully cracked
int success;

//global input
char input[1024];

//number of worker thread
int thread_count_global;
int hash_count_global;

//flag for all threads to stop if password has found
int stop;

//output for decrypted password
char password[1024];

//time for elapsed time in threads
double elapsed;
double total_cpu_time;

int finished;


/*typedef struct queue_node {
  void *data;
  struct queue_node *next;
} queue_node;

struct queue {
  
  copy_constructor_type copy_constructor;
  destructor_type destructor;
  queue_node *head, *tail;
  ssize_t size;  ssize_t max_size;
  pthread_cond_t cv;
  pthread_mutex_t m;
};*/

void* start_routine(void *args){
	int *id = (int*)args;
	int temp=1;
	while(1){
	
		threadStatusSet("before threads processing");
	
	
		pthread_barrier_wait(&mybarrier);
		if(finished==1 || temp==0)break;
		if(strcmp(input,"")!=0){
	
		int result=0;
		threadStatusSet("before threads processing1");
		double thread_common_start_time = getTime();
		double start_cpu_time = getCPUTime();
	
	
		char username[50], encrypted[1024], password_incomplete[100];

		//C.S. for sscanf or not
		sscanf(input, "%s %s %s", username, encrypted, password_incomplete);
		
		size_t len = getPrefixLength(password_incomplete);
		long start_index=0, count=0;
		getSubrange((strlen(password_incomplete)-len),thread_count_global, *id, &start_index, &count); 

		char *test = malloc(9);
		//copy the incomplete password for try
		strcpy(test,password_incomplete);
		//now crack points to the first unknown char
		char *crack = test + len;
		//set crack to the index of password we should hash
		setStringPosition(crack, start_index);
			
		v2_print_thread_start(*id, username, start_index, test);
 
		struct crypt_data cdata;
		cdata.initialized=0;
		const char *hashed = crypt_r(test, "xx", &cdata);	
		int hashcount = 1;

		//C.S. for hash_count_global
		pthread_mutex_lock(&m);
		hash_count_global++;
		int stop_temp=stop;
		pthread_mutex_unlock(&m);

		//if(strcmp(hashed, encrypted)==0){stop = 1;break;}
		long times= count-1;
		int found=0;
		
		while(incrementString(crack)!=0 && times!=0 && stop_temp!=1){

			pthread_mutex_lock(&m);
			stop_temp=stop;
			hash_count_global++;
			pthread_mutex_unlock(&m);

			hashed = crypt_r(test, "xx", &cdata);
			//printf("%s\n",test);
			hashcount++;
	
			if(strcmp(hashed, encrypted)==0){
				pthread_mutex_lock(&m);
				threadStatusSet("found encrpted password");
				found=1;
				success=0;
				stop=1;
				stop_temp=1;
				strcpy(password,test);
				
					
				threadStatusSet("done increment success");
				pthread_mutex_unlock(&m);
				break;
			}	
			times--;
		}
		//C.S. for global elasped and total_cpu_count
		pthread_mutex_lock(&m);
		elapsed = getTime()-thread_common_start_time;
		total_cpu_time = getCPUTime()- start_cpu_time;
		

		if(found==1)result=0;
		else if(hashcount<count && stop==1)result=1;
		else if(times==0)result=2;
		v2_print_thread_result(*id, hashcount, result);
		pthread_mutex_unlock(&m);
		
		
		free(test);
		test=NULL;
		if(finished==1)temp=0;
		threadStatusSet("threads done processing");
		pthread_barrier_wait(&mybarrier);

		}else{
			break;
		}
		if(temp==0)break;
		
	}//while loop

	return NULL;
}
int start(size_t thread_count) {
  // TODO your code here, make sure to use thread_count!
  // Remember to ONLY crack passwords in other threads

	//set global vars
	pthread_mutex_lock(&m);
	thread_count_global = thread_count;
	finished=0;
	pthread_mutex_unlock(&m);
	

	pthread_t ids[thread_count];
	int id[thread_count];
	
	strcpy(input,"temp");

	pthread_barrier_init(&mybarrier, NULL, thread_count + 1);

	for(size_t i=0;i<thread_count;i++){
		id[i] = i+1; 
		pthread_create(&ids[i], NULL, &start_routine, &id[i]);
	}
	

	
	char *buffer=NULL;
	size_t capacity = 0;
	
	int lines=0;
	while(getline(&buffer, &capacity, stdin)!=-1){

		//C.S.
		pthread_mutex_lock(&m);
		buffer[strlen(buffer)-1]='\0';
		success=1;
		stop = 0;
		hash_count_global=0;
		
		char username[50], encrypted[1024], password_incomplete[100];
		sscanf(buffer, "%s %s %s", username, encrypted, password_incomplete);
		pthread_mutex_unlock(&m);

		strcpy(input,buffer);
		v2_print_start_user(username);	//print start username
		threadStatusSet("main thread print username");

		pthread_barrier_wait(&mybarrier);
		
		
		//idle

		pthread_barrier_wait(&mybarrier);
		
		
		v2_print_summary(username, password, hash_count_global,
                      elapsed, total_cpu_time, success);

		lines++;
		
	}
	strcpy(input,"");
	pthread_mutex_lock(&m);
	finished=1;
	pthread_mutex_unlock(&m);
	pthread_barrier_wait(&mybarrier);
	for(size_t i=0;i<thread_count;i++){
		//printf("%s, i:%lu \n","join",i);
		pthread_join(ids[i],NULL);
	}
	
	
	free(buffer);
	pthread_mutex_destroy(&m);
	pthread_barrier_destroy(&mybarrier);
  return 0;
}

/**
 * Machine Problem: Password Cracker
 * CS 241 - Spring 2017
 */

#include "cracker1.h"
#include "format.h"
#include "utils.h"
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <queue.h>
#include "thread_status.h"

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
int success=0;
typedef struct queue_node {
  void *data;
  struct queue_node *next;
} queue_node;
struct queue {
  
  copy_constructor_type copy_constructor;

  destructor_type destructor;

  queue_node *head, *tail;

  ssize_t size;
  ssize_t max_size;

  pthread_cond_t cv;
  pthread_mutex_t m;
};
typedef struct {
  char *input;         // Pointer to the encrypted password.
} task;

/*char *generate_rand(size_t len){
	char *ret = malloc(sizeof(char)*len+1);//+1 for NULL byte
	strcpy(ret,"");
	for(size_t i=0;i<len;i++){
		char c = rand()%26 + 97;
		strcat(ret, c);
	}
	ret[len] = '\0';
	return ret;
}*/

void *my_copy_constructor(void *data){
	if(data==NULL)return NULL;
	task *temp = (task*)data;
	task *mytask = malloc(sizeof(task));
	mytask->input = malloc(1024);
	strcpy(mytask->input, temp->input);
	return mytask;
}

void my_destructor(void *data){
	if(data==NULL)return;
	task *mytask = (task*)data;
	free(mytask->input);
	free(mytask);
}
queue *myqueue;
void* start_routine(void *args){
	int empty = 0;
	int *result = malloc(sizeof(int));//result is always 1 if can't be decrypted
	
	int *id = (int*)args;

	while(empty==0){
		double start_cpu_time = getThreadCPUTime();
		*result = 1;
		task *mytask = (task*)queue_pull(myqueue);
		if(mytask==NULL){empty=1;break;}

		char* buffer = mytask->input;
		char username[50], encrypted[1024], password_incomplete[100];
		sscanf(buffer, "%s %s %s", username, encrypted, password_incomplete);
		v1_print_thread_start(*id, username);
	
		size_t len = getPrefixLength(password_incomplete);
		char *test = malloc(9);
		strcpy(test,password_incomplete);
		char *crack = test + len;//now crack points to the first unknown char
		setStringPosition(crack,0);
		int hashcount = 1;
		struct crypt_data cdata;
		cdata.initialized=0;
		const char *hashed = crypt_r(test, "xx", &cdata);
		if(strcmp(hashed, encrypted)==0){result = 0;break;}
			
		while(incrementString(crack)!=0 && *result==1){
			hashed = crypt_r(test, "xx", &cdata);
			hashcount++;
			if(strcmp(hashed, encrypted)==0){
				threadStatusSet("found encrpted password");
				*result = 0;//only decrypted password has result 0
				
				pthread_mutex_lock(&m);
				success++;
				pthread_mutex_unlock(&m);
				threadStatusSet("done increment success");
				break;
			}	
		}
		double elapsed = getThreadCPUTime() - start_cpu_time;
		v1_print_thread_result(*id, username, test,
        	                    hashcount, elapsed, *result);
		
		free(test);
		test=NULL;
		free(mytask->input);
		free(mytask);
	}
	queue_push(myqueue,NULL);
	return result;
}

int start(size_t thread_count) {
  // TODO your code here, make sure to use thread_count!
  // Remember to ONLY crack passwords in other threads
	
	myqueue = queue_create(-1,my_copy_constructor,my_destructor);
	pthread_t *ids = malloc(sizeof(pthread_t)*thread_count);
	int id[thread_count];
	for(size_t i=0;i<thread_count;i++){
		//id[i] = malloc(sizeof(int));
		id[i] = i+1; 
		pthread_create(&ids[i], NULL, &start_routine, &id[i]);
	}

	task **tasks = malloc(sizeof(task*)*100);//how to know # of task?
	
	char *buffer=NULL;
	size_t capacity = 0;
	int lines = 0;
	while(getline(&buffer, &capacity, stdin) != -1){

		buffer[strlen(buffer)-1]='\0';
		tasks[lines] = malloc(sizeof(task));
		tasks[lines]->input = malloc(1024);
		//printf("%s\n",tasks[lines]->input);
		strcpy(tasks[lines]->input, buffer);
		threadStatusSet("waiting for task");
		queue_push(myqueue,(void*)tasks[lines]);
		threadStatusSet("proceeding");
		lines++;
	}
	queue_push(myqueue,NULL);
	printf("lines: %d\n", lines);
	
	void *result;
	//int success = 0;
	for(size_t i=0;i<thread_count;i++){
		//printf("i: %lu\n", i);
		pthread_join(ids[i],&result);
		free(result);
		//int *temp = (int*)result;
		
		//if(*temp==0)success++;
		
	}
	
	v1_print_summary(success, lines-success);

	queue_destroy(myqueue);
	for(int i=0;i<lines;i++){
		free(tasks[i]->input);
		free(tasks[i]);
	}
	free(tasks);
	free(ids);
	free(buffer);
	pthread_mutex_destroy(&m);
	
  return 0;
}

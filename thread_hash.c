//thread_hash.c
//Drake Wheeler

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <crypt.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include "thread_hash.h"

#ifndef FALSE
# define FALSE 0
#endif // FALSE
#ifndef TRUE
# define TRUE 1
#endif // TRUE
#define BUF_SIZE 250

//used to print helpful debug statements
#ifdef NOISY_DEBUG
# define NOISY_DEBUG_PRINT fprintf(stderr, "%s %s %d\n", __FILE__, __func__, __LINE__)
#else // NOISY_DEBUG
# define NOISY_DEBUG_PRINT
#endif // NOISY_DEBUG

pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER; //to handle multiple threads trying to write to same output file / stdout
pthread_mutex_t stderr_mutex = PTHREAD_MUTEX_INITIALIZER; //to handle mutlipe threads trying to write to stderr
pthread_mutex_t global_counts_mutex = PTHREAD_MUTEX_INITIALIZER; //to handle mutliple threads incrementing the same global variables

unsigned short verbose = FALSE; //verbose flag
char** passwords = NULL; //array holding all the password hash strings
char* whole_file = NULL; //buffer that holds entire passwords file
size_t num_passwords = 0; //number of passwords
char* dictionary_filename = NULL; 
static int num_threads = 1;
FILE* output; //file pointer to either stdout or output file
size_t global_hash_counts[ALGORITHM_MAX] = {0}; //total counts of each hash algo processed between all threads
size_t global_failed_to_crack = 0; //total failed cracks across all threads

int crack_password(const char* password);
void read_passwords(const char* filename);
void thread_ception(void);
void* thread_execution(void* vid);
int get_next_password(void);
void program_priority(int apply_nice);
void setup_output(char* output_filename);
void validate_necessary_files(char* input_filename);
hash_algorithm_t get_hash_algo(const char* hash); //returns the algo type of the hash
double elapse_time(struct timeval* t0, struct timeval* t1);
void validate_num_threads(void);
void free_memory(void);

int main(int argc, char* argv[])
{
	char* input_filename = NULL;
	char* output_filename = NULL;
	int apply_nice = FALSE; //flag to apply nice to program process priority
	output = stdout; //set gloabl output to default stdout

	{
		int opt = 0;

		while ((opt = getopt(argc, argv, OPTIONS)) != -1)
		{
			switch (opt)
			{
				case 'i':
					input_filename = optarg;
					break;

				case 'o':
					output_filename = optarg;
					break;

				case 'd':
					dictionary_filename = optarg;
					break;

				case 't':
					num_threads = atoi(optarg);
					validate_num_threads();
					break;

				case 'v':
					verbose = TRUE;
					break;

				case 'h':
					fprintf(stderr, "help text\n");
					fprintf(stderr, "\t./thread_hash ...\n");
					fprintf(stderr, "\tOptions: i:o:d:hvt:n\n");
					fprintf(stderr, "\t\t-i file\t\thash file name (required)\n");
					fprintf(stderr, "\t\t-o file\t\toutput file name (default stdout)\n");
					fprintf(stderr, "\t\t-d file\t\tdictionary file name (default stdout)\n");
					fprintf(stderr, "\t\t-t #\t\tnumber of threads to create (default 1)\n");
					fprintf(stderr, "\t\t-v\t\tenable verbose mode\n");
					fprintf(stderr, "\t\t-h\t\thelpful text\n");

					exit(EXIT_SUCCESS);
					break;

				case 'n':
					apply_nice = TRUE;
					break;

			}
		}
	}

	//ensure required commands and arguments were passed in
	validate_necessary_files(input_filename);	

	//apply nice() is -n was specified
	program_priority(apply_nice);

	//populate passwords array from input file
	read_passwords(input_filename);
	
	//setup where output will be written to
	setup_output(output_filename);

	//all thread set up and exceution
	thread_ception();

	free_memory();

	return EXIT_SUCCESS;
}



//frees memory of any unfreed memory at the end of the program
void free_memory(void)
{
	//free the whole_file buffer which holes the actual password data
	if (whole_file)
	{
		free(whole_file);
		whole_file = NULL;
	}

	//free the passwords array which hols the pointers to parts of whole_file
	if (passwords)
	{
		free(passwords);
		passwords = NULL;
	}

	//closes output file is it's to a file
	if (output != NULL && output != stdout)
	{
		fclose(output);
		output = NULL;
	}

	return;
}



//determines and returns the hash algo based on the hash string
hash_algorithm_t get_hash_algo(const char* hash)
{
	if (hash == NULL || strlen(hash) ==  0) return ALGORITHM_MAX; //unkown algo

	if (hash[0] != '$') return DES;

	if (hash[1] == '3') return NT;

	if (hash[1] == '1') return MD5;

	if (hash[1] == '5') return SHA256;

	if (hash[1] == '6') return SHA512;

	if (hash[1] == 'y') return YESCRYPT;

	if (hash[1] == 'g' && hash[2] == 'y') return GOST_YESCRYPT;

	if (hash[1] == '2' && hash[2] == 'b') return BCRYPT;

	return ALGORITHM_MAX;
}



//confirms the necesarry commands were passed in on the command line
void validate_necessary_files(char* input_filename)
{
	//check for required commands
	if (!dictionary_filename)
	{
		fprintf(stderr, "must give name for dictionary input file with -d filename\n");
		exit(EXIT_FAILURE);
	}
	if (!input_filename)
	{
		fprintf(stderr, "must give name for hashed password input file with -i filename\n");
		exit(EXIT_FAILURE);
	}

	if (verbose)
	{
		fprintf(stderr, "input file: %s\n", input_filename);
		fprintf(stderr, "dictionary file: %s\n", dictionary_filename);
	}

	return;
}



//sets up output if the output is redirected to a file through a command line option -o
void setup_output(char* output_filename)
{
	if (output_filename != NULL)
	{
		output = fopen(output_filename, "w");
		if (!output)
		{
			fprintf(stderr, "Error: Could not open output file %s\n", output_filename);
			exit(EXIT_FAILURE);
		}
	}

	return;
}



//applys nice value of 10 to this programs priority if -n command was used
void program_priority(int apply_nice)
{
	if (apply_nice)
	{
		int ret = 0;
		errno = 0; //reset errno before calling nice()

		ret = nice(NICE_VALUE);
		if (ret == -1 && errno != 0)
		{
			perror("Error applying nice()");
			exit(EXIT_FAILURE);
		}

		if (verbose) fprintf(stderr, "Applied nice(%d), new priority: %d\n", NICE_VALUE, ret);
	}

	return;
}



//make sure thread count is valid
void validate_num_threads(void)
{
	if (num_threads > 24 || num_threads < 1)
	{
		fprintf(stderr, "invalid thread count %d\n", num_threads);
		exit(EXIT_FAILURE);
	}

	return;
}



//reads password has strings from input file and stores them in global passwords array
void read_passwords(const char* filename)
{
	struct stat file_stat;
	size_t file_size = 0;
	int fd = -1;

	//get the size of the file
	if (stat(filename, &file_stat) == -1)
	{
		perror("stat");
		exit(EXIT_FAILURE);
	}

	//store the size of the input file in bytes
	file_size = file_stat.st_size;

	//allocate memory for entrie file
	whole_file = malloc(file_size + 1);
	if (whole_file == NULL)
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	//initalize the buffer to zero 
	memset(whole_file, 0, file_size + 1);

	//open input file
	fd = open(filename, O_RDONLY);
	if (fd == -1)
	{
		fprintf(stderr, "Error: Could not open file %s\n", filename);
		exit(EXIT_FAILURE);
	}

	//read file into whole_file
	if (read(fd, whole_file, file_size) == -1)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}

	close(fd);

	//count the number of passwords based on newlines
	for (size_t i = 0; i < file_size; ++i)
	{
		if (whole_file[i] == '\n') ++num_passwords;
	}

	//directly allocate correct space for all the lines to be put into array
	passwords = malloc(num_passwords * sizeof(char*));
	if (passwords == NULL)
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}


	//parse through whole_file and set passwords array
	{
		size_t i = 0;
		char* token = strtok(whole_file, "\n");

		while (i < num_passwords)
		{
			passwords[i++] = token;
			token = strtok(NULL, "\n");
		}
	}

	return;
}



//handles all the thread stuff, the highest level thread function
void thread_ception(void)
{
	pthread_t* threads = NULL;
	long tid = 0; //thread ID
	struct timeval start_time, end_time; //to track threads total runtime
	double elapsed_time = 0.0;


	threads = malloc(num_threads * sizeof(pthread_t));

	//get start time of thread work
	gettimeofday(&start_time, NULL);
	

	//create threads
	for (tid = 0; tid < num_threads; ++tid)
	{
		pthread_create(&threads[tid], NULL, thread_execution, (void*) tid);
	}
	for (tid = 0; tid < num_threads; ++tid)
	{
		pthread_join(threads[tid], NULL);
	}

	//get end time of thread work
	gettimeofday(&end_time, NULL);
	elapsed_time = elapse_time(&start_time, &end_time); //calculate time thread was doing work

	free(threads);

	//display thread summary results
	fprintf(stderr, "total:  %2d %8.2lf sec  ", num_threads, elapsed_time);

	//iterate through each hash algorithm and print counts
	for (int alg = 0; alg < ALGORITHM_MAX; ++alg)
	{
		fprintf(stderr, "%15s: %5ld  ", algorithm_string[alg], global_hash_counts[alg]);
	}

	//print total processed and failed counts
 	fprintf(stderr, "total: %8ld", num_passwords);
    fprintf(stderr, "  failed: %8ld\n", global_failed_to_crack);

	return;
}



//this function runs a single thread process. It processes its share of hashes, and prints the thread summary
void* thread_execution(void* vid)
{
	size_t i = -1;
	struct timeval start_time, end_time; //to track threads total runtime
	double elapsed_time = 0.0;
	size_t hash_counts[ALGORITHM_MAX] = {0}; //to track the amount of each has type each thread processes
	size_t hashes_processed = 0; //count total hashes processed by thread
	size_t failed_to_crack = 0; //counts total failed cracks
	int tid = (int)(long)vid; //cast thread id


	//get start time of thread work
	gettimeofday(&start_time, NULL);


	while ((i = get_next_password()) < num_passwords)
	{
		++hash_counts[get_hash_algo(passwords[i])]; //increment the hash type

		//process hash, print results, increments failed_to_crack if necessary
		if (!crack_password(passwords[i])) ++failed_to_crack;


		++hashes_processed; //increments total hashes processed for this thread
	}

	//get end time of thread work
	gettimeofday(&end_time, NULL);
	elapsed_time = elapse_time(&start_time, &end_time); //calculate time thread was doing work

	pthread_mutex_lock(&stderr_mutex); //lock stderr to print the results

	//print the summary for this thread
	fprintf(stderr, "thread: %2d %8.2lf sec  ", tid, elapsed_time);
	//iterate through each hash algorithm and print counts
	for (int alg = 0; alg < ALGORITHM_MAX; ++alg)
	{
		fprintf(stderr, "%15s: %5ld  ", algorithm_string[alg], hash_counts[alg]);
	}
	//print total processed and failed counts
 	fprintf(stderr, "total: %8ld", hashes_processed);
    fprintf(stderr, "  failed: %8ld\n", failed_to_crack);

	pthread_mutex_unlock(&stderr_mutex); //unlock stderr

	//update global counters
	pthread_mutex_lock(&global_counts_mutex); //lock global coutners mutex

	//loop through each hash algo type
	for (int alg = 0; alg < ALGORITHM_MAX; ++alg)
	{
		global_hash_counts[alg] += hash_counts[alg]; //add the count from this threads hash algo to the global hash counter at the same index
	}

	global_failed_to_crack += failed_to_crack; //increment gloabl failed hash with the amount of failed hashes from this thread

	pthread_mutex_unlock(&global_counts_mutex); //unlock global counts mutex

	pthread_exit(EXIT_SUCCESS);
}



//returns the elapsed time between the two variables passed in
double elapse_time(struct timeval* t0, struct timeval* t1)
{
	double et = (((double) (t1->tv_usec - t0->tv_usec)) / MICROSECONDS_PER_SECOND)
		+ ((double) (t1->tv_sec - t0->tv_sec));

	return et;
}



//processes password hash, prints results for the single hash being processed returns 1 for succesful crack, 0 for failed crack
int crack_password(const char* password)
{
	char plain_word[BUF_SIZE] = {'\0'};
	struct crypt_data crypt_buffer; //struct for crypt_rn
	char* calculated_hash = NULL;
	FILE* file = fopen(dictionary_filename, "r");

	//zero initialize crypt_buffer before use
	memset(&crypt_buffer, 0, sizeof(crypt_buffer));

	if (!file)
	{
		fprintf(stderr, "Error: Could not open file %s\n", dictionary_filename);
		exit(EXIT_FAILURE);
	}


	//loop for each word in dictionary file
	while (fgets(plain_word, BUF_SIZE, file))
	{
		//remove trialing newline
		size_t len = strlen(plain_word);
		if (len > 0 && plain_word[len - 1] == '\n') plain_word[len - 1] = '\0';
		
		//get hash for this salt and plain word
		calculated_hash = crypt_rn(plain_word, password, &crypt_buffer, sizeof(crypt_buffer));

		if (!calculated_hash)
		{
			fprintf(stderr, "Error: crypt_rn returned NULL for password %s and plain word %s\n", password, plain_word);
			continue; //skip to next word
		}

		//check if calculated hash matches og hash
		if (strcmp(calculated_hash, password) == 0)
		{
			pthread_mutex_lock(&output_mutex);
			fprintf(output, "cracked  %s  %s\n", plain_word, password);
			pthread_mutex_unlock(&output_mutex);
			fclose(file);

			return 1;
		}
	}

	pthread_mutex_lock(&output_mutex);
	fprintf(output, "*** failed to crack   %s\n", password);
	pthread_mutex_unlock(&output_mutex);
	fclose(file); //closes dictionary file 
	
	return 0;
}



//get next index for password in passwords array for processing in threads, is thread safe
int get_next_password(void)
{
	static int next_password = 0; //shared inex for the next password
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; //mutex for thread saftey
	int current_password = -1; //local variable for the current password index

	pthread_mutex_lock(&lock); //lock the mutex
	current_password = next_password++; //assign and increment the shared index
	pthread_mutex_unlock(&lock); //unlock the mutex

	return current_password;
}




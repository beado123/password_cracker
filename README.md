# password_cracker
pw_cr is a program that recovers incomplete password (We only know the first few letters and the total length) using hashed version of passwords. For example, if the incomplete password is hello... (The dot represents unknown letters) and its hashed password xxC4UjY9eNri6, the program simply tries each possible password and finds the unknown letters to recover the original password.
However, using a single thread to find the original password of a list of unknown passwords is slow, so both cracker1 and cracker2 use multiple threads to complete the task. cracker1 will start a bunch of worker threads and they will crack the passwords as long as the main thread is reading incomplete password(input) from stdin, and this works well with a long list of passwords. cracker2 is designed to crack a single hard password efficiently: all the threads work in parallel on each password , which means each thread will start hashing from different letters in order. Both cracker1 and cracker2 use mutexes to avoid race condition and cracker2 uses pthread barrier to synchronize main thread and worker threads.

## Getting Started
Clone the repository and
```
make
```

## Usage
Create hash and password prefix examples:
```
./create_examples [-soln] <count> <min-iter> <max-iter>
./cracker1 [thread_count] < <password_file>
./cracker2 [thread_count] < <password_file>
```

## Testing
All testfiles are in the inputs folder, try:
```
./cracker1 1 < inputs/cracker1.in
```

# password_cracker
pw_cr is a program that recovers incomplete password (We only know the first few letters and the total length) using hashed version of passwords. For example, if the incomplete password is hello... (The dot represents unknown letters) and its hashed password xxC4UjY9eNri6, the program simply tries each possible password and finds the unknown letters to recover the original password.

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

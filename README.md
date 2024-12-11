# Threaded Password Cracker

## Project Overview
This project is a multi-threaded password-cracking application written in C as part of the CS 333 course, Lab 5. The primary focus of the project is to demonstrate performance improvements using multiple threads while working with hashed passwords and implementing cryptographic algorithms.

## Features
- Uses `PThreads` for multi-threading.
- Supports various hashing algorithms, including DES, NT, MD5, SHA-256, SHA-512, bcrypt, and yescrypt.
- Capable of processing up to 24 threads for password cracking.
- Provides verbose mode for detailed diagnostics.
- Outputs cracked passwords or failures along with performance metrics.

## Command-Line Options
The program accepts the following command-line arguments:

| Option  | Description                                                                 |
|---------|-----------------------------------------------------------------------------|
| `-i`    | Specifies the input file containing hashed passwords (required).           |
| `-o`    | Specifies the output file for results (default: stdout).                   |
| `-d`    | Specifies the dictionary file with plaintext words (required).             |
| `-t`    | Specifies the number of threads to use (default: 1; maximum: 24).          |
| `-v`    | Enables verbose mode for detailed processing diagnostics.                  |
| `-h`    | Displays help text about command-line options.                             |
| `-n`    | Applies the `nice()` function to lower the priority of the running process.|

## Implementation Details
- The program utilizes `crypt_rn()` for thread-safe cryptographic operations.
- Mutexes are used to handle shared resources, ensuring thread safety during operations like output writing and global variable updates.
- The program dynamically balances the load among threads.
- Outputs the performance of each thread, including processing time, number of hashes processed, and failure count.

## File Structure
- `thread_hash.c`: Contains the main logic and functions for the program.
- `thread_hash.h`: Defines constants, data structures, and utility macros.
- `Makefile`: Automates compilation and cleanup.
- Input files:
  - `passwords*.txt`: Files containing hashed passwords. Each file (e.g., `passwords100.txt`, `passwords500.txt`) corresponds to a specific set of hashed passwords.
  - `plain*.txt`: Files containing plaintext words to be used as a dictionary for cracking passwords. Each file (e.g., `plain100.txt`, `plain500.txt`) corresponds to its respective `passwords*.txt` file.

### Notes on Input Files:
- Files with the same number (e.g., `passwords100.txt` and `plain100.txt`) must always be used together for accurate results. The `passwords*.txt` file contains hashed versions of passwords that are expected to match entries in the corresponding `plain*.txt` file.
- The `passwords*.txt` file must be passed in using the `-i` flag, and the corresponding `plain*.txt` file must be passed in using the `-d` flag.
- The `-o` flag is optional. If it is not specified, the output will be displayed in the terminal (stdout). Specifying `-o` will redirect the output to a specified file.

## Compilation and Execution
1. Compile the program using the provided `Makefile`:
   ```bash
   make all
   ```

2. Run the program with appropriate options. Example:
   ```bash
   ./thread_hash -i passwords100.txt -d plain100.txt -t 4 -o output.txt -v
   ```

## Output Format
### Cracked Passwords
```
cracked  <plaintext_password>  <hashed_password>
```
### Failed Passwords
```
*** failed to crack  <hashed_password>
```
### Thread Summary (to `stderr`)
```
total:  4   10.23 sec   DES: 10   NT: 15   MD5: 5   SHA256: 20   SHA512: 10   YESCRYPT: 8   total: 100  failed: 5
```

## Requirements
- Use the `babbage` server for execution.
- Compile with the following `gcc` flags to ensure code quality:
  ```bash
  -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls -Wmissing-declarations \
  -Wold-style-definition -Wmissing-prototypes -Wdeclaration-after-statement -Wno-return-local-addr \
  -Wunsafe-loop-optimizations -Wuninitialized -Werror -Wno-unused-parameter
  ```
- Pass `valgrind` checks with no memory leaks or unsafe accesses.

## Example Use Case
1. Input files: `passwords100.txt` (hashed passwords) and `plain100.txt` (plaintext dictionary).
2. Run the program with 4 threads:
   ```bash
   ./thread_hash -i passwords100.txt -d plain100.txt -t 4 -o results.txt -v
   ```
3. View the results in `results.txt` and performance metrics in the terminal.

# Fuzzing

This section describes the fuzzing testing process, the approaches used, and methods applied, including both successful and unsuccessful attempts.

## Navigation
--------------------------------

- [Docker Image](#docker-image)
- [CMake](#cmake)
- [File Structure](#file-structure)
- [Example of Fuzzing Run](#example-of-fuzzing-run)
- [Other Fuzzing Techniques](#other-fuzzing-techniques)
- [Techniques That Didn't Work](#techniques-that-didnt-work)

## Docker Image
--------------------------------

The script is based on `tests/Dockerfile.ubuntu-24.04-afl++`.
This image builds and installs everything necessary for further testing:

| Module                                   | Description                                               |
|------------------------------------------|-----------------------------------------------------------|
| [`AFL++`](https://github.com/AFLplusplus) | Fuzzer                                                    |
| [`casr`](https://github.com/ispras/casr)  | Utility for crash verification, minimization, and clustering. Requires rust |
| [`desock`](https://github.com/zardus/preeny/) | Utility for replacing system calls. Used in the project to replace the `socket` function, which takes data from the interface, with a function that takes data from the console |

Sanitizers (ASAN, UBSAN, etc.) are also used in the project for runtime error detection.

### Build Docker Image
--------------------------------

To build the Docker image for testing, run the following command from the root directory `fastnetmon`:
```bash
docker build -f tests/Dockerfile.ubuntu-24.04-afl++ . -t fuzz
```

After the build is complete, an `image` named `fuzz` will be created.

## CMake
--------------------------------
A number of options have been added to the source `CMakeLists.txt` file, allowing the building of separate fuzzing wrappers using different cmake options.
*The options in the table will be listed with the `-D` prefix, which allows setting the option as an argument to the cmake utility when run from the command line.*

| Option                            | Description                                               |
|-----------------------------------|-----------------------------------------------------------|
| `-DENABLE_FUZZ_TEST`              | Builds two fuzzing wrappers for `AFL++`. Use **only with the `afl-c++` compiler** or its variations |
| `DENABLE_FUZZ_TEST_LIBFUZZER`    | Builds two fuzzing wrappers for `libfuzzer`. Use **with the `clang` compiler or variations of `afl-c++`** |
| `-DENABLE_FUZZ_TEST_DESOCK`       | This option allows modifying the behavior of the standard `socket` function. Now data will come from the input stream instead of the network socket. **Instruments the original `fastnetmon` executable** |
| `-DCMAKE_BUILD_TYPE=Debug`        | Debugging option required for proper debugger functionality. **Do not use on release builds or during tests - false positives may occur with sanitizer functions like `assert()`** |

## File Structure
--------------------------------
```bash
fuzz/ 
├── README.md 
├── README_rus.md
├── fastnetmon.conf
├── parse_sflow_v5_packet_fuzz.cpp
├── parse_sflow_v5_packet_fuzz_libfuzzer.cpp
├── process_netflow_packet_v5_fuzz.cpp
├── process_netflow_packet_v5_fuzz_libfuzzer.cpp └── scripts/
├── minimize_out.sh
├── start_fuzz_conf_file.sh
└── start_fuzz_harness.sh
```
### File Descriptions
--------------------------------

| File                                    | Description                                                                                   |
|-----------------------------------------|-----------------------------------------------------------------------------------------------|
| `README.md`                             | Documentation in **English** about the fuzz testing of the project.                             |
| `README_rus.md`                         | Documentation in **Russian** about the fuzz testing of the project.                            |
| `fastnetmon.conf`                       | Configuration file for FastNetMon. Only the netflow and sflow protocols are left for operation. |
| `parse_sflow_v5_packet_fuzz.cpp`        | Wrapper for fuzzing the `parse_sflow_v5_packet_fuzz` function using `AFL++`.                   |
| `parse_sflow_v5_packet_fuzz_libfuzzer.cpp` | Wrapper for fuzzing the `parse_sflow_v5_packet_fuzz` function using `libfuzzer`.            |
| `process_netflow_packet_v5_fuzz.cpp`    | Wrapper for fuzzing the `process_netflow_packet_v5_fuzz` function using `AFL++`.               |
| `process_netflow_packet_v5_fuzz_libfuzzer.cpp` | Wrapper for fuzzing the `process_netflow_packet_v5_fuzz` function using `libfuzzer`.        |

| File/Directory                         | Description                                                                                     | Run                                                                                                 |
|----------------------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `/scripts/`                            | Directory containing scripts for automating fuzzing.                                             |                                                                                                     |
| `/scripts/minimize_out.sh`             | Script for minimizing, verifying, and clustering crash outputs.                                  | `./minimize_out.sh <path_to_out_directory> <./binary>`                                               |
| `/scripts/start_fuzz_conf_file.sh`     | Script for running fuzzing on configuration files. Launches several tmux sessions. Uses options `./fastnetmon --configuration_check --configuration_file`. | Run from the current directory without additional options. The environment is automatically set up. |
| `/scripts/start_fuzz_harness.sh`       | Script for testing binary files compiled from wrappers into separate executables. Designed for wrappers compiled for `AFL++`. It sets up the environment, creates folders, and launches two tmux sessions with fuzzer instances. After fuzzing ends, it runs the `minimize_out.sh` script for crash clustering. | `./start_fuzz_harness.sh <path/to/bin>` The script will stop if no new paths are found within a certain time. By default, the time is 1 hour. To change it, modify the `TIME` variable (in seconds) inside the script. |


## Example of Fuzzing Run
--------------------------------

Run the container:
```bash
docker run --privileged -it fuzz /bin/bash
```

To enable multi-threaded fuzzing with AFL++, we set up core dumping:
```bash
echo core | tee /proc/sys/kernel/core_pattern
```
With the standard `docker image` build, the `build_fuzz` directory will be created, inside which the fuzzing wrappers will be compiled:
- `parse_sflow_v5_packet_fuzz`
- `process_netflow_packet_v5_fuzz`

To run fuzzing, we use the `start_fuzz_harness` script:

```bash
/src/tests/fuzz/scripts/start_fuzz_harness.sh ./process_netflow_packet_v5_fuzz
```
Or 
```bash
/src/tests/fuzz/scripts/start_fuzz_harness.sh ./parse_sflow_v5_packet_fuzz
```
After starting, a directory `<bin_name>_fuzz_dir` will be created, containing the input and output folders.
A `tmux session` will be started with two tabs — each running an instance of the `AFL++` fuzzer.
Fuzzing will continue until no new paths are found within one hour (this timeout value can be modified in the script).
After that, the tmux session will end, and crash clustering and verification will begin with the `minimize_out.sh` script.

## Other Fuzzing Techniques

### Coarse Code Intervention Using Persistent Mode AFL++
--------------------------------

The fuzzer `AFL++` allows for rewriting parts of the code for fuzzing, significantly increasing the fuzzing speed (the program does not terminate after processing one data set, but instead restarts the cycle with the target function multiple times).

This approach can be used to instrument two different targets:
- `src/netflow_plugin/netflow_collector.cpp : start_netflow_collector(...)`
- `src/sflow_plugin/sflow_collector.cpp : start_sflow_collector(...)`

How the instrumentation looks:
1. Add the construct `__AFL_FUZZ_INIT();` before the target function.
2. Replace the `while (true)` loop with `while (__AFL_LOOP(10000))`.
3. Replace `char udp_buffer[udp_buffer_size];` with `unsigned char * udp_buffer = __AFL_FUZZ_TESTCASE_BUF;`.
4. Replace `int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr*)&client_addr, &address_len);` with `int received_bytes = __AFL_FUZZ_TESTCASE_LEN;`.
5. Build with the AFL++ compiler and sanitizers. No wrappers are needed for compilation.
6. Run fuzzing with: `afl-fuzz -i in -o out -- ./fastnetmon`


### Techniques That Didn't Work
--------------------------------

| Name                | Description                                                                                          |
|---------------------|------------------------------------------------------------------------------------------------------|
| `AFLNet`            | The characteristics of the protocol (lack of feedback) prevent the use of this fuzzer.               |
| `desock`            | Code instrumentation is successful, but the fuzzer does not start and cannot collect feedback. I consider this method **promising**, but the fuzzer requires adjustments. |

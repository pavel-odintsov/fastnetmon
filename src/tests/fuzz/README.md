# Fuzzing

This section describes the fuzzing testing process, the approaches used, and methods applied, including both successful and unsuccessful attempts.

## Navigation
--------------------------------

- [Docker Image](#docker-image)
- [CMake](#cmake)
- [File Structure](#file-structure)
- [Example of Fuzzing Run](#example-of-manual-fuzzing-launch-for-individual-fuzzing-wrappers)
- [Other Fuzzing Techniques](#other-fuzzing-techniques)
- [Fuzzing Launch in Docker Container](#fuzzing-launch-in-docker-container)

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
| `-DENABLE_FUZZ_TEST_DESOCK`       | This option allows modifying the behavior of the standard `socket` function. Now data will come from the input stream instead of the network socket. **Instruments the original `fastnetmon` executable** |
| `-DCMAKE_BUILD_TYPE=Debug`        | Debugging option required for proper debugger functionality. **Do not use on release builds or during tests - false positives may occur with sanitizer functions like `assert()`** |

## File Structure
--------------------------------
```
fuzz/
├── README.md
├── README_rus.md        
├── fastnetmon.conf                              
├── parse_sflow_v5_packet_fuzz.cpp               
├── process_netflow_packet_v5_fuzz.cpp           
└──  scripts/                                    
│   ├── minimize_out.sh
│   ├── afl_pers_mod_instr.sh   
│   ├── start_fuzz_conf_file.sh                  
│   └── start_fuzz_harness.sh                    
```
### File Descriptions
--------------------------------

| File                                    | Description                                                                                   |
|-----------------------------------------|-----------------------------------------------------------------------------------------------|
| `README.md`                             | Documentation in **English** about the fuzz testing of the project.                             |
| `README_rus.md`                         | Documentation in **Russian** about the fuzz testing of the project.                            |
| `fastnetmon.conf`                       | Configuration file for FastNetMon. Only the netflow and sflow protocols are left for operation. |
| `parse_sflow_v5_packet_fuzz.cpp`        | Wrapper for fuzzing the `parse_sflow_v5_packet_fuzz` function using `AFL++`.                   |
| `process_netflow_packet_v5_fuzz.cpp`    | Wrapper for fuzzing the `process_netflow_packet_v5_fuzz` function using `AFL++`.               |

| File/Directory                         | Description                                                                                     | Run                                                                                                 |
|----------------------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `/scripts/`                            | Directory containing scripts for automating fuzzing.                                             |                                                                                                     |
| `/scripts/minimize_out.sh`             | Script for minimizing, verifying, and clustering crash outputs.                                  | `./minimize_out.sh <path_to_out_directory> <./binary>`                                               |
| `/scripts/start_fuzz_conf_file.sh`     | Script for running fuzzing on configuration files. Launches several tmux sessions. Uses options `./fastnetmon --configuration_check --configuration_file`. | Run from the current directory without additional options. The environment is automatically set up. |
| `/scripts/start_fuzz_harness.sh`       | Script for testing binary files compiled from wrappers into separate executables. Designed for wrappers compiled for `AFL++`. It sets up the environment, creates folders, and launches two tmux sessions with fuzzer instances. After fuzzing ends, it runs the `minimize_out.sh` script for crash clustering. | `./start_fuzz_harness.sh <path/to/bin>` The script will stop if no new paths are found within a certain time. By default, the time is 1 hour. To change it, modify the `TIME` variable (in seconds) inside the script. |
| `/scripts/afl_pers_mod_instr.sh` | A script that adds `AFL++` instrumentation for fuzzing in `persistent mode`. **Important! Currently used only with `netflow_collector.cpp` and `sflow_collector.cpp`** | `./afl_pers_mod_instr.sh <netflow_plugin/netflow_collector.cpp>` |


## Example of manual fuzzing launch for individual fuzzing wrappers  
--------------------------------  
Run the container:  
```bash  
docker run --privileged -it fuzz /bin/bash  
```
To run AFL++ fuzzing with multi-threading enabled:

```bash
echo core | tee /proc/sys/kernel/core_pattern  
```
**Don't forget to collect the data corpus in the in folder**

For a test run, use a single sed with a '1':
```bash
mkdir in  
echo "1" >> in/1
```

With a standard docker image build, there will be a folder build_fuzz_harness where the following fuzzing wrappers will be compiled:

- `parse_sflow_v5_packet_fuzz`
- `process_netflow_packet_v5_fuzz`

**Start fuzzing:**
```bash
afl-fuzz -i in -o out -- ./parse_sflow_v5_packet_fuzz  
```
Or

```bash
afl-fuzz -i in -o out -- ./process_netflow_packet_v5_fuzz  
```
- The `build_netflow_pers_mod` folder will contain the code for fuzzing the `process_netflow_packet_v5` function via `AFL++ persistent mode`.
- The `build_sflow_pers_mod` folder will contain the code for fuzzing the `parse_sflow_v5_packet` function via `AFL++ persistent mode`.
If the build is done manually, use the `afl_pers_mod_instr.sh` script to instrument the files.

The fuzzing launch for these functions is the same, as the final executable file fastnetmon is instrumented:

```bash
  afl-fuzz -i in -o out -- ./fastnetmon  
```

**IMPORTANT!**
For multi-thread fuzzing of the fastnetmon file, you need to provide a separate configuration file for each instance of the fuzzer for `fastnetmon`, specifying different ports for protocols, otherwise, the instances will conflict, and multiple threads will not be able to run.


## Example of fuzzing launch via automation script  
--------------------------------  
*All actions take place inside the container, where the working directory is `src`, so paths are constructed relative to this folder.*

For fuzzing, we use the `start_fuzz_harness` script.

For wrappers compiled into binary files:

```bash
/src/tests/fuzz/scripts/start_fuzz_harness.sh ./build_fuzz_harness/process_netflow_packet_v5_fuzz
```
Or

```bash
/src/tests/fuzz/scripts/start_fuzz_harness.sh ./build_fuzz_harness/parse_sflow_v5_packet_fuzz
```

For instrumenting `fastnetmon`:
```bash
/src/tests/fuzz/scripts/start_fuzz_harness.sh ./build_netflow_pers_mod/fastnetmon
```
Or

```bash
/src/tests/fuzz/scripts/start_fuzz_harness.sh ./build_sflow_pers_mod/fastnetmon
```

After launching, a directory `<bin_name>_fuzz_dir` will be created, inside which a folder `input` will be generated.  
A folder `/output` will be created at the root of the system, where fuzzing output files and clustering files will be sent.  
This is necessary to easily access data after fuzzing inside the container (see below).  
A `tmux` session with an AFL++ fuzzer instance will be started.  
Fuzzing will continue until no new paths are found within an hour (this value can be changed inside the script).  
Then, the tmux session will end, and clustering and crash checking will begin using the `minimize_out.sh` script.


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

For these two purposes, an automation script for code instrumentation has been created.  
See more details in the script `/scripts/afl_pers_mod_instr.sh`.


### Other Fuzzing Techniques 
--------------------------------

| Name                | Description                                                                                          |
|---------------------|------------------------------------------------------------------------------------------------------|
| `AFLNet`            | The characteristics of the protocol (lack of feedback) prevent the use of this fuzzer.               |
| `desock`            | Code instrumentation is successful, but the fuzzer does not start and cannot collect feedback. I consider this method **promising**, but the fuzzer requires adjustments. |
| `libfuzzer`         | Wrappers for `libfuzzer` were written and implemented into cmake, but due to the peculiarities of the build and the project's focus on fuzzing via `AFL++`, they were removed from the project. Commit with a working [`libfuzzer`] wrappers (https://github.com/pavel-odintsov/fastnetmon/commit/c3b72c18f0bc7f43b535a5da015c3954d716be22)


## Fuzzing Launch in Docker Container

### A Few Words for Context

Each fuzzer thread requires one system thread.

The `start_fuzz_harness.sh` script includes a time limit for fuzzing.  
The `TIME` variable is responsible for the "last path found" time parameter.  
If this parameter stops resetting, it means the fuzzer has hit a deadlock and there's no point in continuing fuzzing.  
From empirical experience, this parameter should be set to 2 hours. The project has it set to 1 hour.  
If shallow testing is needed, this parameter can be reduced to 10-15 minutes, making the total fuzzing time last a few hours.

### Build and Launch

Build:

```bash
cd fastnetmon
docker build -f tests/Dockerfile.ubuntu-24.04-afl++ -t fuzz .
```

Launch the container:
```
mkdir work
docker run -v $(pwd)/work:/output --privileged -it fuzz /bin/bash -c "/src/tests/fuzz/scripts/start_fuzz_harness.sh ./build_netflow_pers_mod/fastnetmon"
```

This method can be used to launch any wrapper / binary file by simply providing the command from the *Example of fuzzing launch via automation script* section in quotes after the `-c` argument.

After fuzzing is completed, the results will be placed in the host system's work folder—both the results folder and the clustering folder will be there.

The container will have a status exit. It can be manually restarted to check for crashes.



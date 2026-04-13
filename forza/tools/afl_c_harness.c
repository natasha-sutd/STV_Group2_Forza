#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#define MAX_OUTPUT 1024 * 1024 // 1MB buffer for stdout/stderr
#define MAX_ARG_SIZE 1024 * 1024

const char* ERROR_KEYWORDS[] = {
    "Traceback (most recent call last)",
    "invalidity bug",
    "performance bug",
    "bonus crash",
    "bug has been triggered",
    "InvalidCidrFormatError",
    "AddrFormatError",
    "ParseException",
    NULL
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [args...]\n", argv[0]);
        return 1;
    }

    char *bin = argv[1];
    char **new_argv = malloc(argc * sizeof(char *));
    new_argv[0] = bin;

    char *file_buf = NULL;

    for (int i = 2; i < argc; i++) {
        struct stat arg_stat;
        if (stat(argv[i], &arg_stat) == 0 && S_ISREG(arg_stat.st_mode)) {
            // If the parameter points to an existing file, load its contents
            int fd = open(argv[i], O_RDONLY);
            if (fd >= 0) {
                off_t size = arg_stat.st_size;
                file_buf = malloc(size + 1);
                ssize_t rd_bytes = read(fd, file_buf, size);
                if (rd_bytes >= 0) {
                    // Strip trailing newline to mimic bash Command Substitution
                    while (rd_bytes > 0 && (file_buf[rd_bytes - 1] == '\n' || file_buf[rd_bytes - 1] == '\r')) {
                        rd_bytes--;
                    }
                    file_buf[rd_bytes] = '\0';
                    new_argv[i - 1] = file_buf;
                } else {
                    new_argv[i - 1] = argv[i];
                }
                close(fd);
            } else {
                new_argv[i - 1] = argv[i];
            }
        } else {
            new_argv[i - 1] = argv[i];
        }
    }
    new_argv[argc - 1] = NULL;

// Create a temporary file to avoid pipe deadlocks and lingering background writers
    char tmp_tmpl[] = "/tmp/afl_harness_out_XXXXXX";
    int fd_out = mkstemp(tmp_tmpl);
    if (fd_out == -1) {
        perror("mkstemp");
        return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child process: Redirect stdout and stderr to the temp file
        dup2(fd_out, STDOUT_FILENO);
        dup2(fd_out, STDERR_FILENO);
        close(fd_out);

        execv(bin, new_argv);
        perror("execv failed");
        exit(127);
    } else {
        // Parent process: Wait for the child to finish
        int status;
        waitpid(pid, &status, 0);

        // Read the file contents to scan for crash keywords
        lseek(fd_out, 0, SEEK_SET);
        char *output = malloc(MAX_OUTPUT);
        ssize_t total_read = 0;
        ssize_t bytes_read;

        while ((bytes_read = read(fd_out, output + total_read, MAX_OUTPUT - total_read - 1)) > 0) {
            total_read += bytes_read;
            if (total_read >= MAX_OUTPUT - 1) break;
        }
        output[total_read] = '\0';
        
        close(fd_out);
        unlink(tmp_tmpl); // Delete the temp file

        // Fast substring check for all crash markers
        int crash_detected = 0;
        for (int i = 0; ERROR_KEYWORDS[i] != NULL; i++) {
            if (strstr(output, ERROR_KEYWORDS[i]) != NULL) {
                crash_detected = 1;
                break;
            }
        }

        // Also check for signal 128+ terminations or aborts natively
        if (crash_detected || (WIFSIGNALED(status)) || (WIFEXITED(status) && WEXITSTATUS(status) >= 128)) {
            abort(); // Crash the harness to signal AFL
        }

        free(output);
        if (file_buf) free(file_buf);
        free(new_argv);
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        return 1;
    }
}

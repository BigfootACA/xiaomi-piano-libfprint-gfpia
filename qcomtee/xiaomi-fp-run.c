// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * The sensor is a UIO device now, and holding it open is the whole of keeping
 * it powered: the driver raises the supply, pulses reset and unmasks the
 * interrupt on open, and undoes all of it on close. So this program has
 * nothing left to do but open the thing and run the command.
 */
#define XIAOMI_FP_UIO_NAME "xiaomi-fp-uio"
#define XIAOMI_FP_UIO_CLASS "/sys/class/uio"

static volatile sig_atomic_t received_signal;
static volatile sig_atomic_t child_pid;

static void handle_signal(int signal)
{
	received_signal = signal;
	if (child_pid > 0)
		kill(child_pid, signal);
}

static int run_command(char **argv, int *status, int fp_fd, bool pass_fp_fd)
{
	struct sigaction action = {
		.sa_handler = handle_signal,
	};
	struct sigaction default_action = {
		.sa_handler = SIG_DFL,
	};
	sigset_t blocked_signals;
	sigset_t old_mask;
	pid_t pid;
	int ret;

	sigemptyset(&action.sa_mask);
	sigemptyset(&default_action.sa_mask);
	sigemptyset(&blocked_signals);
	sigaddset(&blocked_signals, SIGINT);
	sigaddset(&blocked_signals, SIGTERM);
	sigaddset(&blocked_signals, SIGHUP);
	if (sigprocmask(SIG_BLOCK, &blocked_signals, &old_mask)) {
		perror("block signals");
		return -1;
	}
	if (sigaction(SIGINT, &action, NULL) ||
	    sigaction(SIGTERM, &action, NULL) ||
	    sigaction(SIGHUP, &action, NULL)) {
		perror("sigaction");
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		return -1;
	}
	if (!pid) {
		int inherited_fd = -1;

		if (sigaction(SIGINT, &default_action, NULL) ||
		    sigaction(SIGTERM, &default_action, NULL) ||
		    sigaction(SIGHUP, &default_action, NULL) ||
		    sigprocmask(SIG_SETMASK, &old_mask, NULL)) {
			perror("restore child signals");
			_exit(127);
		}
		if (pass_fp_fd) {
			char value[32];
			int count;

			inherited_fd = fcntl(fp_fd, F_DUPFD, STDERR_FILENO + 1);
			if (inherited_fd < 0) {
				perror("F_DUPFD fingerprint fd");
				_exit(127);
			}
			count = snprintf(value, sizeof(value), "%d", inherited_fd);
			if (count < 0 || (size_t)count >= sizeof(value)) {
				fprintf(stderr, "cannot format inherited fingerprint fd\n");
				close(inherited_fd);
				_exit(127);
			}
			if (setenv("XIAOMI_FP_FD", value, 1)) {
				perror("export XIAOMI_FP_FD");
				close(inherited_fd);
				_exit(127);
			}
		}
		execvp(argv[0], argv);
		perror("execvp");
		if (inherited_fd >= 0)
			close(inherited_fd);
		_exit(127);
	}

	child_pid = pid;
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL)) {
		perror("restore signals");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		child_pid = 0;
		return -1;
	}
	do {
		ret = waitpid(pid, status, 0);
	} while (ret < 0 && errno == EINTR);
	child_pid = 0;
	if (ret < 0) {
		perror("waitpid");
		return -1;
	}

	return 0;
}

/**
 * open_fingerprint_uio() - Find and open the sensor's UIO device.
 *
 * The minor number is whatever UIO handed out, so the device is identified by
 * the name the driver registered rather than by path.
 *
 * Return: An open descriptor, or -1.
 */
static int open_fingerprint_uio(void)
{
	DIR *dir;
	struct dirent *entry;
	int fd = -1;

	dir = opendir(XIAOMI_FP_UIO_CLASS);
	if (!dir) {
		perror(XIAOMI_FP_UIO_CLASS);
		return -1;
	}

	while ((entry = readdir(dir))) {
		char path[PATH_MAX];
		char name[64];
		FILE *file;

		if (strncmp(entry->d_name, "uio", 3))
			continue;

		snprintf(path, sizeof(path), "%s/%s/name",
			 XIAOMI_FP_UIO_CLASS, entry->d_name);
		file = fopen(path, "re");
		if (!file)
			continue;
		if (!fgets(name, sizeof(name), file)) {
			fclose(file);
			continue;
		}
		fclose(file);

		name[strcspn(name, "\n")] = '\0';
		if (strcmp(name, XIAOMI_FP_UIO_NAME))
			continue;

		snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
		fd = open(path, O_RDWR | O_CLOEXEC);
		if (fd < 0)
			perror(path);
		break;
	}

	closedir(dir);

	if (fd < 0)
		fprintf(stderr, "no UIO device named %s; is the module loaded?\n",
			XIAOMI_FP_UIO_NAME);

	return fd;
}

int main(int argc, char **argv)
{
	int child_status = 0;
	int command_index = 1;
	int ret = EXIT_FAILURE;
	bool pass_fp_fd = false;
	int fd;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s [--pass-fp-fd] COMMAND [ARG...]\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (!strcmp(argv[1], "--pass-fp-fd")) {
		if (argc < 3) {
			fprintf(stderr,
				"usage: %s [--pass-fp-fd] COMMAND [ARG...]\n",
				argv[0]);
			return EXIT_FAILURE;
		}
		pass_fp_fd = true;
		command_index = 2;
	}

	fd = open_fingerprint_uio();
	if (fd < 0)
		return EXIT_FAILURE;

	puts("sensor powered and reset; interrupt armed");
	fflush(stdout);

	if (run_command(&argv[command_index], &child_status, fd, pass_fp_fd))
		goto out;
	if (WIFEXITED(child_status))
		ret = WEXITSTATUS(child_status);
	else if (WIFSIGNALED(child_status))
		ret = 128 + WTERMSIG(child_status);

out:
	/* Closing it is what powers the sensor back down. */
	if (close(fd)) {
		perror("close");
		ret = EXIT_FAILURE;
	}
	if (received_signal)
		ret = 128 + received_signal;
	return ret;
}

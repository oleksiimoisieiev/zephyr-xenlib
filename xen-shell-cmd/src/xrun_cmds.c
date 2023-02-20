// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */
#include <stdio.h>
#include <string.h>
#include <xrun.h>
#include <zephyr/shell/shell.h>

const char *get_param(size_t argc, char **argv, char opt)
{
	int pos;

	for (pos = 1; pos < argc; pos++)
		if (argv[pos][0] == '-' && argv[pos][1] == opt) {
			/* Take next value after option */
			pos++;
			return argv[pos];
		}

	/* Use NULL as invalid value */
	return NULL;
}

static int xrun_shell_run(const struct shell *shell, size_t argc, char **argv)
{
	const char *container_id;
	const char *bundle;
	int socket = 0;

	if (argc < 5 || argc > 7) {
		return -EINVAL;
	}

	container_id = get_param(argc, argv, 'c');
	bundle = get_param(argc, argv, 'b');
	socket = atoi(get_param(argc, argv, 's'));

	if (!container_id) {
		shell_error(shell, "Invalid containerid passed to run cmd\n");
		return -EINVAL;
	}

	return xrun_run(bundle, socket, container_id);
}

static int xrun_shell_kill(const struct shell *shell, size_t argc, char **argv)
{
	const char *container_id;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	container_id = get_param(argc, argv, 'c');

	if (!container_id) {
		shell_error(shell, "Invalid containerid passed to kill cmd\n");
		return -EINVAL;
	}

	return xrun_kill(container_id);
}

static int xrun_shell_pause(const struct shell *shell, size_t argc,
			char **argv)
{
	const char *container_id;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	container_id = get_param(argc, argv, 'c');

	if (!container_id) {
		shell_error(shell, "Invalid containerid passed to pause cmd\n");
		return -EINVAL;
	}

	return xrun_pause(container_id);
}

static int xrun_shell_resume(const struct shell *shell, size_t argc,
				char **argv)
{
	const char *container_id;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	container_id = get_param(argc, argv, 'c');

	if (!container_id) {
		shell_error(shell,
					"Invalid containerid passed to resume cmd\n");
		return -EINVAL;
	}

	return xrun_resume(container_id);
}

static int xrun_shell_state(const struct shell *shell, size_t argc,
				char **argv)
{
	const char *container_id;
	int state;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	container_id = get_param(argc, argv, 'c');

	if (!container_id) {
		shell_error(shell, "Invalid containerid passed to kill cmd\n");
		return -EINVAL;
	}
	state = xrun_state(container_id);
	printf("%s state is %d\n", container_id, state);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xrun,
	SHELL_CMD_ARG(run, NULL,
		" Create xrun container\n"
		" Usage: create -c <container_id> -b <bundle_path> -s <socket>\n",
		xrun_shell_run, 7, 0),
	SHELL_CMD_ARG(kill, NULL,
		" Destroy container\n"
		" Usage: kill -c <container_id>\n",
		xrun_shell_kill, 3, 0),
	SHELL_CMD_ARG(pause, NULL,
		" Pause container\n"
		" Usage: pause -c <container_id>\n",
		xrun_shell_pause, 3, 0),
	SHELL_CMD_ARG(resume, NULL,
		" Resume container\n"
		" Usage: resume -c <container_id>\n",
		xrun_shell_resume, 3, 0),
	SHELL_CMD_ARG(state, NULL,
		" Show container state\n"
		" Usage: state -c <container_id>\n",
		xrun_shell_state, 3, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xrun, &subcmd_xrun, "XRun commands", NULL, 2, 0);

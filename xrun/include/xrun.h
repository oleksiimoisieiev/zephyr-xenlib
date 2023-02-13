/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XRUN_H_
#define XRUN_H_

int xrun_run(const char *bundle, int console_socket, const char *container_id);
int xrun_pause(const char *container_id);
int xrun_resume(const char *container_id);
int xrun_kill(const char *container_id);
int xrun_state(const char *container_id);

#endif /* XRUN_H_ */

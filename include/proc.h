/*
 * Copyright 2026 JongHoon Shim.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*==== FILE DESCRIPTION =====================================================*/

/*!
 * @file    proc.h
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   프로세스 관련 유틸리티 함수 모음
*/

#ifndef _PROC_H
#define _PROC_H

/*==== INCLUDES =============================================================*/

#include <stdbool.h>
#include <sys/types.h>

/*==== GLOBAL DEFINES =======================================================*/
/*==== GLOBAL STRUCTS =======================================================*/
/*==== GLOBAL VARIABLES =====================================================*/
/*==== GLOBAL FUNCTIONS DECLARATION =========================================*/

bool is_process_running(pid_t pid);
int get_proc_name_comm(pid_t pid, char *proc_name, size_t proc_name_size);

#endif

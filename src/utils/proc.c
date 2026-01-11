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
 * @file    proc.c
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   프로세스 관련 유틸리티 함수 모음
*/

/*==== INCLUDES =============================================================*/

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "proc.h"
#include "common/types.h"

/*==== LOCAL DEFINES ========================================================*/
/*==== LOCAL STRUCTS ========================================================*/
/*==== LOCAL VARIABLES ======================================================*/
/*==== LOCAL FUNCTIONS DECLARATION ==========================================*/
/*==== FUNCTIONS ============================================================*/

/*!
 * @brief   PID로부터 프로세스가 동작중인지 확인하는 함수
 * @param   pid PID
 * @return  bool    동작 중 true, 미동작 false
*/
bool is_process_running(pid_t pid)
{
    // 시그널 0을 보내서 살이있는지 확인
    if (0 == kill(pid, 0) || EPERM == errno) {
        return true;
    }
    return false;
}

/*!
 * @brief   PID로부터 프로세스명 획득 (comm)
 * @param   pid             PID
 * @param   proc_name       프로세스명 저장 버퍼
 * @param   proc_name_size  프로세스명 저장 버퍼 사이즈
 * @return  int             성공 시 0, 실패 시 -1
 * @warning
 *  최대 15자까지만 획득 가능
*/
int get_proc_name_comm(pid_t pid, char *proc_name, size_t proc_name_size)
{
    char path[BUF_SIZE_256] = {0};
    FILE *fp = NULL;
    size_t len = 0;
    int err = 0;

    if (NULL == proc_name || 0 == proc_name_size) {
        return -1;
    }

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fp = fopen(path, "r");
    if (NULL == fp) {
        return -1;
    }

    // 프로세스명 읽기
    if (NULL != fgets(proc_name, proc_name_size, fp)) {
        len = strlen(proc_name);
        if (len > 0) {
            // 끝에 개행 문자가 포함되어 있으면 제거
            if ('\n' == proc_name[len - 1]) {
                proc_name[len - 1] = '\0';
            }
        }
        else {
            err = -1;
        }
    }
    else {
        err = -1;
    }

    fclose(fp);

    return err;
}

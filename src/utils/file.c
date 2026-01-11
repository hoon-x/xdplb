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
 * @file    file.c
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   파일 관련 유틸리티 함수 모음
*/

/*==== INCLUDES =============================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "file.h"
#include "common/types.h"

/*==== LOCAL DEFINES ========================================================*/
/*==== LOCAL STRUCTS ========================================================*/
/*==== LOCAL VARIABLES ======================================================*/
/*==== LOCAL FUNCTIONS DECLARATION ==========================================*/
/*==== FUNCTIONS ============================================================*/

/*!
 * @brief   상위 디렉터리까지 재귀적으로 생성
 * @param   path    경로
 * @return  int     성공 시 0, 실패 시 -1
*/
int mkdir_p(const char *path)
{
    char temp[BUF_SIZE_256] = {0};
    char *p = NULL;
    int len = 0;

    if (NULL == path || '\0' == *path) {
        return -1;
    }

    len = snprintf(temp, sizeof(temp), "%s", path);

    // 끝에 '/'가 있으면 제거
    if ('/' == temp[len - 1]) {
        temp[len - 1] = '\0';
    }

    // 경로 앞에서부터 순회하며 디렉터리 생성
    for (p = temp + 1; *p; ++p) {
        if ('/' == *p) {
            *p = '\0';

            if (0 != mkdir(temp, 0755) && EEXIST != errno) {
                return -1;
            }

            *p = '/';
        }
    }

    // 마지막 경로 생성
    if (0 != mkdir(temp, 0755) && EEXIST != errno) {
        return -1;
    }

    return 0;
}

/*!
 * @brief   텍스트 파일 읽기 함수
 * @param   file_path       읽을 파일 경로
 * @return  unsigned char * 성공 시 버퍼, 실패 시 NULL
*/
char *read_text_file(const char *file_path)
{
    FILE *fp = NULL;
    char *buffer = NULL;
    long len = 0;
    int err = -1;

    if (NULL == file_path || '\0' == *file_path) {
        return NULL;
    }

    fp = fopen(file_path, "rb");
    if (NULL == fp) {
        return NULL;
    }

    do {
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (len <= 0) {
            break;
        }

        buffer = (char *)malloc(len + 1);
        if (NULL == buffer) {
            break;
        }

        if ((size_t)len != fread(buffer, 1, len, fp)) {
            break;
        }
        buffer[len] = '\0';

        err = 0;
    } while (0);

    fclose(fp);

    if (0 != err) {
        if (NULL != buffer) {
            free(buffer);
            buffer = NULL;
        }
    }

    return buffer;
}

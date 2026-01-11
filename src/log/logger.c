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
 * @file    logger.c
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   로거 소스 파일
*/

/*==== INCLUDES =============================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/stat.h>

#include "logger.h"
#include "config.h"
#include "file.h"
#include "common/types.h"

/*==== LOCAL DEFINES ========================================================*/
/*==== LOCAL STRUCTS ========================================================*/

typedef struct logger {
    FILE *fp;
    char log_path[BUF_SIZE_256];
    size_t curr_log_size;
    bool enabled;
    bool debug;
    pthread_mutex_t lock;
} logger_t;

/*==== LOCAL VARIABLES ======================================================*/

static const char *g_log_level_str[LVL_MAX] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

static logger_t g_logger = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/*==== LOCAL FUNCTIONS DECLARATION ==========================================*/
/*==== FUNCTIONS ============================================================*/

/*!
 * @brief   로그 출력 함수
 * @param   level   로그 레벨
 * @param   format  포맷 문자열
 * @param   ...     가변 인자
*/
void print_log(LogLevel level, const char *format, ...)
{
    FILE *fp = NULL;
    va_list args;
    time_t now = 0;
    struct tm tm;
    char time_buf[BUF_SIZE_32] = {0};
    char log_buf[BUF_SIZE_2K] = {0};
    char va_buf[BUF_SIZE_1K] = {0};

    if (level >= LVL_MAX || NULL == format) {
        return;
    }

    // 디버그 모드에서만 디버그 로그 출력
    if (!g_config.debug && LVL_DEBUG == level) {
        return;
    }

    // 시간 정보 획득
    time(&now);
    localtime_r(&now, &tm);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);

    // 로그 메시지 추출
    va_start(args, format);
    vsnprintf(va_buf, sizeof(va_buf), format, args);
    va_end(args);
    
    // 로그 생성
    snprintf(log_buf, sizeof(log_buf), "[%s][%s]%s\n", time_buf, g_log_level_str[level], va_buf);

    // 로그 출력
    fp = (level >= LVL_WARN) ? stderr : stdout;
    fputs(log_buf, fp);
}

/*!
 * @brief   로그 기록 함수
 * @param   level   로그 레벨
 * @param   format  포맷 문자열
 * @param   ...     가변 인자
*/
void write_log(LogLevel level, const char *format, ...)
{
    va_list args;
    time_t now = 0;
    struct tm tm;
    char time_buf[BUF_SIZE_32] = {0};
    char log_buf[BUF_SIZE_2K] = {0};
    char va_buf[BUF_SIZE_1K] = {0};
    int len = 0;

    if (level >= LVL_MAX || NULL == format) {
        return;
    }

    // 디버그 모드에서만 디버그 로그 출력
    if (!g_logger.debug && LVL_DEBUG == level) {
        return;
    }

    // 시간 정보 획득
    time(&now);
    localtime_r(&now, &tm);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);

    // 로그 메시지 추출
    va_start(args, format);
    vsnprintf(va_buf, sizeof(va_buf), format, args);
    va_end(args);
    
    // 로그 생성
    len = snprintf(log_buf, sizeof(log_buf), "[%s][%s][PID:%d]%s\n", 
        time_buf, g_log_level_str[level], g_config.pid, va_buf);

    if (g_logger.debug) {
        fputs(log_buf, (level > LVL_INFO) ? stderr : stdout);
    }

    pthread_mutex_lock(&g_logger.lock);
    do {
        // 로거 초기화가 안됐으면 기록하지 않음
        if (!g_logger.enabled) {
            break;
        }

        // 현재 로그 파일 사이즈가 10MB 이상일 경우 로테이트
        if (g_logger.curr_log_size >= (10 * MB)) {
            if (NULL != g_logger.fp) {
                fclose(g_logger.fp);
                g_logger.fp = NULL;
            }

            snprintf(va_buf, sizeof(va_buf), "%s.bak", g_logger.log_path);
            if (0 != rename(g_logger.log_path, va_buf)) {
                break;
            }
            g_logger.curr_log_size = 0;
        }

        // 로그 파일을 오픈하고 있지 않는 경우 오픈해줌
        if (NULL == g_logger.fp) {
            g_logger.fp = fopen(g_logger.log_path, "a");
            if (NULL == g_logger.fp) {
                break;
            }
        }

        // 파일에 로그 기록
        if ((size_t)len == fwrite(log_buf, 1, (size_t)len, g_logger.fp)) {
            // 로그 사이즈 누적
            g_logger.curr_log_size += len;
        }
        else {
            // 로그 기록 실패 시 파일 닫아줌
            fclose(g_logger.fp);
            g_logger.fp = NULL;
        }
    } while (0);
    pthread_mutex_unlock(&g_logger.lock);
}

/*!
 * @brief   로거 초기화
 * @param   log_path    로그 경로
 * @param   debug       디버그 모드 플래그
 * @return  int         성공 시 0, 실패 시 -1
*/
int init_logger(const char *log_path, bool debug)
{
    struct stat st;
    char path[BUF_SIZE_256] = {0};
    char *dir = NULL;

    if (NULL == log_path || '\0' == *log_path) {
        return -1;
    }

    // 로그 경로 생성
    strncpy(path, log_path, sizeof(path) - 1);
    dir = dirname(path);
    if (0 != mkdir_p(dir)) {
        return -1;
    }

    // 기존 로그 파일 존재 시 사이즈 저장
    if (0 == stat(log_path, &st)) {
        g_logger.curr_log_size = st.st_size;
        // 기존 로그 파일이 10MB 이상인 경우
        if (g_logger.curr_log_size >= (10 * MB)) {
            // 로그 파일 백업
            snprintf(path, sizeof(path), "%s.bak", log_path);
            if (0 == rename(log_path, path)) {
                g_logger.curr_log_size = 0;
            }
        }
    }

    // 로그 파일 경로 저장
    strncpy(g_logger.log_path, log_path, sizeof(g_logger.log_path) - 1);
    // 디버그 모드 플래그 저장
    g_logger.debug = debug;
    // 로거 활성화
    g_logger.enabled = true;

    return 0;
}

/*!
 * @brief   로거 자원 정리
*/
void destroy_logger(void)
{
    pthread_mutex_lock(&g_logger.lock);
    g_logger.enabled = false;
    if (NULL != g_logger.fp) {
        fclose(g_logger.fp);
        g_logger.fp = NULL;
    }
    g_logger.debug = false;
    memset(g_logger.log_path, 0x00, sizeof(g_logger.log_path));
    pthread_mutex_unlock(&g_logger.lock);
}

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
 * @file    logger.h
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   로거 헤더 파일
*/

#ifndef _LOGGER_H
#define _LOGGER_H

/*==== INCLUDES =============================================================*/

#include <stdbool.h>

/*==== GLOBAL DEFINES =======================================================*/

#define PRINT_DEBUG(fmt, ...) print_log(LVL_DEBUG, "[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define PRINT_INFO(fmt, ...)  print_log(LVL_INFO,  " " fmt, ##__VA_ARGS__)
#define PRINT_WARN(fmt, ...)  print_log(LVL_WARN,  " " fmt, ##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...) print_log(LVL_ERROR, " " fmt, ##__VA_ARGS__)
#define PRINT_FATAL(fmt, ...) print_log(LVL_FATAL, "[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__); exit(1)

#define LOGX_DEBUG(fmt, ...) write_log(LVL_DEBUG, "[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define LOGX_INFO(fmt, ...)  write_log(LVL_INFO,  " " fmt, ##__VA_ARGS__)
#define LOGX_WARN(fmt, ...)  write_log(LVL_WARN,  " " fmt, ##__VA_ARGS__)
#define LOGX_ERROR(fmt, ...) write_log(LVL_ERROR, " " fmt, ##__VA_ARGS__)
#define LOGX_FATAL(fmt, ...) write_log(LVL_FATAL, "[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__); exit(1)

// DEBUG: 개발 모드에서는 파일/라인 정보 출력, syslog는 메시지만 기록
#define SYSLOG_DEBUG(fmt, ...) \
do { \
    if (g_config.debug) { \
        PRINT_DEBUG(fmt, ##__VA_ARGS__); \
    } else { \
        syslog(LOG_DEBUG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

// INFO: 일반 정보
#define SYSLOG_INFO(fmt, ...) \
do { \
    if (g_config.debug) { \
        PRINT_INFO(fmt, ##__VA_ARGS__); \
    } else { \
        syslog(LOG_INFO, fmt, ##__VA_ARGS__); \
    } \
} while (0)

// WARN: 경고 (syslog 상수는 LOG_WARNING 사용)
#define SYSLOG_WARN(fmt, ...) \
do { \
    if (g_config.debug) { \
        PRINT_WARN(fmt, ##__VA_ARGS__); \
    } else { \
        syslog(LOG_WARNING, fmt, ##__VA_ARGS__); \
    } \
} while (0)

// ERROR: 에러 (syslog 상수는 LOG_ERR 사용)
#define SYSLOG_ERROR(fmt, ...) \
do { \
    if (g_config.debug) { \
        PRINT_ERROR(fmt, ##__VA_ARGS__); \
    } else { \
        syslog(LOG_ERR, fmt, ##__VA_ARGS__); \
    } \
} while (0)

// FATAL: 치명적 에러 (로그 기록 후 프로세스 종료)
// PRINT_FATAL에 exit(1)이 포함되어 있으므로, else 블록에서도 exit(1)을 호출해야 함
#define SYSLOG_FATAL(fmt, ...) \
do { \
    if (g_config.debug) { \
        PRINT_FATAL(fmt, ##__VA_ARGS__); \
    } else { \
        syslog(LOG_CRIT, fmt, ##__VA_ARGS__); \
        exit(1); \
    } \
} while (0)

/*==== GLOBAL STRUCTS =======================================================*/

typedef enum {
    LVL_DEBUG = 0,
    LVL_INFO,
    LVL_WARN,
    LVL_ERROR,
    LVL_FATAL,
    LVL_MAX
} LogLevel;

/*==== GLOBAL VARIABLES =====================================================*/
/*==== GLOBAL FUNCTIONS DECLARATION =========================================*/

void print_log(LogLevel level, const char *format, ...);
void write_log(LogLevel level, const char *format, ...);
int init_logger(const char *log_path, bool debug);
void destroy_logger(void);

#endif

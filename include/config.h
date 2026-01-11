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
 * @file    config.h
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.09
 * @brief   설정 정보 헤더 파일
*/

#ifndef _CONFIG_H
#define _CONFIG_H

/*==== INCLUDES =============================================================*/

#include <stdbool.h>
#include <sys/types.h>

#include "common/types.h"

/*==== GLOBAL DEFINES =======================================================*/

#define VERSION     "1.0.0"
#define MODULE_NAME "xdplb"
#ifndef BUILD_DATE
#define BUILD_DATE  "unknown"
#endif

#define LOG_PATH        "log/" MODULE_NAME ".log"
#define PID_PATH        "var/." MODULE_NAME ".pid"
#define LB_CONF_PATH    "conf/lb_conf.json"

/*==== GLOBAL STRUCTS =======================================================*/

typedef struct config {
    bool running;                               // 메인 루프 실행 제어 플래그
    bool debug;                                 // 디버그 모드 활성화 여부
    pid_t pid;                                  // 현재 프로세스 PID
    char ifnames[MAX_INTERFACES][BUF_SIZE_32];  // 관리 대상 네트워크 인터페이스명 목록
    int ifindices[MAX_INTERFACES];              // 관리 대상 네트워크 인터페이스 커널 인덱스
    int if_count;                               // 현재 등록된 인터페이스 총 개수
} config_t;

/*==== GLOBAL VARIABLES =====================================================*/

extern config_t g_config;

/*==== GLOBAL FUNCTIONS DECLARATION =========================================*/

#endif

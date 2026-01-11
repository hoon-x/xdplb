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
 * @file    types.h
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   타입 정의 헤더 파일
*/

#ifndef _TYPES_H
#define _TYPES_H

/*==== INCLUDES =============================================================*/
/*==== GLOBAL DEFINES =======================================================*/

#define BUF_SIZE_16     16
#define BUF_SIZE_32     32
#define BUF_SIZE_64     64
#define BUF_SIZE_128    128
#define BUF_SIZE_256    256
#define BUF_SIZE_512    512
#define BUF_SIZE_1K     1024
#define BUF_SIZE_2K     2048

#define KB  (1024ULL)
#define MB  (1024ULL * 1024ULL)

// 최대 관리 가능한 인터페이스 개수
#define MAX_INTERFACES  16
// VIP 당 최대 리얼 서버 개수
#define MAX_REAL_SERVERS 16
// 최대 VIP 개수
#define MAX_VIP_NUM     1024

#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))

/*==== GLOBAL STRUCTS =======================================================*/
/*==== GLOBAL VARIABLES =====================================================*/
/*==== GLOBAL FUNCTIONS DECLARATION =========================================*/

#endif

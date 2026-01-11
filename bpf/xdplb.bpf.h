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
 * @file    xdplb.bpf.h
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   eBPF XDP 헤더 파일
*/

#ifndef _XDPLB_BPF_H
#define _XDPLB_BPF_H

/*==== INCLUDES =============================================================*/

#include <linux/bpf.h>

#include "common/common.h"

/*==== GLOBAL DEFINES =======================================================*/
/*==== GLOBAL STRUCTS =======================================================*/

// 커서(Cursor) 구조체: 파싱 위치를 추적하기 위함
struct packet_cursor {
    void *pos;
    void *end;
};

/*==== GLOBAL VARIABLES =====================================================*/

// 패킷 통계 누적 맵 (Per CPU Array)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datarec);
} xdp_stats_map SEC(".maps");

// VIP 관리 맵 (Hash Map)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VIP_NUM);
    __type(key, struct vip_definition);
    __type(value, struct vip_meta);
} vip_map SEC(".maps");

// 리얼 서버 맵
// Key는 index로 계산: (vip_id * MAX_REAL_SERVERS) + server_index
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_VIP_NUM * MAX_REAL_SERVERS);
    __type(key, __u32);
    __type(value, struct real_definition);
} real_server_map SEC(".maps");

/*==== GLOBAL FUNCTIONS DECLARATION =========================================*/

#endif

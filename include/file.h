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
 * @file    file.h
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   파일 관련 유틸리티 함수 모음
*/

#ifndef _FILE_H
#define _FILE_H

/*==== INCLUDES =============================================================*/
/*==== GLOBAL DEFINES =======================================================*/
/*==== GLOBAL STRUCTS =======================================================*/
/*==== GLOBAL VARIABLES =====================================================*/
/*==== GLOBAL FUNCTIONS DECLARATION =========================================*/

int mkdir_p(const char *path);
char *read_text_file(const char *file_path);

#endif

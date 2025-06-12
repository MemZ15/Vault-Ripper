#include "includes.h"

uintptr_t globals::stored_one{ 0 };
_OBJECT_TYPE* globals::stored_two{ nullptr };
void* globals::stored_three{ nullptr };
void* globals::stored_four{ nullptr };
UINTN globals::global_sys_caller{ 0 };



// TEMP FIX //
#pragma once
#include "includes.h"

namespace modules {

	uintptr_t throw_idt_exception(uintptr_t &base, size_t &base_size);

	uintptr_t find_base_from_exception( uintptr_t search_addr, size_t search_limit, uintptr_t& base, size_t& size );

	uintptr_t traverse_export_list( const char* module_name, uintptr_t base );

}
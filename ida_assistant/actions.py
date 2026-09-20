"""Authoritative routing manifest for dynamically registered upstream IDA actions."""

READ_ACTIONS = frozenset(
    {
        "get_metadata",
        "get_function_by_name",
        "get_function_by_address",
        "get_current_address",
        "get_current_function",
        "convert_number",
        "list_functions",
        "list_globals_filter",
        "list_globals",
        "list_imports",
        "list_strings_filter",
        "list_strings",
        "list_local_types",
        "decompile_function",
        "disassemble_function",
        "get_xrefs_to",
        "get_xrefs_to_field",
        "get_callees",
        "get_callers",
        "get_entry_points",
        "get_global_variable_value_by_name",
        "get_global_variable_value_at_address",
        "get_stack_frame_variables",
        "get_defined_structures",
        "analyze_struct_detailed",
        "get_struct_at_address",
        "get_struct_info_simple",
        "search_structures",
        "read_memory_bytes",
        "data_read_byte",
        "data_read_word",
        "data_read_dword",
        "data_read_qword",
        "data_read_string",
    }
)

EDIT_ACTIONS = frozenset(
    {
        "set_comment",
        "rename_local_variable",
        "rename_global_variable",
        "set_global_variable_type",
        "patch_address_assembles",
        "rename_function",
        "set_function_prototype",
        "declare_c_type",
        "set_local_variable_type",
        "rename_stack_frame_variable",
        "create_stack_frame_variable",
        "set_stack_frame_variable_type",
        "delete_stack_frame_variable",
    }
)

DEBUG_ACTIONS = frozenset(
    {
        "dbg_get_registers",
        "dbg_get_call_stack",
        "dbg_list_breakpoints",
        "dbg_start_process",
        "dbg_exit_process",
        "dbg_continue_process",
        "dbg_run_to",
        "dbg_set_breakpoint",
        "dbg_step_into",
        "dbg_step_over",
        "dbg_delete_breakpoint",
        "dbg_enable_breakpoint",
    }
)

SUPPORTED_ACTIONS = READ_ACTIONS | EDIT_ACTIONS | DEBUG_ACTIONS

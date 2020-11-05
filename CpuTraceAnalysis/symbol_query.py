from .libcputrace.MachineCode.SymbolTable import SymbolTable

symtab = SymbolTable()
symtab.add_symbol_from_objdump_dism("../debug_output/pk_c920.dism")
symtab.add_symbol_from_objdump_dism("../debug_output/hello.dism")

while (query := input("Query (addr)? ")) != "q":
    try:
        query_addr = int(query, 16)
    except ValueError:
        print("Invalid input [%s]." % query)
    else:
        s = symtab.find_symbol_by_addr(query_addr)  # type: SymbolTable.Symbol
        if s:
            print("%08X - %08X, [%s] - <%s>" % (s.start_addr, s.end_addr, s.symbol_name, s.module_name))
        else:
            print("None")

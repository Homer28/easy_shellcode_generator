# easy_shellcode_generator
A simple project designed to generate x64 shellcodes for Windows.

VS project is configured in such a way as to create position-independent shellcode using the MSVC compiler. The compiled code is stored in a single section of the compiled file and can be easily converted into shellcode using a Python script.

The finished example contains shellcode for dns resolve. If desired, this code can be changed according to needs.

# Build
To build, use Visual Studio 2022 and Python3 (pefile package required).
# Usage
- Build the solution;
- Run converter script `py python/pe_converter.py`.
- ???

  

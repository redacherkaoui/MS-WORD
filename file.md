

1. **Requirements**

   * Visual Studio (with “Desktop development with C++” workload)
   * Open x64 native tools command prompt for for vs to compile it 
   * No extra libs—`DbgHelp.lib` is pulled in via the `#pragma` in the code.

2. **Steps**

   ```bat
   REM 1. Open “x64 Native Tools Command Prompt for VS”
   REM 2. cd into the directory containing poc.c
   cl /O2 /MD /TC poc.c /link /SUBSYSTEM:CONSOLE /OUT:poc.exe
   REM 3. (Optional) del poc.pdb  &   upx --best poc.exe
   ```

3. **Result**

   * `poc.exe` will be your standalone exploit binary.
  
   
## Note
This is a **local** proof-of-concept only—I have **not** been able to achieve full **remote** code execution with this exploit.


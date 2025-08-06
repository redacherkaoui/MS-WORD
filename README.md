The core of the bug in **TextShaping.dll** can be seen in three small snippets:

1. **Trusting an attacker-controlled `numTables`**

   ```c
   // read from SFNT header without bounds check
   uint16_t numTables   = 0x5000;  // ← attacker sets this to a huge value
   ```

2. **Allocating a too-small buffer**

   ```c
   const size_t dirSize    = 12 + 2*16;
   const size_t gsubOffset = 0x50;
   const size_t gsubSize   = 0x30;
   // only allocates MAX(dirSize, gsubOffset) + gsubSize = 0x50 + 0x30 = 0x80 bytes
   size_t totalSize        = MAX(dirSize, gsubOffset) + gsubSize;
   uint8_t *buf = malloc(totalSize);
   ```

3. **Writing the crafted GSUB table out-of-bounds**

   ```c
   // write GSUB table header at buf+0x50, then subtable entries beyond buf+0x80
   write_u32_be(buf + 12 + 8, gsubOffset);
   write_u32_be(buf + 12 +12, gsubSize);
   // …later, a loop writes past buf+0x80 and corrupts heap metadata…
   ```

By combining an oversized `numTables` with a fixed-size allocation and unbounded writes into the GSUB subtable area, the routine overruns the heap and hands control to attacker-supplied code.

/*
   american fuzzy lop - postprocessor library example
   --------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Postprocessor libraries can be passed to afl-fuzz to perform final cleanup
   of any mutated test cases - for example, to fix up checksums in PNG files.

   Please heed the following warnings:

   1) In almost all cases, it is more productive to comment out checksum logic
      in the targeted binary (as shown in ../libpng_no_checksum/). One possible
      exception is the process of fuzzing binary-only software in QEMU mode.

   2) The use of postprocessors for anything other than checksums is questionable
      and may cause more harm than good. AFL is normally pretty good about
      dealing with length fields, magic values, etc.

   3) Postprocessors that do anything non-trivial must be extremely robust to
      gracefully handle malformed data and other error conditions - otherwise,
      they will crash and take afl-fuzz down with them. Be wary of reading past
      *len and of integer overflows when calculating file offsets.

   In other words, THIS IS PROBABLY NOT WHAT YOU WANT - unless you really,
   honestly know what you're doing =)

   With that out of the way: the postprocessor library is passed to afl-fuzz
   via AFL_POST_LIBRARY. The library must be compiled with:

     gcc -shared -Wall -O3 post_library.so.c -o post_library.so

   AFL will call the afl_postprocess() function for every mutated output buffer.
   From there, you have three choices:

   1) If you don't want to modify the test case, simply return the original
      buffer pointer ('in_buf').

   2) If you want to skip this test case altogether and have AFL generate a
      new one, return NULL. Use this sparingly - it's faster than running
      the target program with patently useless inputs, but still wastes CPU
      time.

   3) If you want to modify the test case, allocate an appropriately-sized
      buffer, move the data into that buffer, make the necessary changes, and
      then return the new pointer. You can update *len if necessary, too.

      Note that the buffer will *not* be freed for you. To avoid memory leaks,
      you need to free it or reuse it on subsequent calls (as shown below).

      *** DO NOT MODIFY THE ORIGINAL 'in_buf' BUFFER. ***

    Aight. The example below shows a simple postprocessor that tries to make
    sure that all input files start with "GIF89a".

    PS. If you don't like C, you can try out the unix-based wrapper from
    Ben Nagy instead: https://github.com/bnagy/aflfix

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


/* The actual postprocessor routine called by afl-fuzz: */

const unsigned char* afl_postprocess(const unsigned char* in_buf,
                                     unsigned int* len) {
// unsigned char* afl_postprocess(unsigned char* in_buf,
//                                      unsigned int* len) {

  // for(int i=0; i< 184; i++) {
  //   if(i%16==0)
  //   { 
  //     printf("\n"); 
  //   }
  //   printf("%x ", (uint8_t)(in_buf[i]));
  // }
  
  static unsigned char* saved_buf;
  unsigned char* new_buf;
  // unsigned char* new_buf = (unsigned char*)in_buf;
  unsigned int pos = 0;
  /* Skip execution altogether for buffers shorter than 16 bytes (just to
     show how it's done). We can trust *len to be sane. */

  if (*len < 16) return in_buf;

  new_buf = realloc(saved_buf, *len);
  saved_buf = new_buf;
  memcpy(new_buf, in_buf, *len);

  /*  */
  while (pos + 16 <= *len) {
    unsigned int real_cksum, temp, temp2, flag;
    uint16_t t1 = 0;
    uint8_t t2 = 0;
    temp = 0xFFFF;
    for (unsigned char i = 1; i < 12; i=i+2)
    {
      temp = temp ^ new_buf[pos+i];
      for (unsigned char j = 1; j <= 8; j++)
      {
        flag = temp & 0x0001;
        temp >>=1;
        if (flag)
          temp ^= 0xA001;
      }
    }
    // Reverse byte order.
    temp2 = temp >> 8;
    temp = (temp << 8) | temp2;
    temp &= 0xFFFF;
    // the returned value is already swapped
    // crcLo byte is first & crcHi byte is last
    real_cksum = temp;

    t1 = real_cksum << 8;
    t2 = t1 >> 8;

    new_buf[pos + 13] = (char)(real_cksum >> 8);
    new_buf[pos + 15] = (char)(t2);

    pos += 16;
  }

  // /* Do nothing for buffers that already start with the expected header. */

  // if (!memcmp(in_buf, HEADER, strlen(HEADER))) return in_buf;

  // /* Allocate memory for new buffer, reusing previous allocation if
  //    possible. */

  // new_buf = realloc(saved_buf, *len);

  // /* If we're out of memory, the most graceful thing to do is to return the
  //    original buffer and give up on modifying it. Let AFL handle OOM on its
  //    own later on. */

  // if (!new_buf) return in_buf;
  // saved_buf = new_buf;

  // /* Copy the original data to the new location. */

  // memcpy(new_buf, in_buf, *len);

  // /* Insert the new header. */

  // memcpy(new_buf, HEADER, strlen(HEADER));

  // /* Return modified buffer. No need to update *len in this particular case,
  //    as we're not changing it. */

  return new_buf;

}

// 0x5B,0x01,0x45,0x46,0x41,0x55,0x8B,0x76,0x40,0x42,0xC2,0x42,0x00,0x42,0x10,0x65,
// 0x55,0xA6,0xA6,0xA6,0xA6,0xA6,0x6D,0x55,0x15,0x10,0x00,0xFF,0x3D,0x3D,0x35,0x89,
// 0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3B,0xAD,
// 0x3D,0x3D,0x3D,0x3D,0x6F,0x74,0x34,0x8B,0x76,0x40,0x42,0xC2,0x42,0x00,0x7E,0xA0,
// 0x40,0x55,0xA6,0xA6,0xA6,0xA6,0x40,0x40,0x55,0x4C,0x54,0x5D,0x20,0x78,0x44,0x92,
// 0xA6,0x98,0xA6,0x54,0x5D,0x20,0x0E,0x66,0x66,0x75,0x7A,0x7A,0x69,0x00,0x52,0x2A,
// 0xF7,0x20,0x00,0x80,0x04,0x94,0x01,0x3F,0x1C,0x78,0x78,0x78,0x26,0x20,0x7B,0x1F,
// 0x43,0x20,0x00,0x00,0x80,0x00,0x75,0x7A,0x7A,0x69,0x00,0x01,0x01,0xF7,0xCB,0x93,
// 0x80,0x04,0x94,0x01,0x3F,0x1C,0x78,0x78,0x78,0x26,0x20,0x08,0x20,0x43,0x95,0x71,
// 0x00,0x80,0x00,0xFF,0x20,0x78,0xFF,0x20,0x78,0x64,0x78,0x23,0x26,0x00,0x82,0xC3,
// 0xFF,0xFF,0xE7,0x7A,0x40,0x7F,0x00,0x45,0x46,0x40,0x55,0x4C,0x54,0x5D,0xEE,0x45,
// 0xB5,0x78,0x78,0x21,0x75,0x7A,0x7A,0xFF

// int main() {
//   printf("Here\n");
//   uint8_t src[184] = {0x5B,0x01,0x45,0x46,0x41,0x55,0x8B,0x76,0x40,0x42,0xC2,0x42,0x00,0x42,0x00,0x00,
//   0x55,0xA6,0xA6,0xA6,0xA6,0xA6,0x6D,0x55,0x15,0x10,0x00,0xFF,0x3D,0x3D,0x00,0x00,
//   0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x3D,0x00,0x00,
//   0x3D,0x3D,0x3D,0x3D,0x6F,0x74,0x34,0x8B,0x76,0x40,0x42,0xC2,0x42,0x00,0x00,0x00,
//   0x40,0x55,0xA6,0xA6,0xA6,0xA6,0x40,0x40,0x55,0x4C,0x54,0x5D,0x20,0x78,0x00,0x00,
//   0xA6,0x98,0xA6,0x54,0x5D,0x20,0x0E,0x66,0x66,0x75,0x7A,0x7A,0x69,0x00,0x00,0x00,
//   0xF7,0x20,0x00,0x80,0x04,0x94,0x01,0x3F,0x1C,0x78,0x78,0x78,0x26,0x20,0x00,0x00,
//   0x43,0x20,0x00,0x00,0x80,0x00,0x75,0x7A,0x7A,0x69,0x00,0x01,0x01,0xF7,0x00,0x00,
//   0x80,0x04,0x94,0x01,0x3F,0x1C,0x78,0x78,0x78,0x26,0x20,0x08,0x20,0x43,0x00,0x00,
//   0x00,0x80,0x00,0xFF,0x20,0x78,0xFF,0x20,0x78,0x64,0x78,0x23,0x26,0x00,0x00,0x00,
//   0xFF,0xFF,0xE7,0x7A,0x40,0x7F,0x00,0x45,0x46,0x40,0x55,0x4C,0x54,0x5D,0x00,0x00,
//   0xB5,0x78,0x78,0x21,0x75,0x7A,0x7A,0xFF};
//   unsigned int len = 184;
//   unsigned char* new_buf = afl_postprocess(src, &len);
//   for(int i=0; i< 184; i++) {
//     if(i%16==0)
//     { 
//       printf("\n"); 
//     }
//     printf("%x ", (uint8_t)(new_buf[i]));
//   }
//   printf("\n%s\n", new_buf);
// }
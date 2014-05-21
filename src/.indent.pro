/* $Id: .indent.pro 813 2006-02-14 20:52:15Z nenolod $ */

/* copy this file to the source dir then run indent file.c */

--gnu-style

/* This is the indent before the brace not inside the block. */
--brace-indent0

/* Indent case: by 2 and braces inside case by 0(then by 0)... */
--case-brace-indentation0
--case-indentation2

--indent-level8

/* Put while() on the brace from do... */
--cuddle-do-while

/* Disable an annoying format... */
--no-space-after-function-call-names

/* Disable an annoying format... */
--dont-break-procedure-type

/* Disable an annoying format... */
--no-space-after-casts

--line-length100

/* typedefs */
-T boolean_t
-T node_t
-T list_t
-T tld_t
-T kline_t
-T EVH
-T sra_t
-T server_t
-T user_t
-T channel_t
-T chanuser_t
-T myuser_t
-T mychan_t
-T chanacs_t
-T CONFIGENTRY
-T CONFIGFILE
-T Block
-T MemBlock
-T BlockHeap

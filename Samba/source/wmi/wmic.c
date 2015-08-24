/*
   WMI Sample client
   Copyright (C) 2006 Andrzej Hajda <andrzej.hajda@wp.pl>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdarg.h>

#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "librpc/gen_ndr/ndr_oxidresolver_c.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/gen_ndr/ndr_dcom_c.h"
#include "librpc/gen_ndr/ndr_remact_c.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "librpc/rpc/dcerpc_table.h"

#include "lib/com/dcom/dcom.h"
#include "lib/com/proto.h"
#include "lib/com/dcom/proto.h"

#include "wmi/wmi.h"

struct WBEMCLASS;
struct WBEMOBJECT;

#include "wmi/proto.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// strLimitPf function
#define STR_PRINT 0
#define STR_APPEND 1

#define ISS_MAX_MSG_SIZE 50000

#define STR_SZ 1048576 // 1MB
#define STR_LINE_SZ 32768 // 1MB
#define STR_HDR_SZ 32768

int ISSdebug = 1;
int queryCount = 0;
int dbgLogOut = 1;

struct program_args {
   char *hostname;
   char *query;
   char *ns;
   char *delim;
   char *outputDir;
};

struct IWbemServices *pWS = NULL;

char **readFile(char *filePath);
int runQuery(struct IWbemServices *pWS, struct com_context *ctx, char *queryStr, struct program_args *args, char *importKey);
int ISSlog(const char *format, ...);
int strLimitPf(char *valOut, int maxLen, int pfType, const char *format, ...);
void getTimeStr(char *strOut, int sz);
void errCheck(char *msg, char *host, WERROR result, struct com_context *ctx);

static void parse_args(int argc, char *argv[], struct program_args *pmyargs) {
   poptContext pc;
   int opt, i;

   int argc_new;
   char **argv_new;

   struct poptOption long_options[] = {
      POPT_AUTOHELP
      POPT_COMMON_SAMBA
      POPT_COMMON_CONNECTION
      POPT_COMMON_CREDENTIALS
      POPT_COMMON_VERSION
      {"namespace", 0, POPT_ARG_STRING, &pmyargs->ns, 0,
	 "WMI namespace, default to root\\cimv2", 0},
      {"delimiter", 0, POPT_ARG_STRING, &pmyargs->delim, 0,
	 "delimiter to use when querying multiple values, default to '|'", 0},
      {"outputDir", 0, POPT_ARG_STRING, &pmyargs->outputDir, 0,
	 "folder for output files", 0},
      POPT_TABLEEND
   };

   pc = poptGetContext("wmi", argc, (const char **) argv,
      long_options, POPT_CONTEXT_KEEP_FIRST);

   poptSetOtherOptionHelp(pc, "//host query\n\nExample: wmic -U [domain/]adminuser%password //host \"select * from Win32_ComputerSystem\"");

   while ((opt = poptGetNextOpt(pc)) != -1) {
      poptPrintUsage(pc, stdout, 0);
      poptFreeContext(pc);
      exit(1);
   }

   argv_new = discard_const_p(char *, poptGetArgs(pc));

   argc_new = argc;
   for (i = 0; i < argc; i++) {
      if (argv_new[i] == NULL) {
	 argc_new = i;
	 break;
      }
   }

//   if (argc_new != 3
//      || strncmp(argv_new[1], "//", 2) != 0) {
//      poptPrintUsage(pc, stdout, 0);
//      poptFreeContext(pc);
//      exit(1);
//   }

   /* skip over leading "//" in host name */
   pmyargs->hostname = argv_new[1] + 2;
   pmyargs->query = argv_new[2];
   pmyargs->outputDir = NULL;
   if (argc > 3) {
      pmyargs->outputDir = argv_new[3];
   }
   poptFreeContext(pc);
}

void errCheck(char *msg, char *host, WERROR result, struct com_context *ctx) {
   NTSTATUS status;
   if (!W_ERROR_IS_OK(result)) { 
      DEBUG(0, ("ERROR: %s\n", msg));
      status = werror_to_ntstatus(result);
      fprintf(stderr, "ERROR: [%s] NTSTATUS: %s - %s\n", host, nt_errstr(status), get_friendly_nt_error_msg(status));
      if (ctx != NULL) {
	 talloc_free(ctx);
      }
      exit(1);
   } else { 
      DEBUG(1, ("OK   : %s\n", msg)); 
   }
}

#define RETURN_CVAR_ARRAY_STR(fmt, arr) {\
        uint32_t i;\
	char *r;\
\
        if (!arr) {\
                return talloc_strdup(mem_ctx, "NULL");\
        }\
	r = talloc_strdup(mem_ctx, "(");\
        for (i = 0; i < arr->count; ++i) {\
		r = talloc_asprintf_append(r, fmt "%s", arr->item[i], (i+1 == arr->count)?"":",");\
        }\
        return talloc_asprintf_append(r, ")");\
}

char *string_CIMVAR(TALLOC_CTX *mem_ctx, union CIMVAR *v, enum CIMTYPE_ENUMERATION cimtype) {
   switch (cimtype) {
      case CIM_SINT8: return talloc_asprintf(mem_ctx, "%d", v->v_sint8);
      case CIM_UINT8: return talloc_asprintf(mem_ctx, "%u", v->v_uint8);
      case CIM_SINT16: return talloc_asprintf(mem_ctx, "%d", v->v_sint16);
      case CIM_UINT16: return talloc_asprintf(mem_ctx, "%u", v->v_uint16);
      case CIM_SINT32: return talloc_asprintf(mem_ctx, "%d", v->v_sint32);
      case CIM_UINT32: return talloc_asprintf(mem_ctx, "%u", v->v_uint32);
      case CIM_SINT64: return talloc_asprintf(mem_ctx, "%lld", v->v_sint64);
      case CIM_UINT64: return talloc_asprintf(mem_ctx, "%llu", v->v_sint64);
      case CIM_REAL32: return talloc_asprintf(mem_ctx, "%f", (double) v->v_uint32);
      case CIM_REAL64: return talloc_asprintf(mem_ctx, "%f", (double) v->v_uint64);
      case CIM_BOOLEAN: return talloc_asprintf(mem_ctx, "%s", v->v_boolean ? "True":"False");
      case CIM_STRING:
      case CIM_DATETIME:
      case CIM_REFERENCE: return talloc_asprintf(mem_ctx, "%s", v->v_string);
      case CIM_CHAR16: return talloc_asprintf(mem_ctx, "Unsupported");
      case CIM_OBJECT: return talloc_asprintf(mem_ctx, "Unsupported");
      case CIM_ARR_SINT8: RETURN_CVAR_ARRAY_STR("%d", v->a_sint8);
      case CIM_ARR_UINT8: RETURN_CVAR_ARRAY_STR("%u", v->a_uint8);
      case CIM_ARR_SINT16: RETURN_CVAR_ARRAY_STR("%d", v->a_sint16);
      case CIM_ARR_UINT16: RETURN_CVAR_ARRAY_STR("%u", v->a_uint16);
      case CIM_ARR_SINT32: RETURN_CVAR_ARRAY_STR("%d", v->a_sint32);
      case CIM_ARR_UINT32: RETURN_CVAR_ARRAY_STR("%u", v->a_uint32);
      case CIM_ARR_SINT64: RETURN_CVAR_ARRAY_STR("%lld", v->a_sint64);
      case CIM_ARR_UINT64: RETURN_CVAR_ARRAY_STR("%llu", v->a_uint64);
      case CIM_ARR_REAL32: RETURN_CVAR_ARRAY_STR("%f", v->a_real32);
      case CIM_ARR_REAL64: RETURN_CVAR_ARRAY_STR("%f", v->a_real64);
      case CIM_ARR_BOOLEAN: RETURN_CVAR_ARRAY_STR("%d", v->a_boolean);
      case CIM_ARR_STRING: RETURN_CVAR_ARRAY_STR("%s", v->a_string);
      case CIM_ARR_DATETIME: RETURN_CVAR_ARRAY_STR("%s", v->a_datetime);
      case CIM_ARR_REFERENCE: RETURN_CVAR_ARRAY_STR("%s", v->a_reference);
      default: return talloc_asprintf(mem_ctx, "Unsupported");
   }
}

#undef RETURN_CVAR_ARRAY_STR

int main(int argc, char **argv) {
   struct program_args args = {};
   uint32_t cnt = 5, ret;
   char *class_name = NULL;
   WERROR result;
   NTSTATUS status;
   char **queryList;
   char *queryStr = NULL;
   char importKey[64];
   int i = 0;

   parse_args(argc, argv, &args);

   /* apply default values if not given by user*/
   if (!args.ns) args.ns = "root\\cimv2";
   if (!args.delim) args.delim = "|";

   dcerpc_init();
   dcerpc_table_init();

   dcom_proxy_IUnknown_init();
   dcom_proxy_IWbemLevel1Login_init();
   dcom_proxy_IWbemServices_init();
   dcom_proxy_IEnumWbemClassObject_init();
   dcom_proxy_IRemUnknown_init();
   dcom_proxy_IWbemFetchSmartEnum_init();
   dcom_proxy_IWbemWCOSmartEnum_init();

   struct com_context *ctx = NULL;
   com_init_ctx(&ctx, NULL);
   dcom_client_init(ctx, cmdline_credentials);

   result = WBEM_ConnectServer(ctx, args.hostname, args.ns, 0, 0, 0, 0, 0, 0, &pWS);
   errCheck("Login to remote object.", args.hostname, result, ctx);

   importKey[0]='\0';
   getTimeStr(&importKey, 64);
   
   queryStr = args.query;
   if (args.query[0] == '@') {
      queryList = readFile(&args.query[1]);
      ISSlog("INFO: WMI queries: %i\n", queryCount);
      for (i=0; i<queryCount; i++) {
	 queryStr = queryList[i];
	 ret=runQuery(pWS, ctx, queryStr, &args, importKey);
	 if (ret) {
	    break;
	 }
      }
   } else {
      ret=runQuery(pWS, ctx, queryStr, &args, importKey);
   }
   printf("Return: %i\n", ret);
   talloc_free(ctx);
}

int runQuery(struct IWbemServices *pWS, struct com_context *ctx, char *queryStr, struct program_args *args, char *importKey) {
   uint32_t cnt = 5, ret;
   char *class_name = NULL;
   WERROR result;
   NTSTATUS status;
   char fOut[1024];
   FILE *f = NULL;
   char *strOut = NULL;
   char *strHdr = NULL;
   int maxRowsPerWrite = 1000;
   int writeHdrs = 0;
   char line[STR_LINE_SZ];
   struct IEnumWbemClassObject *pEnum = NULL;
   
   fprintf(stderr,"INFO: [%s] Query[%i]: '%s'\n", args->hostname, strlen(queryStr), queryStr);
      
   result = IWbemServices_ExecQuery(pWS, ctx, "WQL", queryStr, WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_ENSURE_LOCATABLE, NULL, &pEnum);
   errCheck("WMI query execute.", args->hostname, result, ctx);

   IEnumWbemClassObject_Reset(pEnum, ctx);
   errCheck("Reset result of WMI query.", args->hostname, result, ctx);   

   strOut = (char *) malloc(STR_SZ); 
   strHdr = (char *) malloc(STR_HDR_SZ); 
   strOut[0]='\0';
   strHdr[0]='\0';
   
   do {
      uint32_t i, j;
      struct WbemClassObject * co[cnt];

      result = IEnumWbemClassObject_SmartNext(pEnum, ctx, 0xFFFFFFFF, cnt, co, &ret);
      /* WERR_BADFUNC is OK, it means only that there is less returned objects than requested */
      if (!W_ERROR_EQUAL(result, WERR_BADFUNC)) {
	 errCheck("Retrieve result data.", args->hostname, result, ctx);
      } else {
	 DEBUG(1, ("OK : Retrieved less objects than requested (it is normal).\n"));
      }
      if (!ret) {
	 break;
      }

      // Iterate each record
      for (i = 0; i < ret; ++i) {
	 // Process class headers
	 if (!class_name || strcmp(co[i]->obj_class->__CLASS, class_name)) {
	    
	    if (class_name) {
	       talloc_free(class_name);
	    }
	    class_name = talloc_strdup(ctx, co[i]->obj_class->__CLASS);
	    if (dbgLogOut) {
	       printf("CLASS: %s\n", class_name);
	    }
	    
	    strLimitPf(strHdr, STR_HDR_SZ, STR_PRINT, "Importkey%sHostname%s", args->delim, args->delim);
	    
	    for (j = 0; j < co[i]->obj_class->__PROPERTY_COUNT; ++j) {
	       strLimitPf(strHdr, STR_HDR_SZ, STR_APPEND, "%s%s", j ? args->delim : "", co[i]->obj_class->properties[j].name);
	    }
	    strLimitPf(strHdr, STR_SZ, STR_APPEND, "\n");
	    if (dbgLogOut) {
	       printf(strHdr);
	    }
	 }
	 
	 line[0]='\0';
	 strLimitPf(line, STR_LINE_SZ, STR_APPEND, "%s%s%s%s", importKey, args->delim, args->hostname, args->delim);
	 // Iterate each record
	 for (j = 0; j < co[i]->obj_class->__PROPERTY_COUNT; ++j) { 
	    char *s = NULL;
	    s = string_CIMVAR(ctx, &co[i]->instance->data[j], co[i]->obj_class->properties[j].desc->cimtype & CIM_TYPEMASK);
	    strLimitPf(line, STR_LINE_SZ, STR_APPEND, "%s%s", j ? args->delim : "", s);
	 }
	 strLimitPf(line, STR_SZ, STR_APPEND, "\n");
	 strLimitPf(strOut, STR_SZ, STR_APPEND, "%s", line);
	 if (dbgLogOut) {
	    printf(line);
	 }
      }
   } while (ret == cnt);
   ISSlog("INFO: [%s] Writing output\n", args->hostname);
   
   if ((args->outputDir != NULL) && strlen(args->outputDir) > 0 && strlen(strOut) > 0) {
      if (!doesFileExist(args->outputDir)) {
	  ISSlog("ERROR: [%s] OutputDir does not exist: '%s'\n", args->hostname, args->outputDir);
	  exit(1);
      }
      strLimitPf(fOut, 1024, STR_PRINT, "%s/%s.csv",args->outputDir,class_name);
      ISSlog("INFO: [%s] OutputFile: '%s'\n", args->hostname, fOut);
      // Don't write headers if file exists, presume this has already been done
      if (!doesFileExist(fOut)) {
	 writeHdrs = 1;
      }
      
      f = fopen(fOut,"a");
      if (f != NULL) {
	 if (writeHdrs) {
	    fprintf(f,strHdr);
	 }
	 fprintf(f,strOut);
	 fclose(f);
      } else {
	 fprintf(stderr,"ERROR: [%s] Problem opening file: '%s'\n", args->hostname, fOut);
      }
   } else {
      printf(strHdr);
      printf(strOut);
   }
   
   free(strHdr);
   free(strOut);
   
   return 0;
}

int doesFileExist(const char *filename) {
    struct stat st;
    int result = stat(filename, &st);
    return result == 0;
}

char **readFile(char *filePath)
{
   int lines_allocated = 128;
   int max_line_len = 1024;
   char *tmp = NULL;

   /* Allocate lines of text */
   char **words = (char **) malloc(sizeof (char*)*lines_allocated);
   if (words == NULL) {
      fprintf(stderr, "Out of memory (1).\n");
      exit(1);
   }

   printf("QueryFile: '%s'\n", filePath);
   FILE *fp = fopen(filePath, "r");
   if (fp == NULL) {
      fprintf(stderr, "Error opening file.\n");
      exit(2);
   }

   int i = 0;
   for (i = 0; 1; i++) {
      int j = 0;
      /* Have we gone over our line allocation? */
      if (i >= lines_allocated) {
	 int new_size = 0;

	 /* Double our allocation and re-allocate */
	 new_size = lines_allocated * 2;
	 words = (char **) realloc(words, sizeof (char*)*new_size);
	 if (words == NULL) {
	    fprintf(stderr, "Out of memory.\n");
	    exit(3);
	 }
	 lines_allocated = new_size;
      }
      /* Allocate space for the next line */
      tmp = malloc(max_line_len);
      if (tmp == NULL) {
	 fprintf(stderr, "Out of memory (3).\n");
	 exit(4);
      }
      if (fgets(tmp, max_line_len - 1, fp) == NULL) {
	 break;
      }
      int decrement=1;
      if (strlen(tmp) > 0) {
	 if ((tmp[0] != '#') && (tmp[0] != ';') && 
	    (tmp[0] != '\n') && (tmp[0] != '\r')) {
	    words[i]=tmp;
	    decrement=0;
	 }
      } 
      if (decrement) {
	 i--;
	 //ISSlog("Ignore: '%s'\n", tmp);
      } else {
	 /* Get rid of CR or LF at end of line */
	 for (j = strlen(words[i]) - 1; j >= 0 && (words[i][j] == '\n' || words[i][j] == '\r'); j--)
	    ;
	 words[i][j + 1] = '\0';
	 queryCount++;
      }
   }
   /* Close file */
   fclose(fp);
   return words;
}

// sprintf replacement with maxLen valOut validation and pfType, ie overwrite or append to ValOut
int strLimitPf(char *valOut, int maxLen, int pfType, const char *format, ...) {
   va_list arg;
   int retVal = 1;
   // Small stack size on AIX...
#ifdef AIX
   char *val = (char *) malloc(maxLen);
#else
   char val[maxLen];
#endif

   va_start(arg, format);
   vsnprintf(val, maxLen, format, arg);
   val[maxLen - 1] = '\0';
   va_end(arg);

   switch (pfType) {
      case STR_APPEND:
	 retVal = strLimitCat(valOut, val, maxLen);
	 break;
      case STR_PRINT:
	 retVal = strLimitCpy(valOut, val, maxLen);
	 break;
      default:
	 break;
   }
#ifdef AIX
   free(val);
#endif
   return retVal;
}

int strLimitCpy(char *dst, char *in, int sz) {
   int len = -1;
   int lenNew = -1;
   int ret = 0;

   len = strlen(in);
   strncpy(dst, in, sz);
   lenNew = len;
   if (len + 1 > sz) {
      ret = 1;
      lenNew = sz;
      dst[lenNew - 1] = '\0';
   } else
      dst[lenNew] = '\0';
   return ret;
}

int strLimitCat(char *dst, char *in, int maxSz) {
   int lenIn = -1;
   int lenDst = -1;
   int len = 0;
   int retVal = 0;

   lenIn = strlen(in);
   lenDst = strlen(dst);

   if (lenDst > maxSz) {
      return 1;
   }

   len = lenIn;
   if (lenIn + lenDst >= maxSz) {
      len = maxSz - lenDst - 1;
      retVal = 1;
   }
   strncat(dst, in, len);

   return retVal;
}

int lockfileipc(char *fName, int lck, char *idStr, int timeoutms) {
   char lockfileStr[255];
   int f = -1;
   FILE *fd = NULL;
   char idStrTmp[64];
   int wait = 0;
   int rnd = 0;
   int maxTimeUSecs = 100 * timeoutms;
   int timeWaited = 0;
   char errStr[1024];
   
   strLimitPf(idStrTmp, 64, STR_PRINT, "%li", (long) getpid());

   strLimitPf(lockfileStr, 255, STR_PRINT, "%s", fName);
   if (!lck) {
      ISSlog("DEBUG: (lockfileipc) releasing lock: %s\n", lockfileStr);
      remove(lockfileStr);
      return 1;
   }

   while (1) {
      ISSlog("DEBUG: (lockfileipc) lock file: %s\n", lockfileStr);

      f = open(lockfileStr, O_WRONLY | O_CREAT | O_EXCL, // Try create the file exclusively if it doesnt exist
	 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      ISSlog("DEBUG: (lockfileipc) strErr/f: %s/%d\n", strerror(errno), f);

      if ((f < 0) && (errno == EEXIST)) // If the file already exists, wait...
	 wait = 1;
      else {
	 fd = fdopen(f, "w");
	 if (fd > 0) {
	    fprintf(fd, "%s", idStrTmp);
	    fclose(fd);
	    ISSlog("DEBUG: (lockfileipc) got lock\n");
	    wait = 0;
	    break;
	 } else {
	    wait = 1;
	 }
      }

      if (wait) {
	 rnd = randNo()*5000;
	 ISSlog("INFO: (lockfileipc) [%d] waiting to get lock: %s\n", rnd, lockfileStr);
	 // There is a small chance that other calls could beat us whilst we're sleeping...
	 usleep(rnd);
	 timeWaited += rnd;
      }
      if (timeWaited >= maxTimeUSecs) {
	 strLimitPf(errStr, 1024, STR_PRINT, "ERROR: (lockfileipc) [%d/%d] Timed out trying to get lock file: %s\n", rnd, timeWaited, lockfileStr);
	 ISSlog(errStr);
	 return 0;
      }
   }
   return 1;
}

int ISSlog(const char *format, ...)
{
   if (!ISSdebug) {
      return 1;
   }
  va_list arg;
  int done=1;
  char *logMsg;

  //replaced fixed size declaration of logMsg with a malloc to accomodate HPUX's pathetic stack size
  logMsg = (char *)malloc(ISS_MAX_MSG_SIZE);
  if (logMsg == NULL)
  {
     fprintf(stderr, "ERROR: (ISSlog) Unable to allocate memory\n");
     exit(1);
  }
  memset(logMsg,0,ISS_MAX_MSG_SIZE);

  va_start (arg, format);
  done = vsnprintf (logMsg, ISS_MAX_MSG_SIZE-2, format, arg);
  
  fprintf(stderr,logMsg);
     
  free(logMsg);
  va_end (arg);

  return done;
}

int randNo() {
   unsigned int seed = (unsigned int) time(NULL);
   unsigned int r;

   srand(seed);
   r = rand();

   while (r > 1001) {
      r = r / 1000;
   }
   while (r > 101) {
      r = r / 100;
   }

   if (r > 60) {
      r = r / 2;
   }
   if (r < 10) {
      r = r + 10;
   }
   return (r);
}

void getTimeStr(char *strOut, int sz) {
   struct timeval tv;
   long time_now;
   char newformat[64];

   if (gettimeofday(&tv, NULL) == -1) {
      time_now = time(&time_now);
      strftime(strOut, 23, "%Y-%m-%d %T.000", localtime(&time_now));
      return;
   }

   time_now = tv.tv_sec;
   strftime(newformat, 23, "%Y-%m-%d %T.", localtime(&time_now));
   strLimitPf(strOut, sz, STR_PRINT, "%s%3ld", newformat, tv.tv_usec);
   strOut[23] = '\0';
}

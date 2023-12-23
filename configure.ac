# 
#  Argus Software. Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2015 QoSient, LLC
#  All rights reserved.
# 
#  THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
#  AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
#  EXPRESS PERMISSION OF QoSIENT, LLC.
# 
#  QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
#  IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
#  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
#  THIS SOFTWARE.
# 
# 
#  $Id: //depot/argus/clients/configure.ac#7 $
#  $DateTime: 2010/07/25 23:19:02 $
#  $Change: 1967 $
#
#
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([Argus Pro (Gargoyle) Server Programs],[5.0],[bug-report@qosient.com],[argus],[http://qosient.com/argus])
PACKAGE_RELEASE='3.6'
ARGUSPRO_VERSION='1.4'
AC_DEFINE([ARGUSPRO_VERSION_STRING], ["1.3"], [Product version number string])
AC_CONFIG_SRCDIR([argus/argus.c])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_HEADERS([include/argus_config.h])
AC_CANONICAL_TARGET

AC_PREFIX_DEFAULT( /usr/local )

AC_QOSIENT_PERL(V_PERL)

# Checks for programs.
AC_LBL_C_INIT(V_CCOPT, V_INCLS)
AC_C_INLINE
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_YACC

AC_CHECK_PROGS(V_RANLIB, ranlib, @true)
AC_QOSIENT_LEX_AND_YACC(V_LEX, V_YACC, argus_)

# Checks for libraries.

CMU_SASL2(V_INCLS)

AC_QOSIENT_PCRE(V_PCRE, V_INCLS)


# Checks for header files.
AC_HEADER_DIRENT
m4_warn([obsolete],
[The preprocessor macro `STDC_HEADERS' is obsolete.
  Except in unusual embedded environments, you can safely include all
  ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS([sys/sockio.h string.h fcntl.h sys/file.h syslog.h zlib.h])

AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h libintl.h malloc.h memory.h netdb.h])
AC_CHECK_HEADERS([net/if.h netinet/in.h netinet/if_ether.h netinet/ether.h netinet/in_systm.h])
AC_CHECK_HEADERS([netinet/ip.h netinet/udp.h netinet/tcp.h])
AC_CHECK_HEADERS([stdlib.h stddef.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h])
AC_CHECK_HEADERS([sys/time.h sys/vfs.h syslog.h termios.h unistd.h values.h features.h])
AC_CHECK_HEADERS([dns_sd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

AC_SYS_LARGEFILE
AC_LBL_UNALIGNED_ACCESS

AC_LBL_DEVEL(V_CCOPT)
AC_QOSIENT_DEBUG(V_CCOPT)
AC_QOSIENT_MEMORY

AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

m4_warn([obsolete],
[Update your code to rely only on HAVE_SYS_TIME_H,
then remove this warning and the obsolete code below it.
All current systems provide time.h; it need not be checked for.
Not all systems provide sys/time.h, but those that do, all allow
you to include it and time.h simultaneously.])dnl
AC_CHECK_HEADERS_ONCE([sys/time.h])
# Obsolete code to be removed.
if test $ac_cv_header_sys_time_h = yes; then
  AC_DEFINE([TIME_WITH_SYS_TIME],[1],[Define to 1 if you can safely include both <sys/time.h>
	     and <time.h>.  This macro is obsolete.])
fi
# End of obsolete code.

AC_STRUCT_TM
AC_STRUCT_TIMEZONE

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_VPRINTF
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
m4_warn([obsolete],
[your code may safely assume C89 semantics that RETSIGTYPE is void.
Remove this warning and the `AC_CACHE_CHECK' when you adjust the code.])dnl
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([#include <sys/types.h>
#include <signal.h>
],
		 [return *(signal (0, 0)) (0) == 1;])],
		   [ac_cv_type_signal=int],
		   [ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers
		    (`int' or `void').])

AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_STRTOD


AC_CHECK_FUNCS(backtrace)
AC_CHECK_FUNCS(openlog syslog)
AC_CHECK_FUNCS(vfprintf strlcpy)
AC_CHECK_FUNCS(strftime)
AC_CHECK_FUNCS([inet_aton inet_pton inet_ntop])
AC_CHECK_FUNCS(setlinebuf)
AC_CHECK_FUNCS(strerror strtof)
AC_CHECK_FUNCS(floorf remainderf)
AC_CHECK_FUNCS(timegm)

saved_CPPFLAGS=$CPPFLAGS
saved_LIBS=$LIBS
LIB_XDR=""

AC_CHECK_HEADERS([rpc/xdr.h], ,
   [CPPFLAGS="${saved_CPPFLAGS} -I/usr/include/tirpc"
    AC_CHECK_HEADERS(rpc/xdr.h,
      [XDR_INCLS="-I/usr/include/tirpc"
      LIB_XDR="-ltirpc"])],
      [#include <rpc/types.h>])

LIBS="$LIB_XDR $LIBS"

AC_CHECK_FUNCS(xdrmem_create,
   AC_DEFINE([HAVE_XDR], [], [Using system XDR library]),
   LIB_XDR=""
   XDR_INCLS=""
   )

CPPFLAGS=${saved_CPPFLAGS}
LIBS=${saved_LIBS}

needsnprintf=no
AC_CHECK_FUNCS(vsnprintf snprintf,, [needsnprintf=yes])
if test $needsnprintf = yes; then
   AC_LIBOBJ(snprintf)
fi
#
# Do this before checking for ether_hostton(), as it's a
# "gethostbyname() -ish function".
#
AC_LBL_LIBRARY_NET
AC_CHECK_FUNCS([ether_hostton getaddrinfo gethostname])

if test "$ac_cv_func_ether_hostton" = yes; then
   #
   # OK, we have ether_hostton().  Do we have <netinet/if_ether.h>?
   #
   if test "$ac_cv_header_netinet_if_ether_h" = yes; then
      #
      # Yes.  Does it declare ether_hostton()?
      #
      AC_CHECK_DECL(ether_hostton,
          [
         AC_DEFINE(NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON,,
             [Define to 1 if netinet/if_ether.h declares `ether_hostton'])
          ],,
          [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
struct mbuf;
struct rtentry;
#include <net/if.h>
#include <netinet/if_ether.h>
          ])
   fi
   #
   # Did that succeed?
   #
   if test "$ac_cv_have_decl_ether_hostton" != yes; then
      #
      # No, how about <netinet/ether.h>, as on Linux?
      #
      AC_CHECK_HEADERS(netinet/ether.h)
      if test "$ac_cv_header_netinet_ether_h" = yes; then
         #
         # We have it - does it declare ether_hostton()?
         # Unset ac_cv_have_decl_ether_hostton so we don't
         # treat the previous failure as a cached value and
         # suppress the next test.
         #
         unset ac_cv_have_decl_ether_hostton
         AC_CHECK_DECL(ether_hostton,
             [
            AC_DEFINE(NETINET_ETHER_H_DECLARES_ETHER_HOSTTON,,
                [Define to 1 if netinet/ether.h declares `ether_hostton'])
             ],,
             [
#include <netinet/ether.h>
             ])
      fi
   fi
   #
   # Is ether_hostton() declared?
   #
   if test "$ac_cv_have_decl_ether_hostton" != yes; then
      #
      # No, we'll have to declare it ourselves.
      # Do we have "struct ether_addr"?
      #
      AC_CHECK_TYPES(struct ether_addr,,,
          [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
struct mbuf;
struct rtentry;
#include <net/if.h>
#include <netinet/if_ether.h>
          ])
      AC_DEFINE(HAVE_DECL_ETHER_HOSTTON, 0,
          [Define to 1 if you have the declaration of `ether_hostton', and to 0 if you
don't.])
   else
      AC_DEFINE(HAVE_DECL_ETHER_HOSTTON, 1,
          [Define to 1 if you have the declaration of `ether_hostton', and to 0 if you
don't.])
   fi
fi

if test "$ac_cv_type_struct_ether_addr" = yes ; then
   AC_DEFINE([HAVE_STRUCT_ETHER_ADDR], [], [struct ether addr])
fi

if test "$tcl_cv_member_tm_gmtoff" = yes ; then
   AC_DEFINE([HAVE_TM_GMTOFF], [], [tm_gmtoff in struct tm])
fi

AC_CHECK_FUNCS([alarm bzero endgrent endpwent floor gethostbyaddr gethostbyname getpass gettimeofday inet_ntoa isascii localtime_r])
AC_CHECK_FUNCS([memchr memmove memset mkdir modf pow putenv realpath regcomp select setenv socket sqrt strcasecmp strchr])
AC_CHECK_FUNCS([strdup strlcat strncasecmp strpbrk strrchr strstr strtol srandomdev tzset])
AC_CHECK_FUNCS([gethostuuid])
AC_CHECK_FUNCS([posix_memalign memalign])

case "$target" in
   arm*darwin*)
	V_ARCH="-arch arm64 -arch x86_64"
        ;;
   x86*darwin*)
        ;;
esac

case "$target_os" in
   arm*darwin*)
	V_ARCH="-arch arm64 -arch x86_64"
        COMPATLIB="-lz"
        ;;
   x86*darwin*)
        COMPATLIB="-lz"
        ;;
   *)
	if test "$ac_cv_header_zlib_h" = yes ; then
	   COMPATLIB="-lm -lz"
	else
	   COMPATLIB="-lm"
	fi
        ;;
esac

AC_QOSIENT_MEMORY

AC_QOSIENT_HASHDEBUG()
AC_QOSIENT_NANOSECONDS()
AC_QOSIENT_FLEXLM(V_FLEXLM, V_FLEXLM_ARCH)
AC_QOSIENT_THREADS(V_THREADS)
AC_QOSIENT_TCPWRAP(V_WRAPDEP, V_INCLS)
if test ! -z "$V_WRAPDEP"; then
   if test -f "$V_WRAPDEP"; then
      if test -f lib/libwrap.a; then
         rm -rf lib/libwrap.a
      fi
      wrapdir=`echo $V_WRAPDEP | sed -e 's/^\.\./..\/../'`
      ln -s $wrapdir lib/libwrap.a
      V_WRAPDEP="../lib/libwrap.a"
   else
      if test "$V_WRAPDEP" = "-lwrap" ; then
         if test -f lib/libwrap.a; then
            rm -rf lib/libwrap.a
         fi
         case "$target_os" in
         linux*)
            V_WRAPDEP="$V_WRAPDEP -lnsl";;
         esac
      fi
   fi
   AC_DEFINE([HAVE_TCP_WRAPPER], [], [Using Tcp wrappers])
   WRAPLIBS="$V_WRAPDEP"
fi

AC_QOSIENT_LIBPCAP(V_PCAPDEP, V_INCLS)
if test ! -z "$V_PCAPDEP"; then
   if test -f "$V_PCAPDEP"; then
      if test -f lib/libpcap.a; then
           rm -rf lib/libpcap.a
      fi
      pcapdir=`echo $V_PCAPDEP | sed -e 's/\.\./..\/../'`
      ln -s $pcapdir lib/libpcap.a
      V_PCAPDEP="../lib/libpcap.a"
   else
      if test "$V_PCAPDEP" = "-lpcap" ; then
         if test -f lib/libpcap.a; then
            rm -rf lib/libpcap.a
         fi
      fi
      if test "$V_PCAPDEP" = "-lwpcap" ; then
         if test -f lib/libpcap.a; then
            rm -rf lib/libpcap.a
         fi
      fi
   fi
   LIBS="$LIBS $V_PCAPDEP"
fi

case "$target_cpu" in
*86)
   have_x86=yes;
   ;;

powerpc-apple*)
   ;;
        
powerpc64-*-linux-gnu)
   V_CCOPT="$V_CCOPT -m64 -fPIC"
   ;;   
        
esac    

case "$target_os" in

aix*)
	dnl Workaround to enable certain features
	have_sun=yes;
	;;

darwin*)
	have_darwin=yes;
	;;

hpux9*)
        have_hpux_nine=yes;
	;;

hpux10.0*)
	;;

hpux10.1*)
	;;

hpux*)
	dnl HPUX 10.20 and above is similar to HPUX 9...
	have_hpux_ten=yes;
	;;

sinix*)
	AC_MSG_CHECKING(if SINIX compiler defines sinix)
	AC_CACHE_VAL(ac_cv_cc_sinix_defined,
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[int i = sinix;]])],[ac_cv_cc_sinix_defined=yes],[ac_cv_cc_sinix_defined=no]))
	    AC_MSG_RESULT($ac_cv_cc_sinix_defined)
	    if test "$ac_cv_cc_sinix_defined" = "no" ; then
               AC_DEFINE([sinix], [], [Description])
	    fi
	;;

solaris*)
	AC_DEFINE(HAVE_SOLARIS,1,[On solaris])
	AC_MSG_CHECKING(for LD_LIBRARY_PATH, since you appear to be running Solaris)
	if test "x$LD_LIBRARY_PATH" != "x" ; then
		LIBS="$LIBS -R$LD_LIBRARY_PATH"
		AC_MSG_RESULT(yes -- added LD_LIBRARY_PATH to run-time linker path)
	else
		AC_MSG_RESULT(no -- this may be a problem in a few seconds)
	fi
	COMPATLIB="-lsocket -lnsl -lrt $COMPATLIB"
	;;

linux*)
	;;

cygwin*)
	have_cygwin=yes;
	V_INCLS="$V_INCLS -I../include/cygwin-include"
	;;
esac

if test "$have_x86" = yes ; then
   AC_DEFINE([CONFIG_X86_BSWAP], [], [System has x86 endian support])
fi
if test "$have_darwin" = yes ; then
   AC_DEFINE([HAVE_DARWIN], [], [Mac OS X])
fi
if test "$have_hpux_nine" = yes ; then
   AC_DEFINE([HAVE_HPUX9], [], [HPUX 9])
fi
if test "$have_hpux_ten" = yes ; then
   AC_DEFINE([HAVE_HPUX10_20], [], [HPUX 10])
fi
if test "$have_sun" = yes ; then
   AC_DEFINE([_SUN], [], [Description])
fi
if test "$have_cygwin" = yes ; then
   AC_DEFINE([CYGWIN], [], [Using cygwin])
fi
if test "$with_pluribus" = yes ; then
   AC_DEFINE([ARGUS_PLURIBUS], [], [Using Pluribus])
fi

AC_CACHE_CHECK([tm_gmtoff in struct tm], tcl_cv_member_tm_gmtoff, [
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <time.h>]], [[struct tm tm; tm.tm_gmtoff;]])],[tcl_cv_member_tm_gmtoff=yes],[tcl_cv_member_tm_gmtoff=no])])
if test $tcl_cv_member_tm_gmtoff = yes ; then
   AC_DEFINE([HAVE_TM_GMTOFF], [], [tm_gmtoff in struct tm])
fi

AC_CACHE_CHECK([sys_errlist in stdio.h], arg_cv_sys_errlist, [
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[char *ptr = sys_errlist[0];]])],[arg_cv_sys_errlist=yes],[arg_cv_sys_errlist=no])])
if test $arg_cv_sys_errlist = yes ; then
   AC_DEFINE([HAVE_SYS_ERRLIST], [], [sys_errlist in stdio.h])
fi



INSTALL_LIB="../lib"
INSTALL_BIN="../bin"

AC_SUBST(PACKAGE_VERSION)
AC_SUBST(PACKAGE_RELEASE)
AC_SUBST(ARGUSPRO_VERSION)
AC_SUBST(LIBS)
AC_SUBST(INCLS)
AC_SUBST(V_ARCH)
AC_SUBST(V_CCOPT)
AC_SUBST(V_INCLS)
AC_SUBST(V_RANLIB)
AC_SUBST(V_YACC)
AC_SUBST(V_LEX)
AC_SUBST(V_PERL)
AC_SUBST(V_FLEXLM)
AC_SUBST(V_FLEXLM_ARCH)
AC_SUBST(V_THREADS)
AC_SUBST(WRAPLIBS)
AC_SUBST(COMPATLIB)
AC_SUBST(LIB_SASL)
AC_SUBST(LIB_XDR)
AC_SUBST(XDR_INCLS)
AC_SUBST(INSTALL_LIB)
AC_SUBST(INSTALL_BIN)


AC_CONFIG_FILES([
   Makefile 
   ./common/Makefile 
   ./argus/Makefile
   ./events/Makefile 
   ./pkg/win/Makefile
   ./pkg/win/argus.wxs
   ./lib/argus.spec
   ./licenses/arguspro_sensor_appliance.lic.template
   ./licenses/arguspro_sensor_floating.lic.template
   ./licenses/arguspro_sensor_workstation.lic.template
])

AC_OUTPUT

if test -f .devel ; then
	make depend
fi

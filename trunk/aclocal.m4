# =========================================================================
# AM_PATH_MYSQL : MySQL library

dnl AM_PATH_MYSQL([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for MYSQL, and define MYSQL_CFLAGS and MYSQL_LIBS
dnl
AC_DEFUN(AM_PATH_MYSQL,
[dnl
dnl Get the cflags and libraries from the mysql_config script
dnl
AC_ARG_WITH(mysql-prefix,[  --with-mysql-prefix=PFX   Prefix where MYSQL is installed (optional)],
            mysql_prefix="$withval", mysql_prefix="")
AC_ARG_WITH(mysql-exec-prefix,[  --with-mysql-exec-prefix=PFX Exec prefix where MYSQL is installed (optional)],
            mysql_exec_prefix="$withval", mysql_exec_prefix="")

  if test x$mysql_exec_prefix != x ; then
     mysql_args="$mysql_args --exec-prefix=$mysql_exec_prefix"
     if test x${MYSQL_CONFIG+set} != xset ; then
        MYSQL_CONFIG=$mysql_exec_prefix/bin/mysql_config
     fi
  fi
  if test x$mysql_prefix != x ; then
     mysql_args="$mysql_args --prefix=$mysql_prefix"
     if test x${MYSQL_CONFIG+set} != xset ; then
        MYSQL_CONFIG=$mysql_prefix/bin/mysql_config
     fi
  fi

  AC_REQUIRE([AC_CANONICAL_TARGET])
  AC_PATH_PROG(MYSQL_CONFIG, mysql_config, no)
  AC_MSG_CHECKING(for MYSQL)
  no_mysql=""
  if test "$MYSQL_CONFIG" = "no" ; then
    MYSQL_CFLAGS=""
    MYSQL_LIBS=""
    AC_MSG_RESULT(no)
     ifelse([$2], , :, [$2])
  else
    MYSQL_CFLAGS=`$MYSQL_CONFIG $mysqlconf_args --cflags | sed -e "s/'//g"`
    MYSQL_LIBS=`$MYSQL_CONFIG $mysqlconf_args --libs | sed -e "s/'//g"`
    AC_MSG_RESULT(yes)
    ifelse([$1], , :, [$1])
  fi
  AC_SUBST(MYSQL_CFLAGS)
  AC_SUBST(MYSQL_LIBS)
])

# =========================================================================
# AM_PATH_PGSQL : pgSQL library

dnl AM_PATH_PGSQL([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for PGSQL, and define PGSQL_CFLAGS and PGSQL_LIBS
dnl
AC_DEFUN(AM_PATH_PGSQL,
[dnl
dnl Get the cflags and libraries from the pg_config script
dnl
AC_ARG_WITH(pgsql-prefix,[  --with-pgsql-prefix=PFX   Prefix where PostgreSQL is installed (optional)],
            pgsql_prefix="$withval", pgsql_prefix="")
AC_ARG_WITH(pgsql-exec-prefix,[  --with-pgsql-exec-prefix=PFX Exec prefix where PostgreSQL is installed (optional)],
            pgsql_exec_prefix="$withval", pgsql_exec_prefix="")

  if test x$pgsql_exec_prefix != x ; then
     if test x${PGSQL_CONFIG+set} != xset ; then
        PGSQL_CONFIG=$pgsql_exec_prefix/bin/pg_config
     fi
  fi
  if test x$pgsql_prefix != x ; then
     if test x${PGSQL_CONFIG+set} != xset ; then
        PGSQL_CONFIG=$pgsql_prefix/bin/pg_config
     fi
  fi

  AC_REQUIRE([AC_CANONICAL_TARGET])
  AC_PATH_PROG(PGSQL_CONFIG, pg_config, no, [$PATH:/usr/lib/postgresql/bin])
  AC_MSG_CHECKING(for PGSQL)
  no_pgsql=""
  if test "$PGSQL_CONFIG" = "no" ; then
    PGSQL_CFLAGS=""
    PGSQL_LIBS=""
    AC_MSG_RESULT(no)
     ifelse([$2], , :, [$2])
  else
    PGSQL_CFLAGS=-I`$PGSQL_CONFIG --includedir`
    PGSQL_LIBS="-lpq -L`$PGSQL_CONFIG --libdir`"
    AC_MSG_RESULT(yes)
    ifelse([$1], , :, [$1])
  fi
  AC_SUBST(PGSQL_CFLAGS)
  AC_SUBST(PGSQL_LIBS)
])

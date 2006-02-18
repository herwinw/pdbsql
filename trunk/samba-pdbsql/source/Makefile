#
# Makefile for the Samba pdbsql plugins
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 675
# Mass Ave, Cambridge, MA 02139, USA.
# 

samba = /usr/src/samba3
inc = -I$(samba)/source/include -I$(samba)/source -I$(samba)/source/ubiqx \
	-I/usr/include/postgresql/8.0

SHLD=${CC} ${CFLAGS}
LDSHFLAGS=-shared -Wl,-Bsymbolic

MYSQL_OBJ = pdb_mysql.o
PGSQL_OBJ = pdb_pgsql.o
SQL_OBJ = pdb_sql.o

all: mysql.so pgsql.so

clean:
	rm -f *.{po,so}

.SUFFIXES: .po .c

mysql.so: $(MYSQL_OBJ:.o=.po) $(SQL_OBJ:.o=.po)
	$(SHLD) $(LDSHFLAGS) -o $@ $(MYSQL_OBJ:.o=.po) $(SQL_OBJ:.o=.po) -L/usr/lib -lmysqlclient -lz -lcrypt -lnsl -lm \
		-Wl,-soname=`basename $@`

pgsql.so: $(PGSQL_OBJ:.o=.po)
	$(SHLD) $(LDSHFLAGS) -o $@ $(PGSQL_OBJ:.o=.po)  \
      		-Wl,-soname=`basename $@`
      
.c.po:
	@if (: >> $@ || : > $@) >/dev/null 2>&1; then rm -f $@; else \
	  	dir=`echo $@ | sed 's,/[^/]*$$,,;s,^$$,.,'` $(MAKEDIR); fi
	$(CC) $(inc) $(FLAGS) -fPIC -c $< -o $*.po


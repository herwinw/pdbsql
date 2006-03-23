[global]
netbios name = FOOBAR
workgroup = TESTGROUP
security = domain
domain logons = yes
domain master = yes
passdb backend = plugin:/usr/local/samba/lib/pdb_pgsql.so:pgsql
pgsql:pgsql host = localhost
pgsql:pgsql user = samba
pgsql:pgsql password = ambas
pgsql:pgsql database = samba
pgsql:pgsql port = 5433

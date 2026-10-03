# Real database template and bind check

`run.sh` starts private PostgreSQL and MySQL containers from the cached
OrbStack images, runs the real Express, `pg`, and `mysql2` clients through the
Node preload, and sends the same value over HTTP to an interpolated SQL
template and a parameterized bind endpoint. The result checks HTTP 200 status,
the native database values, template sink evidence, request-body source
evidence, and a trace id. No database port is published and cleanup is
restricted to the IDs created by the script.

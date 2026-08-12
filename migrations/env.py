"""Alembic environment.

Two things worth noting:

* The URL comes from ``MYBOT_DATABASE_URL`` via the settings object, never from
  ``alembic.ini`` -- a connection string with a password has no business in a
  committed file.
* SQLite needs ``render_as_batch`` for ALTER TABLE support, so the same
  migrations apply to the local Core and to a Postgres server profile.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from mybot_schemas.config import get_settings
from mybot_schemas.db.base import Base
from mybot_schemas.models import *  # noqa: F401,F403  (registers every model)
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=get_settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

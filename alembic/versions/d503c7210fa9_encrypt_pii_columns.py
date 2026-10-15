"""encrypt pii columns

Revision ID: d503c7210fa9
Revises: 6c30dc4c2d20
Create Date: 2026-10-15 13:40:59.517340

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd503c7210fa9'
down_revision: Union[str, None] = '6c30dc4c2d20'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite не вміє ALTER для обмежень → batch-режим (копія таблиці)
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("encrypted_email", sa.String(500), nullable=True))
        batch.add_column(sa.Column("email_index", sa.String(64), nullable=True))
        batch.add_column(sa.Column("encrypted_phone", sa.String(500), nullable=True))
        batch.create_index("ix_users_email_index", ["email_index"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_index("ix_users_email_index")
        batch.drop_column("encrypted_phone")
        batch.drop_column("email_index")
        batch.drop_column("encrypted_email")

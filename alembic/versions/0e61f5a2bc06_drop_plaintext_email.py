"""drop plaintext email

Revision ID: 0e61f5a2bc06
Revises: d503c7210fa9
Create Date: 2026-10-15 13:40:59.924309

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0e61f5a2bc06'
down_revision: Union[str, None] = 'd503c7210fa9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Запускати ЛИШЕ після python -m scripts.migrate_encrypt
    with op.batch_alter_table("users") as batch:
        batch.drop_index("ix_users_email")
        batch.drop_column("email")


def downgrade() -> None:
    # Відкриті email не відновлюються — лише порожня колонка
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("email", sa.String(100), nullable=True))

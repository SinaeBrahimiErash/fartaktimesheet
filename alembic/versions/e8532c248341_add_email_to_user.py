"""add email to user

Revision ID: e8532c248341
Revises: 4e796e22cb90
Create Date: 2024-10-05 09:46:53.555442

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e8532c248341'
down_revision: Union[str, None] = '4e796e22cb90'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

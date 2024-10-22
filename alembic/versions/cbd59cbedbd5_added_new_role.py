"""Added new role

Revision ID: cbd59cbedbd5
Revises: e8532c248341
Create Date: 2024-10-22 10:26:19.514674

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cbd59cbedbd5'
down_revision: Union[str, None] = 'e8532c248341'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('140306')
    op.drop_table('140305')
    op.alter_column('users', 'role',
               existing_type=sa.VARCHAR(length=5),
               type_=sa.Enum('admin', 'user', 'supervisor', name='role'),
               existing_nullable=True)
    op.create_unique_constraint(None, 'users', ['email'])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.alter_column('users', 'role',
               existing_type=sa.Enum('admin', 'user', 'supervisor', name='role'),
               type_=sa.VARCHAR(length=5),
               existing_nullable=True)
    op.create_table('140305',
    sa.Column('user_id', sa.VARCHAR(), nullable=True),
    sa.Column('date', sa.VARCHAR(), nullable=True),
    sa.Column('times', sa.VARCHAR(), nullable=True),
    sa.Column('day_type', sa.VARCHAR(), nullable=True),
    sa.Column('description', sa.VARCHAR(), nullable=True),
    sa.Column('times_edited', sa.VARCHAR(), nullable=True),
    sa.Column('time_sheet_status', sa.BOOLEAN(), nullable=True),
    sa.Column('final_times', sa.VARCHAR(), nullable=True),
    sa.Column('total_presence', sa.VARCHAR(), nullable=True)
    )
    op.create_table('140306',
    sa.Column('user_id', sa.VARCHAR(), nullable=True),
    sa.Column('date', sa.VARCHAR(), nullable=True),
    sa.Column('times', sa.VARCHAR(), nullable=True),
    sa.Column('day_type', sa.VARCHAR(), nullable=True),
    sa.Column('description', sa.VARCHAR(), nullable=True),
    sa.Column('times_edited', sa.VARCHAR(), nullable=True),
    sa.Column('time_sheet_status', sa.BOOLEAN(), nullable=True),
    sa.Column('final_times', sa.VARCHAR(), nullable=True),
    sa.Column('total_presence', sa.VARCHAR(), nullable=True)
    )
    # ### end Alembic commands ###
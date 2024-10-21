"""Initial migration

Revision ID: f1a175d79922
Revises: e8532c248341
Create Date: 2024-10-05 09:54:47.522691

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1a175d79922'
down_revision: Union[str, None] = 'e8532c248341'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('140303')
    op.drop_index('ix_user_session_log_id', table_name='user_session_log')
    op.drop_table('user_session_log')
    op.add_column('users', sa.Column('email', sa.String(), nullable=True))
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
    op.drop_column('users', 'email')
    op.create_table('user_session_log',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('username', sa.VARCHAR(), nullable=False),
    sa.Column('start_time', sa.DATETIME(), nullable=True),
    sa.Column('end_time', sa.DATETIME(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_session_log_id', 'user_session_log', ['id'], unique=False)
    op.create_table('140303',
    sa.Column('user_id', sa.VARCHAR(), nullable=True),
    sa.Column('date', sa.VARCHAR(), nullable=True),
    sa.Column('times', sa.VARCHAR(), nullable=True),
    sa.Column('day_type', sa.VARCHAR(), nullable=True),
    sa.Column('description', sa.VARCHAR(), nullable=True),
    sa.Column('times_edited', sa.VARCHAR(), nullable=True),
    sa.Column('time_sheet_status', sa.BOOLEAN(), nullable=True)
    )
    # ### end Alembic commands ###
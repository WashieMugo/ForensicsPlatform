"""fix ftk ops relationships

Revision ID: 0a1a3829c17f
Revises: 7eab2901b010
Create Date: 2024-12-03 07:02:00.372878

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0a1a3829c17f'
down_revision = '7eab2901b010'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ftk_ops', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('operation', sa.String(length=100), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ftk_ops', schema=None) as batch_op:
        batch_op.drop_column('operation')
        batch_op.drop_column('status')

    # ### end Alembic commands ###

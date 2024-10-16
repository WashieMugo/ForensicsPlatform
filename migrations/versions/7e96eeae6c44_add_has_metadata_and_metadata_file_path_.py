"""Add has_metadata and metadata_file_path fields

Revision ID: 7e96eeae6c44
Revises: 
Create Date: 2024-10-16 10:15:26.974895

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7e96eeae6c44'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('uploaded_files', schema=None) as batch_op:
        batch_op.add_column(sa.Column('has_metadata', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('metadata_file_path', sa.String(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('uploaded_files', schema=None) as batch_op:
        batch_op.drop_column('metadata_file_path')
        batch_op.drop_column('has_metadata')

    # ### end Alembic commands ###
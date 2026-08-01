"""initial_migration

Revision ID: 6c7200934f3a
Revises: None
Create Date: 2026-08-01 22:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '6c7200934f3a'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_users_email'), 'users', ['email'], unique=True)

    # Create emails table
    op.create_table(
        'emails',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('message_id', sa.String(length=255), nullable=False),
        sa.Column('subject', sa.String(length=998), nullable=True),
        sa.Column('sender', sa.String(length=320), nullable=False),
        sa.Column('recipient', sa.String(length=320), nullable=False),
        sa.Column('body_text', sa.Text(), nullable=True),
        sa.Column('body_html', sa.Text(), nullable=True),
        sa.Column('raw_header', sa.Text(), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=True),
        sa.Column('received_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_emails_message_id'), 'emails', ['message_id'], unique=True)
    op.create_index(op.f('idx_emails_sender'), 'emails', ['sender'], unique=False)
    op.create_index(op.f('idx_emails_received_at'), 'emails', ['received_at'], unique=False)

    # Create attachments table
    op.create_table(
        'attachments',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('email_id', sa.UUID(), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('content_type', sa.String(length=100), nullable=True),
        sa.Column('file_hash_sha256', sa.String(length=64), nullable=False),
        sa.Column('path_on_disk', sa.String(length=512), nullable=True),
        sa.Column('scanning_status', sa.String(length=50), nullable=False),
        sa.Column('virus_found', sa.Boolean(), nullable=False),
        sa.Column('threat_label', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_attachments_email_id'), 'attachments', ['email_id'], unique=False)
    op.create_index(op.f('idx_attachments_hash'), 'attachments', ['file_hash_sha256'], unique=False)

    # Create url_indicators table
    op.create_table(
        'url_indicators',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('email_id', sa.UUID(), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('hash_sha256', sa.String(length=64), nullable=False),
        sa.Column('vt_positives', sa.Integer(), nullable=False),
        sa.Column('vt_total', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_urls_email_id'), 'url_indicators', ['email_id'], unique=False)
    op.create_index(op.f('idx_urls_hash'), 'url_indicators', ['hash_sha256'], unique=False)

    # Create yara_matches table
    op.create_table(
        'yara_matches',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('email_id', sa.UUID(), nullable=False),
        sa.Column('rule_name', sa.String(length=255), nullable=False),
        sa.Column('tags', sa.String(length=255), nullable=True),
        sa.Column('matched_strings', sa.JSON(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_yara_email_id'), 'yara_matches', ['email_id'], unique=False)

    # Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('email_id', sa.UUID(), nullable=False),
        sa.Column('assigned_to', sa.UUID(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email_id')
    )
    op.create_index(op.f('idx_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_index(op.f('idx_alerts_risk'), 'alerts', ['risk_score'], unique=False)

    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('target_entity', sa.String(length=100), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_index('idx_alerts_risk', table_name='alerts')
    op.drop_index('idx_alerts_status', table_name='alerts')
    op.drop_table('alerts')
    op.drop_index('idx_yara_email_id', table_name='yara_matches')
    op.drop_table('yara_matches')
    op.drop_index('idx_urls_hash', table_name='url_indicators')
    op.drop_index('idx_urls_email_id', table_name='url_indicators')
    op.drop_table('url_indicators')
    op.drop_index('idx_attachments_hash', table_name='attachments')
    op.drop_index('idx_attachments_email_id', table_name='attachments')
    op.drop_table('attachments')
    op.drop_index('idx_emails_received_at', table_name='emails')
    op.drop_index('idx_emails_sender', table_name='emails')
    op.drop_index('idx_emails_message_id', table_name='emails')
    op.drop_table('emails')
    op.drop_index('idx_users_email', table_name='users')
    op.drop_table('users')

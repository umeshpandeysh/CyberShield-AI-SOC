"""add_modules_5_7_tables

Revision ID: b83f9104c21e
Revises: 6c7200934f3a
Create Date: 2026-08-04 20:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b83f9104c21e'
down_revision: Union[str, None] = '6c7200934f3a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create task_records table
    op.create_table(
        'task_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('task_type', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('email_id', sa.UUID(), nullable=True),
        sa.Column('celery_task_id', sa.String(length=255), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('result_data', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_task_records_status'), 'task_records', ['status'], unique=False)
    op.create_index(op.f('idx_task_records_email_id'), 'task_records', ['email_id'], unique=False)

    # Create cases table
    op.create_table(
        'cases',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=True),
        sa.Column('assigned_to', sa.UUID(), nullable=True),
        sa.Column('created_by', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('tags', sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_cases_severity'), 'cases', ['severity'], unique=False)
    op.create_index(op.f('idx_cases_status'), 'cases', ['status'], unique=False)
    op.create_index(op.f('idx_cases_alert_id'), 'cases', ['alert_id'], unique=False)
    op.create_index(op.f('idx_cases_assigned_to'), 'cases', ['assigned_to'], unique=False)
    op.create_index(op.f('idx_cases_created_at'), 'cases', ['created_at'], unique=False)

    # Create case_notes table
    op.create_table(
        'case_notes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('author_id', sa.UUID(), nullable=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_case_notes_case_id'), 'case_notes', ['case_id'], unique=False)

    # Create case_events table
    op.create_table(
        'case_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('actor_id', sa.UUID(), nullable=True),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_case_events_case_id'), 'case_events', ['case_id'], unique=False)
    op.create_index(op.f('idx_case_events_timestamp'), 'case_events', ['timestamp'], unique=False)

    # Create case_evidence table
    op.create_table(
        'case_evidence',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('evidence_type', sa.String(length=100), nullable=False),
        sa.Column('reference_id', sa.String(length=255), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('added_by', sa.UUID(), nullable=True),
        sa.Column('added_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['added_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_case_evidence_case_id'), 'case_evidence', ['case_id'], unique=False)

    # Create threat_intel_records table
    op.create_table(
        'threat_intel_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('ioc', sa.String(length=512), nullable=False),
        sa.Column('ioc_type', sa.String(length=50), nullable=False),
        sa.Column('provider', sa.String(length=100), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('reputation', sa.String(length=100), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('tags', sa.String(length=500), nullable=True),
        sa.Column('malware_family', sa.String(length=255), nullable=True),
        sa.Column('threat_actor', sa.String(length=255), nullable=True),
        sa.Column('source', sa.String(length=255), nullable=True),
        sa.Column('raw_response', sa.JSON(), nullable=True),
        sa.Column('cache_expiry', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('idx_ti_ioc'), 'threat_intel_records', ['ioc'], unique=False)
    op.create_index(op.f('idx_ti_ioc_type'), 'threat_intel_records', ['ioc_type'], unique=False)
    op.create_index(op.f('idx_ti_provider'), 'threat_intel_records', ['provider'], unique=False)


def downgrade() -> None:
    op.drop_table('threat_intel_records')
    op.drop_table('case_evidence')
    op.drop_table('case_events')
    op.drop_table('case_notes')
    op.drop_table('cases')
    op.drop_table('task_records')

# ============================================================
# GuardianHer AI — database package
#
# Data access layer — all DB operations live here.
# Repos are the ONLY files that write SQL.
# Services never write SQL directly.
#
# Public API (import from here, not from sub-modules):
#
#   from database.connection   import DatabaseManager, get_db
#   from database.migrations   import run_migrations, get_schema_status
#   from database.schema       import SCHEMA_VERSION
#
#   from database.user_repository       import UserRepository
#   from database.emergency_repository  import EmergencyContactRepository
#   from database.sos_repository        import SOSRepository
#   from database.incident_repository   import IncidentRepository
#   from database.wearable_repository   import WearableRepository
#   from database.audit_repository      import AuditRepository, AuditEvent
# ============================================================

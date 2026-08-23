"""Canonical CORPUSfm addon script names — the single source of truth.

Every code path that CALLS an addon script over OData (schema pull, readiness probe,
Documents cleanup, FM-push trigger, automation-password rotation) imports the name from
here, rather than hardcoding its own literal — so the names can never drift across
modules. These mirror the script names shipped in the addon
(addon/CORPUSfm_ADDON.xml + extensions/export/resources/cfm_*.xml); if the addon renames
a script, change it HERE and every caller follows.

Lives in core/ so both core (ingestion pipeline) and extensions/server may import it
without violating the core-must-not-import-extensions rule.
"""

from __future__ import annotations

# Schema export — writes the full SaveAsXML to FM's Documents folder, returns only its
# path (sidesteps FileMaker's ~1M-char script-result cap). The co-located pull + probe.
SAVE_TO_DOCUMENTS = "CFM.TOOLS.ExportSchemaXML.SaveToDocumentsFolder"

# Companion cleanup — deletes the Cfm_*.xml the export wrote (FM never auto-cleans Documents).
DELETE_FROM_DOCUMENTS = "CFM.TOOLS.DeleteExportFileFromDocumentsFolder"

# FM-initiated push — FM saves the schema and POSTs it to CORPUSfm's /api/upload.
POST_TO_SERVER = "CFM.TOOLS.ExportSchemaXML.PostToServer"

# Save the export to a configured filesystem path.
SAVE_TO_FILE_PATH = "CFM.TOOLS.ExportSchemaXML.SaveToFilePath"

# Server-side rotation of the CORPUSfm automation account's password (bootstrap).
CHANGE_AUTOMATION_PASSWORD = "CFM.SRV.ChangeAutomationPassword"

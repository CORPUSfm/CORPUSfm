"""Section display configuration."""

# Alphabetical by display name.
# "FieldsForTables" is a virtual key — handled via cr.fields, not cr.sections.

# Intentionally omitted sections:
#   BaseDirectoryCatalog — "Addons" label was misleading; entries are internal FM path aliases
#     (file: URLs) that appear on every file with addons but carry no user-meaningful content.
#     BaseDirectory name attributes are raw paths, not addon names; SourceUUID is an internal
#     package ID with no display value. Dropped in favour of surfacing nothing rather than noise.
#   LibraryCatalog — 73+ individual binary data blobs (BinaryData / StreamList), one per asset
#     chunk across all addon packages. Not meaningful at the item level; no grouping key maps
#     cleanly to "N addons installed." Dropped.

SECTION_ORDER = [
    ("AccountsCatalog",           "Accounts"),
    ("BaseTableCatalog",          "Base Tables"),
    ("CustomFunctionsCatalog",    "Custom Functions"),
    ("CustomMenuCatalog",         "Custom Menus"),
    ("ExtendedPrivilegesCatalog", "Extended Privileges"),
    ("ExternalDataSourceCatalog", "External Data Sources"),
    ("FieldsForTables",           "Fields"),
    ("LayoutCatalog",             "Layouts"),
    ("PrivilegeSetsCatalog",      "Privilege Sets"),
    ("RelationshipCatalog",       "Relationships"),
    ("ScriptCatalog",             "Scripts"),
    ("TableOccurrenceCatalog",    "Table Occurrences"),
    ("ThemeCatalog",              "Themes"),
    ("ValueListCatalog",          "Value Lists"),
]

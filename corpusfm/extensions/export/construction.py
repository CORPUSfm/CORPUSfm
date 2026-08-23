"""Construction templates — native FM XML grammar for AUTHORING new schema objects
in an FMUpgradeToolPatch.

The capability ledger (capabilities.py) says what FMUpgradeTool *can apply*; this
module gives the AI the native XML to *author* it. It closes the construction-template
gap the AI-context behavioral probe found (docs/completeness-audit.md): the system
prompt had a SCRIPT AddAction example but no FIELD grammar, so the model emitted
`<!-- MISSING -->` for any field it was asked to create.

Every template here is grounded in a live FMUpgradeTool apply on a playground
(2026-06-04, Probes 1+2+4) — including the load-bearing findings that a calculation
needs only `<TableOccurrenceReference>` + `<Text>` (the `<DDRREF>` chunk hash that
real exports carry is NOT required — FM recompiles from the text), and that new
table occurrences + relationships apply via generic-catalog AddActions, bind by
NAME (id/UUID are reassigned), and must be emitted referent-first (TO before the
relationship that uses it), and that a whole new LAYOUT — including a button whose
action runs an existing script — applies via a LayoutCatalog AddAction with
placeholder object hashes (FM recomputes them; Probe 5).

Placeholders use {CURLY} braces (consistent with the structure-catalog step
templates) so the example XML stays well-formed and testable; the AI substitutes
real values from SCHEMA CONTEXT.
"""

from __future__ import annotations

# Field AddAction grammar. References (BaseTableReference, TableOccurrenceReference)
# carry id + name (+ UUID where SCHEMA CONTEXT provides it). New fields use id="0".
_FIELD_TEMPLATES = """\
FIELD CONSTRUCTION (add fields to an existing table — verified live):
A field AddAction adds one or more <Field> objects to a table. Take the table's
name and id and (for calculations) its table occurrence's name and id from SCHEMA
CONTEXT. New fields always use id="0".

  <AddAction>
    <FieldsForTables>
      <FieldCatalog>
        <BaseTableReference name="{TABLE}" id="{TABLE_ID}" />
        <ObjectList>
          <!-- one or more Field objects from the variants below -->
        </ObjectList>
      </FieldCatalog>
    </FieldsForTables>
  </AddAction>

  Normal field (plain stored value; datatype = Text | Number | Date | Time | Timestamp | Container):
    <Field id="0" name="{NAME}" fieldtype="Normal" datatype="Text" comment="">
      <AutoEnter type="" prohibitModification="False" />
      <Validation type="Always" allowOverride="True" notEmpty="False" unique="False" existing="False" />
      <Storage autoIndex="True" index="None" global="False" maxRepetitions="1">
        <LanguageReference name="English" id="21" />
      </Storage>
      <TagList />
    </Field>

  Auto-enter calculated field (value computed once on record creation — e.g. a UUID key):
    <Field id="0" name="{NAME}" fieldtype="Normal" datatype="Text" comment="">
      <AutoEnter type="Calculated" prohibitModification="False" overwriteExisting="False" alwaysEvaluate="False">
        <Calculated>
          <Calculation>
            <TableOccurrenceReference id="{TO_ID}" name="{TO_NAME}" />
            <Text>Get ( UUID )</Text>
          </Calculation>
        </Calculated>
      </AutoEnter>
      <Validation type="OnlyDuringDataEntry" allowOverride="True" notEmpty="False" unique="False" existing="False" />
      <Storage index="None" global="False" maxRepetitions="1">
        <LanguageReference name="English" id="21" />
      </Storage>
      <TagList />
    </Field>

  Calculation field (fieldtype="Calculated" — recomputes from its formula):
    <Field id="0" name="{NAME}" fieldtype="Calculated" datatype="Text" comment="">
      <AutoEnter alwaysEvaluate="False" />
      <Storage storeCalculationResults="True" autoIndex="True" index="Minimal" global="False" maxRepetitions="1">
        <LanguageReference name="English" id="21" />
      </Storage>
      <Calculation>
        <TableOccurrenceReference id="{TO_ID}" name="{TO_NAME}" />
        <Text>Upper ( SomeField )</Text>
      </Calculation>
      <TagList />
    </Field>

  CRITICAL calculation rules (verified):
   - Inside any <Calculation>, emit ONLY <TableOccurrenceReference> (the field's own
     table occurrence, from SCHEMA CONTEXT) followed by <Text>. The <Text> is the FM
     calc formula; reference other fields by name.
   - Do NOT emit a <DDRREF>. Real FM exports carry one (a compiled-chunk hash), but
     FMUpgradeTool recompiles the calc from <Text> — a DDRREF is not an input.
   - To ADD field behavior, prefer a field AddAction. Do NOT change an existing field's
     type via ReplaceAction — that applies but leaves the field non-functional.
"""

# Placeholder names the AI substitutes — exported so a renderer/validator can fill them.
FIELD_PLACEHOLDERS = ("TABLE", "TABLE_ID", "NAME", "TO_ID", "TO_NAME")

# Table-occurrence + relationship grammar. Verified live by Probe 4 (2026-06-04):
# a generic-catalog AddAction for a TableOccurrence and for a Relationship applies;
# FMUpgradeTool REASSIGNS both the integer id (0 → real) and the UUID, so new
# objects are supplied with id="0", no UUID, and are referenced BY NAME. Order is
# load-bearing: a referenced object must precede its referrer in the patch (TO
# before the relationship that uses it).
_RELATIONSHIP_TEMPLATES = """\
TABLE OCCURRENCE + RELATIONSHIP CONSTRUCTION (relationship graph — verified live):
These are generic-catalog AddActions (no ObjectList wrapper). Two load-bearing
rules from a live apply:
 - id/UUID are REASSIGNED by the tool. Give every NEW object id="0" and NO <UUID>.
   Reference objects BY NAME, never by id or UUID.
 - ORDER MATTERS. The tool applies AddActions top-to-bottom and does not resolve
   forward references. Emit a referenced object BEFORE the object that uses it:
   a new table occurrence's AddAction must come before the relationship's AddAction.

Add a table occurrence (a named view of a base table on the relationship graph).
Take the base table's name + id from SCHEMA CONTEXT; the new TO uses id="0":
  <AddAction>
    <TableOccurrenceCatalog>
      <TableOccurrence id="0" name="{TO_NAME}" type="Local">
        <BaseTableSourceReference type="BaseTableReference">
          <BaseTableReference id="{TABLE_ID}" name="{TABLE}" />
        </BaseTableSourceReference>
        <TagList />
      </TableOccurrence>
    </TableOccurrenceCatalog>
  </AddAction>

Add a relationship between two table occurrences. For an EXISTING TO use its real
id + name from SCHEMA CONTEXT; for a TO added earlier in THIS patch use id="0" and
the name you gave it. Each side's join field is a <FieldReference> (the field's id
+ name from SCHEMA CONTEXT) carrying its own <TableOccurrenceReference>:
  <AddAction>
    <RelationshipCatalog>
      <Relationship id="0">
        <LeftTable cascadeCreate="False" cascadeDelete="False" type="Local">
          <TableOccurrenceReference id="{LEFT_TO_ID}" name="{LEFT_TO}" />
        </LeftTable>
        <RightTable cascadeCreate="False" cascadeDelete="False" type="Local">
          <TableOccurrenceReference id="{RIGHT_TO_ID}" name="{RIGHT_TO}" />
        </RightTable>
        <JoinPredicateList membercount="1">
          <JoinPredicate type="Equal">
            <LeftField>
              <FieldReference id="{LEFT_FIELD_ID}" name="{LEFT_FIELD}">
                <TableOccurrenceReference id="{LEFT_TO_ID}" name="{LEFT_TO}" />
              </FieldReference>
            </LeftField>
            <RightField>
              <FieldReference id="{RIGHT_FIELD_ID}" name="{RIGHT_FIELD}">
                <TableOccurrenceReference id="{RIGHT_TO_ID}" name="{RIGHT_TO}" />
              </FieldReference>
            </RightField>
          </JoinPredicate>
        </JoinPredicateList>
        <TagList />
      </Relationship>
    </RelationshipCatalog>
  </AddAction>

  Join operator: JoinPredicate type = Equal | NotEqual | LessThan | LessThanEqual
  | GreaterThan | GreaterThanEqual | Cartesian. Add more <JoinPredicate> entries
  inside <JoinPredicateList> (raise membercount) for a multi-key relationship.
  When a side references a TO added earlier in this same patch, use id="0" there
  AND in the nested <TableOccurrenceReference> — the bind is by name.
"""

# Placeholders the AI substitutes for relationship/TO construction.
RELATIONSHIP_PLACEHOLDERS = (
    "TO_NAME", "TABLE", "TABLE_ID",
    "LEFT_TO", "LEFT_TO_ID", "RIGHT_TO", "RIGHT_TO_ID",
    "LEFT_FIELD", "LEFT_FIELD_ID", "RIGHT_FIELD", "RIGHT_FIELD_ID",
)

# Layout grammar. Verified live by Probe 5 (2026-06-04): a LayoutCatalog AddAction
# adds a whole new layout; a LayoutObject's `hash` may be a 32-char placeholder —
# FM RECOMPUTES it on apply (proven: a fake all-zeros hash came back as a real
# hash) — so authoring needs no FM-internal hash, just like calc DDRREFs. A button's
# action ScriptReference wires to an existing script and survives the round trip.
_LAYOUT_TEMPLATES = """\
LAYOUT CONSTRUCTION (a new layout, optionally with a button that runs a script — verified live):
This AddAction creates a WHOLE NEW layout. (Adding an object to an EXISTING layout
is not expressible as an add — it would need a ReplaceAction reproducing that
layout's entire object list, which is not supported here. Author a new layout.)

Take the layout's context table occurrence (name + id) from SCHEMA CONTEXT. Each
LayoutObject's hash is a placeholder of 32 zeros — FM recomputes it; never try to
compute a real one. LayoutObject ids are sequential within the layout (1, 2, …),
and ObjectList membercount = the number of objects.

  <AddAction>
    <LayoutCatalog>
      <Layout id="0" name="{LAYOUT_NAME}" width="600">
        <TableOccurrenceReference id="{CONTEXT_TO_ID}" name="{CONTEXT_TO}" />
        <LayoutThemeReference />
        <PartsList membercount="1">
          <Part type="Body" kind="4">
            <Definition type="Body" kind="4" size="300" absolute="0" Options="1024" />
            <ObjectList membercount="2">
              <!-- objects from the variants below, in document order -->
            </ObjectList>
          </Part>
        </PartsList>
      </Layout>
    </LayoutCatalog>
  </AddAction>

  Text label (type="Text" kind="2"):
    <LayoutObject hash="00000000000000000000000000000000" id="1" type="Text" name="" kind="2">
      <Bounds top="20" left="20" bottom="40" right="300" />
      <Options>0</Options>
      <Text>
        <Options>0</Options>
        <StyledText><Data>Approval</Data></StyledText>
      </Text>
    </LayoutObject>

  Button that runs a script (type="Button" kind="10"); the action's ScriptReference
  needs only the EXISTING script's id + name from SCHEMA CONTEXT (NO UUID — FM
  resolves the script and fills the UUID itself; verified live):
    <LayoutObject hash="00000000000000000000000000000000" id="2" type="Button" name="" kind="10">
      <Bounds top="60" left="20" bottom="100" right="220" />
      <Options>536870920</Options>
      <Button>
        <Options>0</Options>
        <Label><Text><Options>2</Options><StyledText><Data>{BTN_LABEL}</Data></StyledText></Text></Label>
        <IconData type="0" size="12" />
        <action>
          <Options>4</Options>
          <ScriptReference id="{SCRIPT_ID}" name="{SCRIPT_NAME}" />
        </action>
      </Button>
    </LayoutObject>

  CRITICAL layout rules (verified):
   - hash="00000000000000000000000000000000" on every LayoutObject — FM recomputes
     it. Do NOT invent a hash and do NOT emit a <DDRREF>.
   - The button's <ScriptReference> carries only id + name — do NOT require or flag a
     missing UUID; FM resolves the script by id/name and fills the UUID.
   - A button with NO script parameter omits the action's <Calculation> entirely
     (just <Options/> + <ScriptReference/>). Only add a <Calculation><Text>…</Text>
     when the button passes a script parameter (no DDRREF there either).
   - This adds a NEW layout; you cannot add a single object onto an existing layout.
"""

# Placeholders the AI substitutes for layout construction.
LAYOUT_PLACEHOLDERS = (
    "LAYOUT_NAME", "CONTEXT_TO", "CONTEXT_TO_ID",
    "BTN_LABEL", "SCRIPT_ID", "SCRIPT_NAME",
)


def render_construction_templates() -> str:
    """Return the construction-template block for the patch-authoring system prompt."""
    return _FIELD_TEMPLATES + "\n" + _RELATIONSHIP_TEMPLATES + "\n" + _LAYOUT_TEMPLATES

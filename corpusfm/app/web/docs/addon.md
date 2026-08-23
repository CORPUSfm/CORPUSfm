---
title: The FileMaker add-on
slug: addon
order: 35
status: published
public: true
public_section: Integrations
---

# The FileMaker add-on

`CORPUSfm_ADDON` is what exports your schema XML **from inside FileMaker**. You install it once into
each FM file you want CORPUSfm to watch, and its scripts appear in that file under
`CORPUSfm (Cfm)`.

Download it from **Settings → Integrations → FM Addon**.

## Installing it

The download is a ZIP containing **one folder**, `CORPUSfm_ADDON`. Extract it, then move **that
folder** — not the ZIP, and not the files inside it — into the add-on modules directory on the
workstation running **FileMaker Pro**. Not the FileMaker Server machine: add-on modules are
installed by Pro, not by Server.

| Platform | Add-on modules directory |
|---|---|
| Windows | `%LOCALAPPDATA%\FileMaker\Extensions\AddonModules` |
| macOS | `~/Library/Application Support/FileMaker/Extensions/AddonModules` |

Then, in FileMaker Pro, choose **File → Add-ons → Install Add-on Module** and pick CORPUSfm.

Repeat the *install into the file* step for every FM file you want to monitor. The folder only has
to be placed once per workstation.

## The three scripts, and which one you want

All three are **disabled by default except `SaveToDocumentsFolder`**. A disabled script has a guard
*Exit Script* step at the top; to enable one, open it in Script Workspace and disable that step.

| Script | Default | What it does |
|---|---|---|
| `CFM.TOOLS.ExportSchemaXML.SaveToDocumentsFolder` | **Enabled** | Saves to FileMaker Server's `Data/Documents` and returns the path. This is the zero-admin default that ordinary pull jobs use. |
| `CFM.TOOLS.ExportSchemaXML.PostToServer` | Disabled | Saves the schema XML to a temporary file and POSTs it to `/api/upload`. This is the one for **push** jobs, including jobs on a remote server. |
| `CFM.TOOLS.ExportSchemaXML.SaveToFilePath` | Disabled | Saves to a path you supply as a JSON parameter, `{"exportPath":"…"}`. For when you want the file somewhere specific. |

If you are setting up an ordinary local job you do not need to enable anything — the default is
already the one that job will call. See [Jobs & automation](/docs/jobs) for which export method each
job uses.

## Why it has to be an add-on

CORPUSfm reads FileMaker's own schema export ("Save a Copy as XML" with analysis detail). Only
FileMaker can produce that file, and only from inside the file itself — so something has to run
*there*. The add-on is that something, and it is deliberately small: it exports, and it hands the
result back. It does not read your data.

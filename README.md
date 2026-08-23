# CORPUSfm

CORPUSfm is open-source schema intelligence for FileMaker developers. It turns FileMaker schema
exports into durable artifacts you can inspect, compare, automate, and use with an AI assistant.

## Install CORPUSfm

CORPUSfm installs alongside FileMaker Server 2024, 2025, or 2026 on Ubuntu Server or Windows Server.

1. Open [Releases](https://github.com/CORPUSfm/CORPUSfm/releases).
2. Choose the latest release and download the installer for your server platform.
3. Extract the complete package without separating its files.
4. Open `READ-ME-FIRST` and follow the package checklist.
5. Visit `https://<your-fms-host>/corpusfm/` and sign in with the administrator created during
   installation.

Install CORPUSfm on a development FileMaker Server. From there, it can acquire and ingest schema XML
from other FileMaker Servers.

## First use

After signing in:

1. Open **Artifacts**.
2. Choose **Import** to upload a schema export or saved CORPUSfm artifact, or choose **Paste** when
   the schema content is already on the clipboard.
3. Open the resulting artifact in Explorer.
4. Import or paste another version when you are ready to create a Diff.
5. To connect an AI assistant, open **MCP Access → OAuth setup** and follow the in-app recipe.

## What CORPUSfm does

- Creates durable, searchable artifacts from FileMaker schema exports.
- Explores objects and traces references across related files.
- Compares artifact versions with a structured Diff.
- Automates acquisition, ingestion, enrichment, indexing, and export through Jobs.
- Connects OAuth-capable MCP clients through each user's CORPUSfm account.
- Supports patch application on FileMaker Server 2025 and later, and file creation on FileMaker
  Server 2026.

Product documentation, setup recipes, and problem-solving guides are also available inside the app
and match the installed version.

## Repository

This repository is the public home of CORPUSfm. It contains the public site, product source,
installer source, documentation, tests, and legal files as they are published. Development occurs in
the project's private repositories; this public repository records reviewed releases and public-site
updates.

CORPUSfm is published and supported by PINAX SOFTWARE LLC. It is licensed under the
[Apache License 2.0](LICENSE).

FileMaker is a registered trademark of Claris International Inc. CORPUSfm is an independent tool and
is not affiliated with or endorsed by Claris.

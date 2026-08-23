<#
  corpusfm-proxy - the PUBLIC administrator surface (packet 1246-06 section 8.1).

    corpusfm-proxy status|add|ignore|remove|reconcile [<type>|all] [--json]

  It accepts NO request-file option and NO disposition option; mutating verbs use direct_commit
  internally. Route facts come from the published manifest (manifest.web) and nowhere else - not
  install.yaml, not the environment, not a default - and a missing or incomplete WebBlock REFUSES.

  The integrator protocol beneath this tool is not reachable from here.
  ASCII-only: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI.
#>
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
$py = $env:CORPUSFM_PYTHON
if (-not $py) { $py = 'python' }
& $py -m corpusfm.lifecycle proxy-public @Args
exit $LASTEXITCODE

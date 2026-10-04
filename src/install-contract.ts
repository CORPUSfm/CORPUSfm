// The few installation facts the public guide shares with the release package's READ-ME-FIRST.
// The package generator (`installer/package-installer.sh`) is the authority; the rendered-HTML test
// compares every value here with that generator, so a change there fails the site build instead of
// leaving the guide quietly wrong. Everything release-specific stays in the package.
export const installContract = {
  linux: {
    entryPoint: "install.sh",
    launch: "sudo bash install.sh",
    installDir: "/opt/CORPUSfm/",
    asset: "corpusfm-installer-linux-<version>.zip",
  },
  windows: {
    entryPoint: "install.ps1",
    launch: "powershell -File install.ps1",
    installDir: "C:\\Program Files\\CORPUSfm",
    asset: "corpusfm-installer-windows-<version>.zip",
  },
  keepTogether: "Keep every extracted file together.",
} as const;

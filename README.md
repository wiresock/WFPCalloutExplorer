# WFPCalloutExplorer

`WFPCalloutExplorer` is a specialized tool meticulously designed to identify currently loaded Windows Filtering Platform (WFP) callout filter drivers. It achieves this objective by scrutinizing whether these drivers import the vital `FWPKCLNT!FwpsCalloutRegister` function.

## Prerequisites

- Visual Studio 2022.
- Dependency on `pe-parse`. You can easily install it using `vcpkg` with the following commands:

```bash
vcpkg install pe-parse:x64-windows pe-parse:x86-windows pe-parse:arm64-windows pe-parse:x64-windows-static pe-parse:x86-windows-static pe-parse:arm64-windows-static
```

## Usage

1. Build the `WFPCalloutExplorer` project using Visual Studio 2022.
2. Run the executable. The program will dynamically load the `ntdll.dll`, query system modules, and inspect each module to determine if it is a WFP callout filter driver.

Alternatively, precompiled binaries for `x86`, `x64`, and `arm64` platforms are available in the [Releases section](https://github.com/wiresock/WFPCalloutExplorer/releases) of this repository.

## Functionality

- Dynamically retrieves system modules using the `NtQuerySystemInformation` function.
- Translates the path of system modules to ensure correct file paths.
- Parses the PE headers of modules to identify if they link against the `FWPKCLNT.SYS` library and import the `FwpsCalloutRegister` function.

## Output

The program outputs the names of drivers that are highly likely to be WFP callout filters based on their imports.

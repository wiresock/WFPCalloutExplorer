param (
    [string]$versionTag
)

# Import PowerShellForGitHub module
Import-Module PowerShellForGitHub

# Base URL for downloading files
$owner = "wiresock"
$repository = "WFPCalloutExplorer"
$baseURL = "https://github.com/$owner/$repository/releases/download/$versionTag/"
$files = @("wfpcalloutexplorer-arm64.exe", "wfpcalloutexplorer-x64.exe", "wfpcalloutexplorer-x86.exe")

foreach ($file in $files) {
    $downloadURL = $baseURL + $file
    $downloadPath = "./" + $file
    Invoke-WebRequest -Uri $downloadURL -OutFile $downloadPath

    # Sign the executable
    & signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" $downloadPath
    & signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" $downloadPath

    # Zip the signed executable
    $zipPath = $downloadPath -replace ".exe", ".zip"
    Compress-Archive -Path $downloadPath -DestinationPath $zipPath -Force

    # Delete the original executable
    Remove-Item -Path $downloadPath -Force
}

# Getting the GitHub release
$release = Get-GitHubRelease -OwnerName $owner -RepositoryName $repository -Tag $versionTag

# Removing existing ZIP files from the release
$assets = Get-GitHubReleaseAsset -OwnerName $owner -RepositoryName $repository -ReleaseId $release.id
foreach ($asset in $assets) {
    if ($asset.name -like "*.exe") {
        Remove-GitHubReleaseAsset -OwnerName $owner -RepositoryName $repository -AssetId $asset.id -Force
    }
}

# Uploading new ZIP files and deleting them after upload
foreach ($file in Get-ChildItem "./" -Filter "*.zip") {
    $release | New-GitHubReleaseAsset -Path $file.Name
    Remove-Item -Path $file.Name -Force
}

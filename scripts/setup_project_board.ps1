# ==============================================================================
# CyberShield-AI-SOC GitHub Project Board Setup Script
# This script automates the creation and configuration of the project board.
# ==============================================================================

# 1. Check for required token scopes
Write-Host "Checking GitHub CLI project access..." -ForegroundColor Cyan
$projectCheck = gh project list --owner "@me" 2>&1

if ($projectCheck -match "missing required scopes") {
    Write-Host ""
    Write-Host "[!] Missing project scope in GitHub CLI token." -ForegroundColor Yellow
    Write-Host "Please refresh your token by running the following command in your terminal:" -ForegroundColor Yellow
    Write-Host "    gh auth refresh -s project" -ForegroundColor Green
    Write-Host "After authorization, run this script again." -ForegroundColor Yellow
    exit 1
}

# 2. Create the Project Board
Write-Host "Creating GitHub Project Board..." -ForegroundColor Cyan
$projectJson = gh project create --owner "@me" --title "CyberShield-AI-SOC Board" --format json
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to create project board." -ForegroundColor Red
    exit 1
}

$project = $projectJson | ConvertFrom-Json
$projectNumber = $project.number
Write-Host "[+] Project Board #$projectNumber created successfully." -ForegroundColor Green

# 3. Link the Project Board to the Repository
Write-Host "Linking Project Board to CyberShield-AI-SOC repository..." -ForegroundColor Cyan
gh project link $projectNumber --owner "@me" --repo "CyberShield-AI-SOC"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to link project board to repository." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Linked successfully." -ForegroundColor Green

# 4. Create single-select columns (Backlog, Todo, In Progress, Review, Done)
Write-Host "Configuring project board columns (Kanban Status)..." -ForegroundColor Cyan
$options = "Backlog,Todo,In Progress,Review,Done"
gh project field-create $projectNumber --owner "@me" --name "Kanban Status" --data-type "SINGLE_SELECT" --single-select-options $options
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to create Kanban Status columns." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Kanban Status columns created successfully." -ForegroundColor Green

# 5. Import existing repository issues into the Project Board
Write-Host "Importing existing repository issues into the board..." -ForegroundColor Cyan
$issuesJson = gh issue list --repo "umeshpandeysh/CyberShield-AI-SOC" --json url --limit 10
$issues = $issuesJson | ConvertFrom-Json

if ($issues.Count -eq 0 -or $null -eq $issues) {
    Write-Host "[*] No issues found to import." -ForegroundColor Yellow
} else {
    foreach ($issue in $issues) {
        Write-Host "Adding issue: $($issue.url) ..." -ForegroundColor Gray
        gh project item-add $projectNumber --owner "@me" --url $issue.url | Out-Null
    }
    Write-Host "[+] All issues successfully imported into the Project Board!" -ForegroundColor Green
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "CyberShield-AI-SOC Project Board Setup Completed!" -ForegroundColor Green
Write-Host "View your project board at: https://github.com/users/umeshpandeysh/projects/$projectNumber" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green

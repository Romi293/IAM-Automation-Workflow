# Requires -Modules ActiveDirectory

<#
.SYNOPSIS
IAM Automation Workflow - Provisioning AD Groups, Users and File System Permissions

.DESCRIPTION
This script automates identity-driven provisioning based on Active Directory attributes:
- Organizational hierarchy (Division / Department / Group / Team)
- Dynamic AD security group creation
- User-to-group assignment
- File system folder provisioning
- NTFS permission mapping
- Full audit logging
#>

# -----------------------------
# PARAMETERS
# -----------------------------

param (
    [string]$username
)

if (-not $username) {
    $username = Read-Host "Enter username"
}

# =============================
# CONFIGURATION (USER INPUT REQUIRED)
# =============================

$SearchBase   = "<OU=Users,DC=company,DC=com>"
$GroupsBase   = "<OU=Groups,DC=company,DC=com>"
$Destination  = "<\\fileserver\share>"
$LogPath      = "<C:\Logs\IAM>"

$CurrentDate  = Get-Date -Format "dd-MM-yyyy"
$LogFile      = Join-Path $LogPath "$CurrentDate.txt"

# -----------------------------
# INITIALIZATION
# -----------------------------

New-Item -ItemType File -Path $LogFile -Force | Out-Null

Add-Content $LogFile "====================================="
Add-Content $LogFile "IAM Automation Started: $(Get-Date)"
Add-Content $LogFile "User: $username"
Add-Content $LogFile "====================================="

# -----------------------------
# USER QUERY
# -----------------------------

$ldapFilter = "(&(sAMAccountName=$username)(employeeID=*))"

$users = Get-ADUser -SearchBase $SearchBase -LDAPFilter $ldapFilter -Properties *

if (-not $users) {
    Write-Error "No AD user found for: $username"
    exit 1
}

# -----------------------------
# CORE PROCESS
# -----------------------------

foreach ($user in $users) {

    Add-Content $LogFile "Processing user: $($user.SamAccountName)"

    # Organizational attributes
    $org = @{
        Division   = $user.orgDivisionID
        Department = $user.orgDepartmentID
        Group      = $user.orgGroupID
        Team       = $user.orgTeamID
    }

    $orgNames = @{
        Division   = $user.DivisionName
        Department = $user.DepartmentName
        Group      = $user.GroupName
        Team       = $user.TeamName
    }

    foreach ($level in $org.Keys) {

        $orgId   = $org[$level]
        $orgName = $orgNames[$level]

        if ([string]::IsNullOrWhiteSpace($orgId) -or $orgId -eq "-" -or $orgId -eq ".") {
            Add-Content $LogFile "$level is empty - skipped"
            continue
        }

        if ([string]::IsNullOrWhiteSpace($orgName)) {
            Add-Content $LogFile "$level name is empty - skipped"
            continue
        }

        $groupName = "ORG_$orgId"

        # -----------------------------
        # AD GROUP PROVISIONING
        # -----------------------------

        $group = Get-ADGroup -Filter "SamAccountName -eq '$groupName'" -ErrorAction SilentlyContinue

        if (-not $group) {
            New-ADGroup `
                -Name $groupName `
                -SamAccountName $groupName `
                -GroupCategory Security `
                -GroupScope Universal `
                -Description $orgName `
                -Path $GroupsBase

            Add-Content $LogFile "Created AD Group: $groupName"
        }

        # Add user to group
        $isMember = Get-ADGroupMember $groupName -ErrorAction SilentlyContinue |
                    Where-Object { $_.SamAccountName -eq $user.SamAccountName }

        if (-not $isMember) {
            Add-ADGroupMember -Identity $groupName -Members $user.SamAccountName
            Add-Content $LogFile "Added user to group: $groupName"
        }

        # -----------------------------
        # FILE SYSTEM PROVISIONING
        # -----------------------------

        $folderName = $orgName -replace '"', ''
        $folderPath = Join-Path $Destination $folderName

        if (-not (Test-Path $folderPath)) {

            Start-Sleep -Seconds 2

            New-Item -ItemType Directory -Path $folderPath | Out-Null

            $acl = Get-Acl $folderPath

            $permission = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $groupName,
                "Modify",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )

            $acl.SetAccessRule($permission)
            Set-Acl -Path $folderPath -AclObject $acl

            Add-Content $LogFile "Created folder and applied ACL: $folderName"
        }
    }
}

# -----------------------------
# FINALIZATION
# -----------------------------

Add-Content $LogFile "====================================="
Add-Content $LogFile "IAM Automation Completed: $(Get-Date)"
Add-Content $LogFile "====================================="

###############################################################################################################
###############################################################################################################
### FILE: create-neo-team.ps1                                                                               ###
### AUTHOR: Dan Stevenson <dansteve@microsoft.com>                                                          ###
### LAST UPDATE: June 20, 2018                                                                              ###
### DESCRIPTION: PowerShell script to create a new team from a data file and provision an app               ###
###############################################################################################################
###############################################################################################################
### CREDITS:                                                                                                ###
### https://blog.kloud.com.au/2016/09/13/leveraging-the-microsoft-graph-api-with-powershell-and-oauth-2-0/  ###
###############################################################################################################
###############################################################################################################

###################################################
### SET PARAMETERS AND CONSTANTS
###################################################

$usersFilePath = "C:\code\data\neo-users.txt"
$teamPhotoPath = "C:\code\danspot.github.io\images\neo-team2.png"

$neoAppId = "c5a7da43-518d-4340-8139-cb7c93150015"
$appJSON = "{ 'id': '$neoAppId'}"
$Admin = "dansteve@teamsftw.com" # be careful of this
$AdminPassword = "PASSWORDGOESHERE"   # be careful of this

# load system.web library
Add-Type -AssemblyName System.Web

# graph and app configs
$resource = "https://graph.microsoft.com"
$clientid = "e56da1e2-674f-4a89-8019-f5fca4b6431b"
$clientSecret = "2rwIuXz1XGNZJY9B2zetCEI6WZ7BFtCFLw2WifsPals="

# not really used
$redirectUri = "https://localhost:8000"

# UrlEncode the ClientID and ClientSecret and URLs for special characters 
$clientIDEncoded = [System.Web.HttpUtility]::UrlEncode($clientid)
$clientSecretEncoded = [System.Web.HttpUtility]::UrlEncode($clientSecret)
$redirectUriEncoded =  [System.Web.HttpUtility]::UrlEncode($redirectUri)
$resourceEncoded = [System.Web.HttpUtility]::UrlEncode($resource)
$scopeEncoded = [System.Web.HttpUtility]::UrlEncode("https://outlook.office.com/user.readwrite.all")


###################################################
### AUTHENTICATE TO MICROSOFT TEAMS POWERSHELL
###################################################


Write-Output "######################################################################"
Write-Output "### FILE: create-neo-team.ps1                                      ###"
Write-Output "### AUTHOR: Dan Stevenson <dansteve@microsoft.com>                 ###"
Write-Output "###  --- FOR DEMO AND TESTING PURPOSES ONLY ---                    ###"
Write-Output "######################################################################"
Write-Output ""
Write-Output "Initializing..."
Write-Output "Authenticating Microsoft Teams PowerShell cmdlets"
Start-Sleep -Milliseconds 1000

# connect to Teams cmdlets
###  be careful with this password
$SecPass = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($Admin, $SecPass)
Connect-MicrosoftTeams -Credential $cred


###################################################
### AUTHENTICATE TO GRAPH API
###################################################

# Function to popup Auth Dialog Windows Form
Function Get-AuthCode {
    Add-Type -AssemblyName System.Windows.Forms

    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
    $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=420;Height=600;Url=($url -f ($Scope -join "%20")) }

    $DocComp  = {
        $Global:uri = $web.Url.AbsoluteUri        
        if ($Global:uri -match "error=[^&]*|code=[^&]*") {$form.Close() }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null

    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
    $output = @{}
    foreach($key in $queryOutput.Keys){
        $output["$key"] = $queryOutput[$key]
    }

    $output
}

Write-Output "Authenticating Graph API"
Start-Sleep -Milliseconds 1000

# Get AuthCode
$url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri=$redirectUriEncoded&client_id=$clientID&resource=$resourceEncoded&prompt=admin_consent&scope=$scopeEncoded"
Get-AuthCode

# Extract Access token from the returned URI
$regex = '(?<=code=)(.*)(?=&)'
$authCode  = ($uri | Select-string -pattern $regex).Matches[0].Value
$shortAuthCode = $authCode.substring(0,20)
Write-Output "Graph auth code: $shortAuthCode..."

#get Access Token
$body = "grant_type=authorization_code&redirect_uri=$redirectUri&client_id=$clientId&client_secret=$clientSecretEncoded&code=$authCode&resource=$resource"
$Authorization = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token `
    -Method Post -ContentType "application/x-www-form-urlencoded" `
    -Body $body `
    -ErrorAction STOP

$accesstoken = $Authorization.access_token
$shortAccesstoken = $accesstoken.substring(0,20)
Write-Output "Access token: $shortAccesstoken..."


###################################################
### GET TEAM NAME
###################################################

Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""

$monthName = (Get-Culture).DateTimeFormat.GetMonthName((get-date).month+1)
$defaultTeamName = "New Employees - $monthName"
$teamName = Read-Host "Enter team name [default=""$defaultTeamName""] "
if ($teamName.length -lt 1) { $teamName=$defaultTeamName }


###################################################
### CREATE TEAM 
###################################################

Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""
Write-Output "Creating team: $teamName"
Start-Sleep -Milliseconds 500
$group = New-Team -DisplayName $teamName -Description "New Employee Orientation Team" 
$groupID = $group.GroupID
Write-Output "Group ID: $groupID"
Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""

###################################################
### CREATE CHANNELS
###################################################
Write-Output "Creating channels:"

$channelNames = ("Announcements","Events and Weekend Plans","Buy-Sell","Local Tips")
$channelNames | ForEach-Object {
    Write-Output "        Creating new channel: $_"
    $output = New-TeamChannel -GroupID $groupID -DisplayName $_
}
Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""


###################################################
### ADD USERS (see add-new-users.ps1)
###################################################

# file contains a flat list of UPNs
$UPNs = Get-Content -Path $usersFilePath

Write-Output "Adding users:"

$UPNs | ForEach-Object {
    Write-Output "        Adding new user: $_"
    Add-TeamUser -GroupId $groupID -User $_
}
Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""



###################################################
### ADD NEW EMPLOYEE ORIENTATION APP (see add-new-users.ps1)
###################################################

Write-Output "Adding app for New Employee Orientation"
$appInstall = Invoke-RestMethod -Headers @{Authorization = "Bearer $accesstoken"} -Uri https://graph.microsoft.com/beta/teams/$groupID/apps -Method Post -Body $appJSON
Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""




# NOTE: it can take a while to sync between AAD, Teams, and Outlook (for users and picture)
# See  https://github.com/microsoftgraph/microsoft-graph-docs/blob/w/nkramer/slashteams/api-reference/beta/resources/teams_api_overview.md
# and consider using beta endpoints if necessary

###################################################
### ADD PICTURE
###################################################


Write-Output "Adding team picture"

# wait for group mailbox to be created to host picture
Start-Sleep -Milliseconds 8000

Set-TeamPicture -GroupID $groupID -ImagePath $teamPhotoPath

Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""
Write-Output "-->  Team ""$teamName"" (ID: $groupID) successfully created with channels, users, apps"
Write-Output ""
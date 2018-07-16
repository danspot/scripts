###############################################################################################################
###############################################################################################################
### FILE: add-new-users.ps1                                                                                 ###
### AUTHOR: Dan Stevenson <dansteve@microsoft.com>                                                          ###
### LAST UPDATE: June 20, 2018                                                                              ###
### DESCRIPTION: PowerShell script to create new users in a tenant from a CSV file                          ###
###############################################################################################################
###############################################################################################################
### CREDITS:                                                                                                ###
### https://docs.microsoft.com/en-us/powershell/azure/active-directory/importing-data?view=azureadps-2.0    ###
### https://docs.microsoft.com/en-us/powershell/azure/active-directory/enabling-licenses-sample?view=azure  ###
### adps-2.0                                                                                                ###
###############################################################################################################
###############################################################################################################

###################################################
### SET PARAMETERS AND CONSTANTS
###################################################

$Directory = "teamsftw.com"
$NewUserPassword = "Taipei101!"
$CsvFilePath = "C:\code\data\users.csv"
$outfilePath = "C:\code\data\neo-users.txt"
$location = "US"
$Admin = "dansteve@teamsftw.com" # be careful of this
$AdminPassword = "PASSWORDGOESHERE"   # be careful of this

# this is the Teams IW trial (1 year)
$EnabledPlans = 'TEAMS_IW'

Write-Output "######################################################################"
Write-Output "### FILE: add-new-users.ps1                                        ###"
Write-Output "### AUTHOR: Dan Stevenson <dansteve@microsoft.com>                 ###"
Write-Output "###  --- FOR DEMO AND TESTING PURPOSES ONLY ---                    ###"
Write-Output "######################################################################"
Write-Output ""
Write-Output "Initializing..."
Write-Output "Authenticating Azure AD PowerShell cmdlets"
Start-Sleep -Milliseconds 1000


### Connect to AAD PowerShell - be careful with this password
$SecPass = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($Admin, $SecPass)
Connect-AzureAD -Credential $cred

$LicenseSku = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq $EnabledPlans} 

###
### Create a new Password Profile for the new users. We'll be using the same password for all new users in this example
###

$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = $NewUserPassword

###
### Import the csv file. You will need to specify the path and file name of the CSV file in this cmdlet
###

Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""
Write-Output "Importing user data from $CsvFilePath"
$NewUsers = import-csv -Path $CsvFilePath


###
### Loop through all new users in the file. We'll use the ForEach cmdlet for this.
###
Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""
Write-Output "Adding new users:"

$UPNlist = @();

Foreach ($NewUser in $NewUsers) { 

    ###
    ### Construct the UserPrincipalName, the MailNickName and the DisplayName from the input data in the file 
    ###

    $UPN = $NewUser.Firstname.substring(0,1) + $NewUser.LastName + "@" + $Directory
    $DisplayName = $NewUser.Firstname + " " + $NewUser.Lastname
    $MailNickName = $NewUser.Firstname + "." + $NewUser.LastName

    ###
    ### Now that we have all the necessary data for to create the new user, we can execute the New-AzureADUser cmdlet  
    ###
    Write-Output "    Adding new user: $UPN"
    $UserToLicense = New-AzureADUser -UserPrincipalName $UPN -AccountEnabled $true -DisplayName $DisplayName -GivenName $NewUser.FirstName -MailNickName $MailNickName -Surname $NewUser.LastName -Department $Newuser.Department -JobTitle $NewUser.JobTitle -PasswordProfile $PasswordProfile -UsageLocation $location

    Write-Output "        Assigning license"
    $License = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
    $License.SkuId = $LicenseSku.SkuId
    #Create the AssignedLicenses Object 
    $AssignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
    $AssignedLicenses.AddLicenses = $License
    $AssignedLicenses.RemoveLicenses = @()

    #Assign the license to the user
    Set-AzureADUserLicense -ObjectId $UserToLicense.ObjectId -AssignedLicenses $AssignedLicenses

    $UPNlist += $UPN
    ###
    ### End the Foreach loop
    ###
}

Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""
Write-Output "New user IDs saved to $outfilePath"

$UPNlist | out-file $outfilePath

$numUsers = $NewUsers.Length

Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output ""
Write-Output "-->  $numUsers new users created"
Write-Output ""
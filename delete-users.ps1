$usersFilePath = "C:\code\data\neo-users.txt"



$Admin = "dansteve@teamsftw.com" # be careful of this
$AdminPassword = "07Apples!"   # be careful of this
### Connect to AAD PowerShell - be careful with this password
$SecPass = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($Admin, $SecPass)
Connect-AzureAD -Credential $cred

$DelUsers = Get-Content -Path $usersFilePath

Foreach ($DelUser in $DelUsers) { 
    write-output "deleting $DelUser"
    Remove-AzureADUser -ObjectID $DelUser
}

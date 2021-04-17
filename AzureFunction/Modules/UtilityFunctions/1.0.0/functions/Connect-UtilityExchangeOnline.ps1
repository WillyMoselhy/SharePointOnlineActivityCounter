function Connect-UtilityExchangeOnline {
    #TODO: Remove switch once we confirm all is working properly with MSI
    Write-Output "Switch Exchange Online MSI: $env:Switch_ExchangeOnlineMSI"
    if ([int] $env:Switch_ExchangeOnlineMSI) {
        Write-Output "Connecting to Exchange Online using MSI."

        #get token with MSI
        $resourceURI = "https://outlook.office365.com/"
        $tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
        $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER" = "$env:IDENTITY_HEADER" } -Uri $tokenAuthURI
        $accessToken = $tokenResponse.access_token
        $Authorization = "Bearer {0}" -f $accessToken
        $Password = ConvertTo-SecureString -AsPlainText $Authorization -Force

        $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList "OAuthUser@f548601e-a4f2-4f16-8e11-29512a15399f", $Password

        $ConnectionUri = "https://outlook.office365.com/PowerShell-LiveId?email=SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@$env:ExchangeOrganization&BasicAuthToOAuthConversion=true"

        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Credential $Ctoken -Authentication Basic -AllowRedirection -Verbose
        Import-PSSession $Session -DisableNameChecking| Format-List

        Write-Output "Connected to Exchange Online"
    }
    else {
        Write-Output "Connecting to Exchange Online using SP."

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([system.Convert]::FromBase64String($env:KeyVaultCertificate))

        Connect-ExchangeOnline -AppId $env:ExchangeAppId -Certificate $cert -Organization $env:ExchangeOrganization -ShowBanner:$false -ShowProgress $false
        Write-Output "Connected to Exchange Online"
    }

}
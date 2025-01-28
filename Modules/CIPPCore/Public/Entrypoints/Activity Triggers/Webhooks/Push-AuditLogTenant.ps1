function Push-AuditLogTenant {
    Param($Item)
    $ConfigTable = Get-CippTable -TableName 'WebhookRules'
    $TenantFilter = $Item.TenantFilter

    # Get Table contexts
    $AuditBundleTable = Get-CippTable -tablename 'AuditLogBundles'
    $SchedulerConfig = Get-CIPPTable -TableName 'SchedulerConfig'
    $WebhookTable = Get-CippTable -tablename 'webhookTable'
    $ConfigTable = Get-CIPPTable -TableName 'WebhookRules'

    # Query CIPPURL for linking
    $CIPPURL = Get-CIPPAzDataTableEntity @SchedulerConfig -Filter "PartitionKey eq 'webhookcreation'" | Select-Object -First 1 -ExpandProperty CIPPURL

    # Get all webhooks for the tenant
    $Webhooks = Get-CIPPAzDataTableEntity @WebhookTable -Filter "PartitionKey eq '$($Item.TenantFilter)' and Version eq '3'" | Where-Object { $_.Resource -match '^Audit' }

    # Get webhook rules
    $ConfigEntries = Get-CIPPAzDataTableEntity @ConfigTable

    # Date filter for existing bundles
    $LastHour = (Get-Date).AddHours(-1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')

    $NewBundles = [System.Collections.Generic.List[object]]::new()
    foreach ($Webhook in $Webhooks) {
        # only process webhooks that are configured in the webhookrules table
    try {
        Write-Information "Audit Logs: Processing $($TenantFilter)"
        # Get CIPP Url, cleanup legacy tasks
        $SchedulerConfig = Get-CippTable -TableName 'SchedulerConfig'
        $LegacyWebhookTasks = Get-CIPPAzDataTableEntity @SchedulerConfig -Filter "PartitionKey eq 'webhookcreation'"
        $LegacyUrl = $LegacyWebhookTasks | Select-Object -First 1 -ExpandProperty CIPPURL
        $CippConfigTable = Get-CippTable -tablename Config
        $CippConfig = Get-CIPPAzDataTableEntity @CippConfigTable -Filter "PartitionKey eq 'InstanceProperties' and RowKey eq 'CIPPURL'"
        if ($LegacyUrl) {
            if (!$CippConfig) {
                $Entity = @{
                    PartitionKey = 'InstanceProperties'
                    RowKey       = 'CIPPURL'
                    Value        = [string]([System.Uri]$LegacyUrl).Host
                }
                Add-CIPPAzDataTableEntity @CippConfigTable -Entity $Entity -Force
            }
            # remove legacy webhooks
            foreach ($Task in $LegacyWebhookTasks) {
                Remove-AzDataTableEntity -Force @SchedulerConfig -Entity $Task
            }
            $CIPPURL = $LegacyUrl
        } else {
            if (!$CippConfig) {
                    $CippConfig = @{
                        PartitionKey = 'InstanceProperties'
                        RowKey       = 'CIPPURL'
                        Value        = [string]([System.Uri]$Request.Headers.'x-ms-original-url').Host
                    }
                    Add-AzDataTableEntity @ConfigTable -Entity $CippConfig -Force
                    $CIPPURL = 'https://{0}' -f $CippConfig.Value
            } else { $CIPPURL = 'https://{0}' -f $CippConfig.Value }
        }

        # Get webhook rules
        $ConfigEntries = Get-CIPPAzDataTableEntity @ConfigTable
        $LogSearchesTable = Get-CippTable -TableName 'AuditLogSearches'

        $Configuration = $ConfigEntries | Where-Object { ($_.Tenants -match $TenantFilter -or $_.Tenants -match 'AllTenants') }
        if ($Configuration) {
            try {
                $LogSearches = Get-CippAuditLogSearches -TenantFilter $TenantFilter -ReadyToProcess | Select-Object -First 10
                Write-Information ('Audit Logs: Found {0} searches, begin processing' -f $LogSearches.Count)
                foreach ($Search in $LogSearches) {
                    $SearchEntity = Get-CIPPAzDataTableEntity @LogSearchesTable -Filter "Tenant eq '$($TenantFilter)' and RowKey eq '$($Search.id)'"
                    $SearchEntity.CippStatus = 'Processing'
                    Add-CIPPAzDataTableEntity @LogSearchesTable -Entity $SearchEntity -Force
                    try {
                        # Test the audit log rules against the search results
                        $AuditLogTest = Test-CIPPAuditLogRules -TenantFilter $TenantFilter -SearchId $Search.id

        $TenantFilter = $Webhook.PartitionKey
        $LogType = $Webhook.Resource
        Write-Information "Querying for $LogType on $TenantFilter"
        $ContentBundleQuery = @{
            TenantFilter = $TenantFilter
            ContentType  = $LogType
            StartTime    = $Item.StartTime
            EndTime      = $Item.EndTime
        }
        $LogBundles = Get-CIPPAuditLogContentBundles @ContentBundleQuery
        $ExistingBundles = Get-CIPPAzDataTableEntity @AuditBundleTable -Filter "PartitionKey eq '$($Item.TenantFilter)' and ContentType eq '$LogType' and Timestamp ge datetime'$($LastHour)'"

        foreach ($Bundle in $LogBundles) {
            if ($ExistingBundles.RowKey -notcontains $Bundle.contentId) {
                $NewBundles.Add([PSCustomObject]@{
                        PartitionKey      = $TenantFilter
                        RowKey            = $Bundle.contentId
                        DefaultDomainName = $TenantFilter
                        ContentType       = $Bundle.contentType
                        ContentUri        = $Bundle.contentUri
                        ContentCreated    = $Bundle.contentCreated
                        ContentExpiration = $Bundle.contentExpiration
                        CIPPURL           = [string]$CIPPURL
                        ProcessingStatus  = 'Pending'
                        MatchedRules      = ''
                        MatchedLogs       = 0
                    })
                        $SearchEntity.CippStatus = 'Completed'
                        $MatchedRules = [string](ConvertTo-Json -Compress -InputObject $AuditLogTest.MatchedRules)
                        $SearchEntity | Add-Member -MemberType NoteProperty -Name MatchedRules -Value $MatchedRules -Force
                        $SearchEntity | Add-Member -MemberType NoteProperty -Name MatchedLogs -Value $AuditLogTest.MatchedLogs -Force
                        $SearchEntity | Add-Member -MemberType NoteProperty -Name TotalLogs -Value $AuditLogTest.TotalLogs -Force
                    } catch {
                        if ($_.Exception.Message -match 'Request rate is large. More Request Units may be needed, so no changes were made. Please retry this request later.') {
                            $SearchEntity.CippStatus = 'Pending'
                            Write-Information "Audit Log search: Rate limit hit for $($SearchEntity.RowKey)."
                            if ($SearchEntity.PSObject.Properties.Name -contains 'RetryCount') {
                                $SearchEntity.RetryCount++
                            } else {
                                $SearchEntity | Add-Member -MemberType NoteProperty -Name RetryCount -Value 1
                            }
                        } else {
                            $Exception = [string](ConvertTo-Json -Compress -InputObject (Get-CippException -Exception $_))
                            $SearchEntity | Add-Member -MemberType NoteProperty -Name Error -Value $Exception
                            $SearchEntity.CippStatus = 'Failed'
                            Write-Information "Error processing audit log rules: $($_.Exception.Message)"
                        }
                        $AuditLogTest = [PSCustomObject]@{
                            DataToProcess = @()
                        }
                    }
                    Add-CIPPAzDataTableEntity @LogSearchesTable -Entity $SearchEntity -Force
                    $DataToProcess = ($AuditLogTest).DataToProcess
                    Write-Information "Audit Logs: Data to process found: $($DataToProcess.count) items"
                    if ($DataToProcess) {
                        foreach ($AuditLog in $DataToProcess) {
                            Write-Information "Processing $($AuditLog.operation)"
                            $Webhook = @{
                                Data         = $AuditLog
                                CIPPURL      = [string]$CIPPURL
                                TenantFilter = $TenantFilter
                            }
                            try {
                                Invoke-CippWebhookProcessing @Webhook
                            } catch {
                                Write-Information "Error processing webhook: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            } catch {
                Write-Information ( 'Audit Log search: Error {0} line {1} - {2}' -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
            }
        }
    } catch {
        Write-Information ( 'Push-AuditLogTenant: Error {0} line {1} - {2}' -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }

    if (($NewBundles | Measure-Object).Count -gt 0) {
        Add-CIPPAzDataTableEntity @AuditBundleTable -Entity $NewBundles -Force
        Write-Information ($NewBundles | ConvertTo-Json -Depth 5 -Compress)

        $Batch = $NewBundles | Select-Object @{Name = 'ContentId'; Expression = { $_.RowKey } }, @{Name = 'TenantFilter'; Expression = { $_.PartitionKey } }, @{Name = 'FunctionName'; Expression = { 'AuditLogBundleProcessing' } }
        $InputObject = [PSCustomObject]@{
            OrchestratorName = 'AuditLogs'
            Batch            = @($Batch)
            SkipLog          = $true
        }
        $InstanceId = Start-NewOrchestration -FunctionName 'CIPPOrchestrator' -InputObject ($InputObject | ConvertTo-Json -Depth 5 -Compress)
        Write-Host "Started orchestration with ID = '$InstanceId'"
    }catch {
        Write-Information ( 'Push-AuditLogTenant: Error {0} line {1} - {2}' -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }
}catch {
    Write-Information ( 'Push-AuditLogTenant: Error {0} line {1} - {2}' -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
}

}
finally {
    <#Do this after the try block regardless of whether an exception occurred or not#>
}

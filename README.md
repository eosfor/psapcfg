# Overview

This is a test module to work with rest APIs of Azure App Configuration service

## Usage

List all keys

```powershell
Get-AppCfgKeyvalue -AppCfgConnectionString "<app config servece connection string>"
```

Set a key

```powershell
Set-AppCfgKeyvalue -AppCfgConnectionString "<app config servece connection string>" -Key qwerty -Value 9876
```
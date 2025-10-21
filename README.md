# HetrixTools Windows Server Monitoring Agent

Documentation available here: https://docs.hetrixtools.com/category/server-monitor/

### Changelog

#### Version 2.1.0: 
- Added the Port Connection Monitoring feature.
- Added the ability to automatically detect active ports, unless specified in the `hetrixtools.cfg` file.
- Improved the agent install/update process.
- Other minor improvements.

#### Version 2.0.8: 
- Fixed an issue where, in some cases, network metrics wouldn't be read properly.

#### Version 2.0.7: 
- Added the `update.ps1` script for an easier way to upgrade your agent.
- General improvements and optimizations on how CPU metrics are collected.
- Further improvements on the CPU reading of non-English Windows versions.
- Fixed an issue introduced in `v2.0.6` where CPU disk time wasn't read properly.
- Other minor improvements.

#### Version 2.0.6: 
- Fixed CPU reading on non-English Windows versions.

#### Version 2.0.5: 
- Fixed an issue where in some cases agent would not be able to send metrics data.

#### Version 2.0.4: 
- Introducing DEBUG Mode, as with our Linux Agent, to help out in debugging potential agent issues.

#### Version 2.0.3: 
- Fixed some instances where the agent would not collect its metrics properly.
- Improved compatibility with older versions of Windows Server (thanks to @hkavula).

#### Version 2.0.2: 
- Improved CPU and disk time sample collection.

#### Version 2.0.1: 
- Improved CPU sample collection.

#### Version 2.0.0: 
- Rewritten the entire Windows Agent in PowerShell.
- Optimized metrics collection & simplified the code.
- Added `CheckServices` which allows the agent to monitor the status of running processes and services.
- Added `CheckDriveHealth` which allows the agent to monitor drive health.
- The agent will now have a warning on the HetrixTools interface if your server needs to reboot to finish installing updates.


#### Version 1.x (discontinued): 
https://github.com/hetrixtools/agent-win
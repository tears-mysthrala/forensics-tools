# Forensics Tools Cleanup Roadmap

## Overview

This document outlines the plan to clean up the forensics-tools repository, addressing issues with file naming, large files, duplicates, and documentation.

## Issues Identified

- **Redundant Naming**: Many files end with "Functions.ps1" unnecessarily.
- **Inconsistent Prefixes**: "Advanced" prefix used inconsistently.
- **Duplicates**: Multiple variants of similar files (e.g., HTMLReportFunctions.ps1, ForensicFunctions.ps1).
- **Large Files**: Several files >20KB that could be split for better maintainability.
- **Documentation Gaps**: Missing or outdated docs for many modules.

## Proposed Naming Convention

- Remove "Functions" suffix from filenames.
- Use "Advanced" prefix only for specialized features.
- Descriptive names without redundancy.

## Phases

1. **Analyze Duplicates**: Review and merge duplicate files.
2. **Review Large Files**: Identify splits for files >20KB.
3. **Define Naming Convention**: Finalize rules.
4. **Rename Files**: Apply new names.
5. **Split Large Files**: Break into smaller modules.
6. **Update Docs**: Ensure all modules have docs.
7. **Test Functionality**: Verify no breakage.

## Progress Tracking

- [x] Phase 1: Analyze Duplicates
- [x] Phase 2: Review Large Files
- [x] Phase 3: Define Naming Convention
- [x] Phase 4: Rename Files
- [x] Phase 5: Split Large Files
- [x] Phase 6: Update Docs
- [x] Phase 7: Test Functionality

## Summary of Changes

- Removed duplicate files: HTMLReportFunctions_new.ps1, HTMLReportFunctions_simple.ps1, ForensicFunctions.ps1 (kept _new as main)
- Split large files that had existing smaller counterparts into individual modules
- Renamed all module files to remove "Functions" suffix for consistency
- Updated module loader to reflect new file names
- Deleted redundant .psm1 files
- Tested loading: 60 modules loaded successfully

Last Updated: October 12, 2025

## Docs to Update/Add

- Ensure every module has a .md file in docs/.

Last Updated: October 12, 2025

ExecArtefactHunter

ExecArtefactHunter is a Windows forensic analysis tool designed to identify suspicious execution artifacts through correlation of system logs, file metadata, and PE characteristics.
It is built for incident responders, DFIR analysts, and security engineers who need a reliable, structured way to detect abnormal or malicious execution behaviour.

Overview

ExecArtefactHunter collects and correlates information from multiple Windows subsystems.
The goal is to highlight executables that have been tampered with, modified after execution, or that exhibit traits commonly associated with malware.

The tool includes both:

A command-line interface (CLI) for fast scanning and automation

An optional graphical interface (dark, modern, animated UI) for interactive investigation

Collected Data

ExecArtefactHunter gathers the following categories of artifacts:

Execution Traces

Prefetch

Amcache

Shimcache

SRUM

Windows Event Logs (including Sysmon if present)

Filesystem & Metadata

USN Journal modification timeline

Creation / modification timestamps

File size, hashes (MD5, SHA1, SHA256)

File path and location risk assessment

Executable Properties

Embedded icon presence

Digital signature validation

PE section data and imports

Entropy analysis (full file + per-section)

Manifest extraction (privilege level, execution requirements)

All collected data is stored in a structured database for rule evaluation.

Suspicion Rules

ExecArtefactHunter applies a set of rules to identify unusual or high-risk files.
Default rules include:

1. No icon but requires administrative permissions

Executables that lack an embedded icon but request elevation via UAC manifest.

2. High entropy

Files or PE sections with entropy values suggesting packing, compression, or encryption.

3. Unsigned but executed

Executables that were run on the system but do not contain a valid Authenticode signature.

4. File tampering (USN Journal analysis)

Files modified after they were executed, or altered in ways that conflict with expected timelines.

5. Execution from user-writable or risky paths

Examples:
Downloads, Desktop, Temp, AppData, or any non-system location writable by standard users.

6. Abnormal PE structure

Suspicious section names, missing standard sections, or imports linked to injection (e.g. VirtualAllocEx, WriteProcessMemory, CreateRemoteThread).

7. Execution logs inconsistent with filesystem state

For instance, Event Logs indicate execution but the file is deleted, timestamped incorrectly, or replaced.

These rules can be adjusted or extended through a configuration file.

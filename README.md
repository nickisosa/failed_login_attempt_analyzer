## Failed Login Attempt Analyzer

## Overview

This is a beginner Python cybersecurity project that analyzes simulated login records. The goal is to identify successful and failed login attempts, count repeated failures, and eventually flag potentially suspicious activity.

## Project Objectives

- Read login records from a text file
- Separate each record into timestamp, IP address, username, and status
- Count successful and failed login attempts
- Track failed attempts by IP address
- Flag IP addresses that reach a failed-login threshold
- Practice Python fundamentals in a cybersecurity context

## Current Progress

So far, the program can:

- Open and read `login_attempts.txt`
- Process the file line by line
- Remove extra whitespace with `.strip()`
- Separate each login record with `.split(",")`
- Access individual fields using list indexing

## Technologies / Concepts

- Python
- File handling
- `for` loops
- Lists
- List indexing
- String methods
- Conditionals
- Dictionaries
- Functions
- Git / GitHub

## Log Format

Each login record follows this format:

```text
timestamp,IP address,username,status
```

Example:

```text
2026-10-27 08:12:14,192.168.1.10,admin,FAILED
```

## Security Focus

Repeated failed login attempts can be a sign of suspicious activity, but they are not automatic proof of an attack. This project uses simulated data only and is intended for learning and portfolio development.

## Project Status

**In Progress**

Current Phase: Parsing login records  
Next Phase: Counting successful and failed login attempts

→ read file
→ clean each line
→ split fields
→ count total attempts
→ count success/failure
→ track failures by IP
→ compare against threshold
→ flag suspicious IPs
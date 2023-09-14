# Architecture Independent Analysis and Mitigation Recommendations for Faults

This tools analyses single instruction-skip faults by assigning them to a specific set of categories. We achieve this through binary analysis but stay architecture independent by first lifting the assembly into Ghidra's P-Code intermediate representation using SLEIGH. After this categorization process a fitting mitigation for each fault is recommended.

This repo also contains an exemplary GitHub workflow that automatically scans a firmware for vulnerabilities with ARCHIE, analyzes the identified faults and uploads the results to GitHub's security tab.

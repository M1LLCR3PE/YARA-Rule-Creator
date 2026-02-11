/**
 * YARA Rule Creator - Main Application JavaScript
 */

// Global editor instance
let editor;

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    initEditor();
    initTabs();
    initTemplateGenerator();
    initValidation();
    initExtraction();
    initTesting();
    initSliders();
});

/**
 * Initialize CodeMirror editor
 */
function initEditor() {
    const textarea = document.getElementById('editor');

    editor = CodeMirror.fromTextArea(textarea, {
        mode: 'yara',
        theme: 'dracula',
        lineNumbers: true,
        lineWrapping: false,
        indentUnit: 4,
        tabSize: 4,
        indentWithTabs: false,
        matchBrackets: true,
        autoCloseBrackets: true,
        extraKeys: {
            'Ctrl-S': () => saveRule(),
            'Ctrl-Enter': () => validateRule(),
            'Tab': (cm) => {
                cm.replaceSelection('    ', 'end');
            }
        }
    });

    // Update cursor position in status bar
    editor.on('cursorActivity', () => {
        const cursor = editor.getCursor();
        document.getElementById('cursor-pos').textContent =
            `Line ${cursor.line + 1}, Col ${cursor.ch + 1}`;
    });

    // Default content
    editor.setValue(`rule example_rule
{
    meta:
        author = "Your Name"
        description = "Example YARA rule"
        date = "${new Date().toISOString().split('T')[0]}"

    strings:
        $str1 = "example" ascii nocase

    condition:
        $str1
}
`);
}

/**
 * Initialize tab switching
 */
function initTabs() {
    const tabs = document.querySelectorAll('.tab');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            // Activate clicked tab
            tab.classList.add('active');
            const tabId = tab.dataset.tab;
            document.getElementById(`tab-${tabId}`).classList.add('active');
        });
    });
}

/**
 * Initialize template generator
 */
function initTemplateGenerator() {
    const btnGenerate = document.getElementById('btn-generate');
    const templateType = document.getElementById('template-type');

    btnGenerate.addEventListener('click', async () => {
        const type = templateType.value;
        if (!type) {
            setStatus('Please select a template type', 'warning');
            return;
        }

        const ruleName = document.getElementById('rule-name').value || 'new_rule';
        const author = document.getElementById('rule-author').value;
        const description = document.getElementById('rule-description').value;

        btnGenerate.disabled = true;
        setStatus('Generating template...');

        try {
            const response = await fetch('/api/template/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    template_type: type,
                    rule_name: ruleName,
                    author: author,
                    description: description
                })
            });

            const data = await response.json();

            if (data.success) {
                editor.setValue(data.rule_content);
                setStatus('Template generated successfully', 'success');
            } else {
                setStatus(data.message || 'Failed to generate template', 'error');
            }
        } catch (error) {
            setStatus('Error: ' + error.message, 'error');
        } finally {
            btnGenerate.disabled = false;
        }
    });
}

/**
 * Initialize validation
 */
function initValidation() {
    const btnValidate = document.getElementById('btn-validate');

    btnValidate.addEventListener('click', validateRule);
}

async function validateRule() {
    const content = editor.getValue();
    const resultsDiv = document.getElementById('validation-results');

    setStatus('Validating rule...');
    resultsDiv.innerHTML = '';

    try {
        const response = await fetch('/api/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_content: content })
        });

        const data = await response.json();

        if (data.valid) {
            resultsDiv.innerHTML = '<div class="validation-item success">Rule is valid!</div>';
            setStatus('Rule validated successfully', 'success');
        } else {
            setStatus('Validation failed', 'error');
        }

        // Show errors
        data.errors.forEach(err => {
            const lineInfo = err.line ? ` (line ${err.line})` : '';
            resultsDiv.innerHTML += `<div class="validation-item error">${err.message}${lineInfo}</div>`;
        });

        // Show warnings
        data.warnings.forEach(warn => {
            resultsDiv.innerHTML += `<div class="validation-item warning">${warn.message}</div>`;
        });

    } catch (error) {
        resultsDiv.innerHTML = `<div class="validation-item error">Error: ${error.message}</div>`;
        setStatus('Validation error', 'error');
    }
}

/**
 * Initialize string extraction
 */
function initExtraction() {
    const btnExtract = document.getElementById('btn-extract');
    const extractFile = document.getElementById('extract-file');
    const extractPath = document.getElementById('extract-path');

    btnExtract.addEventListener('click', async () => {
        const resultsDiv = document.getElementById('extraction-results');
        resultsDiv.innerHTML = '<div class="loading"></div> Extracting...';
        btnExtract.disabled = true;
        setStatus('Extracting strings...');

        try {
            let response;
            const minLength = document.getElementById('min-length').value;
            const includeUnicode = document.getElementById('opt-unicode').checked;
            const includePeInfo = document.getElementById('opt-pe-info').checked;
            const classify = document.getElementById('opt-classify').checked;

            if (extractFile.files.length > 0) {
                // Upload file
                const formData = new FormData();
                formData.append('file', extractFile.files[0]);
                formData.append('min_length', minLength);
                formData.append('include_unicode', includeUnicode);
                formData.append('include_pe_info', includePeInfo);
                formData.append('classify_strings', classify);

                response = await fetch('/api/extract/file', {
                    method: 'POST',
                    body: formData
                });
            } else if (extractPath.value) {
                // Use path
                const formData = new FormData();
                formData.append('file_path', extractPath.value);
                formData.append('min_length', minLength);
                formData.append('include_unicode', includeUnicode);
                formData.append('include_pe_info', includePeInfo);
                formData.append('classify_strings', classify);

                response = await fetch('/api/extract/path', {
                    method: 'POST',
                    body: formData
                });
            } else {
                resultsDiv.innerHTML = '<div class="validation-item warning">Please select a file or enter a path</div>';
                btnExtract.disabled = false;
                return;
            }

            const data = await response.json();
            displayExtractionResults(data);
            setStatus('Extraction complete', 'success');
        } catch (error) {
            resultsDiv.innerHTML = `<div class="validation-item error">Error: ${error.message}</div>`;
            setStatus('Extraction error', 'error');
        } finally {
            btnExtract.disabled = false;
        }
    });
}

function displayExtractionResults(data) {
    const resultsDiv = document.getElementById('extraction-results');

    if (!data.success) {
        resultsDiv.innerHTML = `<div class="validation-item error">${data.error}</div>`;
        return;
    }

    let html = `
        <div class="result-card">
            <h4>${data.filename}</h4>
            <p>Size: ${formatBytes(data.file_size)} | Strings found: ${data.strings.length}</p>
        </div>
    `;

    // Strings
    if (data.strings.length > 0) {
        html += '<div class="result-card"><h4>Extracted Strings</h4><div class="string-list">';
        data.strings.slice(0, 100).forEach((str, idx) => {
            const category = str.category ? `<span class="category">[${str.category}]</span>` : '';
            const escaped = escapeHtml(str.value.substring(0, 60));
            const suffix = str.value.length > 60 ? '...' : '';
            html += `
                <div class="string-item">
                    <span>${escaped}${suffix} ${category}</span>
                    <button class="insert-btn" onclick="insertString('${escapeJs(str.value)}', '${str.encoding}')">+ Insert</button>
                </div>
            `;
        });
        html += '</div></div>';
    }

    // PE Info
    if (data.pe_info) {
        html += '<div class="result-card pe-info"><h4>PE Information</h4>';

        // Imports
        if (Object.keys(data.pe_info.imports).length > 0) {
            html += '<div class="pe-section"><h5>Imports</h5><ul>';
            for (const [dll, funcs] of Object.entries(data.pe_info.imports).slice(0, 5)) {
                html += `<li><strong>${dll}</strong>: ${funcs.slice(0, 5).join(', ')}${funcs.length > 5 ? '...' : ''}</li>`;
            }
            html += '</ul></div>';
        }

        // Sections
        if (data.pe_info.sections.length > 0) {
            html += '<div class="pe-section"><h5>Sections</h5><ul>';
            data.pe_info.sections.forEach(sec => {
                html += `<li>${sec.name} - Entropy: ${sec.entropy}</li>`;
            });
            html += '</ul></div>';
        }

        html += '</div>';
    }

    // Suggested YARA
    if (data.suggested_yara) {
        html += `
            <div class="result-card">
                <h4>Suggested YARA Strings</h4>
                <button class="btn btn-small" onclick="insertSuggestedYara()">Insert into Editor</button>
                <pre id="suggested-yara" style="margin-top: 10px; font-size: 0.8rem; white-space: pre-wrap;">${escapeHtml(data.suggested_yara)}</pre>
            </div>
        `;
    }

    resultsDiv.innerHTML = html;

    // Store suggested YARA for insertion
    window.suggestedYara = data.suggested_yara;
}

function insertString(value, encoding) {
    const modifier = encoding === 'unicode' ? 'wide' : 'ascii';
    const varName = '$str_' + Date.now().toString(36);
    const line = `        ${varName} = "${value}" ${modifier}\n`;

    const cursor = editor.getCursor();
    editor.replaceRange(line, cursor);
    setStatus('String inserted', 'success');
}

function insertSuggestedYara() {
    if (window.suggestedYara) {
        const cursor = editor.getCursor();
        editor.replaceRange('\n' + window.suggestedYara + '\n', cursor);
        setStatus('Suggested YARA inserted', 'success');
    }
}

/**
 * Initialize rule testing
 */
function initTesting() {
    const btnTestFile = document.getElementById('btn-test-file');
    const btnTestPath = document.getElementById('btn-test-path');

    btnTestFile.addEventListener('click', async () => {
        const testFile = document.getElementById('test-file');
        if (testFile.files.length === 0) {
            setStatus('Please select a file', 'warning');
            return;
        }

        const resultsDiv = document.getElementById('test-results');
        resultsDiv.innerHTML = '<div class="loading"></div> Testing...';
        btnTestFile.disabled = true;
        setStatus('Testing rule...');

        try {
            const formData = new FormData();
            formData.append('rule_content', editor.getValue());
            formData.append('file', testFile.files[0]);

            const response = await fetch('/api/test/file', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            displayTestResults(data);
        } catch (error) {
            resultsDiv.innerHTML = `<div class="validation-item error">Error: ${error.message}</div>`;
            setStatus('Test error', 'error');
        } finally {
            btnTestFile.disabled = false;
        }
    });

    btnTestPath.addEventListener('click', async () => {
        const testPath = document.getElementById('test-path').value;
        if (!testPath) {
            setStatus('Please enter a path', 'warning');
            return;
        }

        const resultsDiv = document.getElementById('test-results');
        resultsDiv.innerHTML = '<div class="loading"></div> Testing...';
        btnTestPath.disabled = true;
        setStatus('Testing rule...');

        try {
            const response = await fetch('/api/test/path', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    rule_content: editor.getValue(),
                    target_path: testPath
                })
            });

            const data = await response.json();
            displayTestResults(data);
        } catch (error) {
            resultsDiv.innerHTML = `<div class="validation-item error">Error: ${error.message}</div>`;
            setStatus('Test error', 'error');
        } finally {
            btnTestPath.disabled = false;
        }
    });
}

function displayTestResults(data) {
    const resultsDiv = document.getElementById('test-results');

    if (!data.success) {
        resultsDiv.innerHTML = `<div class="validation-item error">${data.error}</div>`;
        setStatus('Test failed', 'error');
        return;
    }

    let html = `
        <div class="result-card">
            <h4>Test Results</h4>
            <p>Files scanned: ${data.total_files} | Matches: ${data.matched_files}</p>
        </div>
    `;

    if (data.results.length === 0) {
        html += '<div class="no-match">No files scanned</div>';
    } else {
        data.results.forEach(result => {
            if (result.error) {
                html += `<div class="validation-item error">${result.file_path}: ${result.error}</div>`;
            } else if (result.matches.length > 0) {
                html += `<div class="result-card">`;
                html += `<h4>${result.file_path}</h4>`;
                result.matches.forEach(match => {
                    html += `<div class="match-item">`;
                    html += `<span class="rule-name">${match.rule_name}</span>`;
                    if (match.tags.length > 0) {
                        html += ` [${match.tags.join(', ')}]`;
                    }
                    if (match.strings.length > 0) {
                        html += `<br><small>Matched strings: ${match.strings.length}</small>`;
                    }
                    html += `</div>`;
                });
                html += '</div>';
            } else {
                html += `<div class="result-card"><h4>${result.file_path}</h4><p class="no-match">No match</p></div>`;
            }
        });
    }

    resultsDiv.innerHTML = html;
    setStatus(`Test complete: ${data.matched_files}/${data.total_files} matched`, data.matched_files > 0 ? 'success' : 'info');
}

/**
 * Initialize sliders
 */
function initSliders() {
    const minLengthSlider = document.getElementById('min-length');
    const minLengthVal = document.getElementById('min-length-val');

    minLengthSlider.addEventListener('input', () => {
        minLengthVal.textContent = minLengthSlider.value;
    });
}

/**
 * Save rule to file
 */
function saveRule() {
    const content = editor.getValue();
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'rule.yar';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setStatus('Rule saved', 'success');
}

// Wire up save button
document.getElementById('btn-save').addEventListener('click', saveRule);

/**
 * Utility functions
 */
function setStatus(message, type = 'info') {
    const statusText = document.getElementById('status-text');
    statusText.textContent = message;
    statusText.className = type;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeJs(text) {
    return text.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

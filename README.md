# CSIT-697---Masters-Project
Research project analyzing how GitHub Copilot, ChatGPT, and Claude Code impact secure Python development. Includes experiments comparing generated code, identifying vulnerabilities, and evaluating how AI assistants influence secure coding practices and developer workflows.

## Python security examples

`/home/runner/work/CSIT-697---Masters-Project/CSIT-697---Masters-Project/python_security_examples.py` contains minimal, runnable pairs of insecure and secure implementations for the same tasks:

- **CWE-89**: SQL injection vs parameterized queries
- **CWE-502**: unsafe deserialization with `pickle` vs JSON parsing
- **CWE-327**: weak report signing with MD5 vs keyed HMAC-SHA256
- **CWE-22 / CWE-732**: path traversal and permissive file handling vs constrained writes with `0600` permissions

Run the demo:

```bash
python python_security_examples.py
```

Run the focused tests:

```bash
python -m unittest test_python_security_examples.py
```

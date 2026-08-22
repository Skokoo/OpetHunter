# Contributing to Opet

Thank you for your interest in contributing to Opet. As a low-level framework and reverse engineering tool, maintaining absolute architectural precision, execution efficiency, and multi-architecture compatibility is critical. 

Please strictly adhere to the guidelines below before submitting any issues or pull requests.

## 1. Engineering Principles

* **Preserve Core Control Flow & Logical Integrity:** Do not disrupt or break the existing logical pipeline of the decompiler. Every contribution must seamlessly integrate with the established analysis, parsing, and decompilation phases without introducing regressions.
* **Efficient Complexity Over Clean-Code Minimalism:** This tool solves complex reverse engineering problems, and complex code additions are expected. However, complexity must never compromise execution efficiency. Optimize for minimal CPU overhead, strict memory management, and ensure zero critical memory leaks.
* **Zero-Tolerance for Unintended Side Effects:** You must thoroughly test your code across different binary samples. Do not introduce hidden regressions, unpredictable behaviors, or unexpected edge-case bugs into the engine.
* **Strict Cross-Architecture Design:** Opet is built as a multi-processor tool. Do not restrict implementation or hardcode components to be compatible with only one specific processor. All parsing, disassembly, and lifting logic must remain scalable and generic across architectures (e.g., ARM64, x86_64).

## 2. Mandatory Technical Review

* **Analyze the Architecture Specification:** You are strictly required to read and fully comprehend the internal mechanics documented in the Architecture Documentation (docs/architecture.md) *(Coming Soon)* before modifying any core engine components. Do not submit blind contributions without understanding the underlying design framework.

## 3. Contribution Workflow

### Bug Reports & Feature Requests
* Search the active and archived Issues to ensure your topic has not been addressed.
* Provide precise replication steps, including environment setup, targeted binary type, and specific instruction sequences causing the failure.

### Pull Request (PR) Requirements
1. Fork the repository and isolate your changes into a dedicated feature branch.
2. Verify that your implementation adheres to the existing multi-processor architecture and efficiency metrics.
3. Write clear, technical, and concise commit messages.
4. Submit a detailed PR explanation highlighting the modified components, why the architecture demands this adjustment, and your verification process.

Thank you for helping scale Opet responsibly and maintaining high-quality low-level engineering!
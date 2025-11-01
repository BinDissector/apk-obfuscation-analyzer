# Contributing to APK/AAR Obfuscation Analyzer

Thank you for your interest in contributing to the APK/AAR Obfuscation Analyzer! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Python version, jadx version)
- Sample APK/AAR if possible (or description of file characteristics)

### Suggesting Enhancements

We welcome feature requests! Please open an issue with:
- A clear description of the enhancement
- Use cases and benefits
- Any implementation ideas you have

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** with clear, commented code
3. **Test your changes** thoroughly
   ```bash
   python3 -m py_compile analyzer.py
   ./test_obfuscation.py
   ./test_metadata.py
   ```
4. **Update documentation** if you've changed functionality
5. **Follow the existing code style**
6. **Submit a pull request** with:
   - Clear description of changes
   - Related issue numbers
   - Testing performed

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/apk-obfuscation-analyzer.git
cd apk-obfuscation-analyzer

# Install prerequisites
sudo apt-get install jadx  # or brew install jadx on macOS

# Make scripts executable
chmod +x analyzer.py batch_analyze.sh check_release.sh test_*.py

# Run tests
./test_obfuscation.py
```

## Code Style Guidelines

- Use Python 3.6+ syntax
- Follow PEP 8 style guide
- Add docstrings to all functions
- Keep functions focused and modular
- Comment complex logic
- Use meaningful variable names

## Areas for Contribution

We're especially interested in contributions for:

### High Priority
- **Native library analysis** (.so files)
- **Resource obfuscation detection** (layout, strings, assets)
- **Performance optimizations** for large APKs
- **Additional obfuscation patterns** (Allatori, DashO, etc.)
- **Improved test coverage**

### Medium Priority
- **Machine learning-based detection** for unknown obfuscators
- **Diff visualization** for comparison reports
- **Additional output formats** (PDF, Markdown, CSV)
- **CI/CD integration examples** (GitHub Actions, GitLab CI, Jenkins)
- **Docker improvements** and multi-stage builds

### Documentation
- **Tutorial videos** or blog posts
- **Translation** to other languages
- **Example ProGuard/R8 configurations**
- **Case studies** with real APKs

## Testing Guidelines

Before submitting a PR, ensure:

1. **All existing tests pass**:
   ```bash
   ./test_obfuscation.py
   ./test_metadata.py
   ./test_sensitive_strings.py
   ```

2. **Add tests for new features**:
   - Unit tests for new analysis methods
   - Integration tests for new workflows
   - Test edge cases and error conditions

3. **Manual testing**:
   ```bash
   # Test single file analysis
   ./analyzer.py sample.apk

   # Test comparison mode
   ./analyzer.py original.apk obfuscated.apk

   # Test batch processing
   ./batch_analyze.sh -d ./apks -o ./results
   ```

## Commit Message Guidelines

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests after the first line

Example:
```
Add native library analysis support

- Implement .so file parsing
- Add architecture detection
- Update reports to show native code metrics

Fixes #123
```

## Code Review Process

1. Maintainers will review your PR within a few days
2. Address any feedback or requested changes
3. Once approved, a maintainer will merge your PR
4. Your contribution will be credited in the changelog

## Community Guidelines

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Keep discussions on-topic
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)

## Questions?

- Open a [Discussion](../../discussions) for general questions
- Open an [Issue](../../issues) for bugs or feature requests
- Check [existing issues](../../issues) before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make this tool better! 🎉

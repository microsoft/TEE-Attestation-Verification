# Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Test coverage

Test coverage is collected in CI by the `coverage` job using
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov). Per-run LCOV
reports and a human-readable summary are uploaded as the `coverage-reports`
workflow artifact, and the summary is also written to the job summary page.

To reproduce locally:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked

# Summary in the terminal
cargo llvm-cov --no-default-features --features "crypto_pure_rust" \
    --ignore-filename-regex '(^|/)(tests|demos|src/bin)/'

# LCOV report (e.g. for IDE integration)
cargo llvm-cov --no-default-features --features "crypto_pure_rust" \
    --lcov --output-path lcov.info \
    --ignore-filename-regex '(^|/)(tests|demos|src/bin)/'
```

The `--ignore-filename-regex` flag excludes test fixtures, demos, and the CLI
binary from the measured surface so the percentages reflect library code only.
